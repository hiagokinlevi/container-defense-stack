# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International License.
# https://creativecommons.org/licenses/by/4.0/
"""
Kubernetes Resource Quota & Container Limit Security Analyzer
=============================================================
Analyzes Kubernetes workload manifests (as Python dicts / dataclasses) for
missing resource requests, missing resource limits, excessively high limits,
and missing namespace-level ResourceQuota objects.

Operates entirely offline on manifest dicts — no live cluster API calls.

Check IDs
----------
RQ-001  Container without CPU/memory requests              (MEDIUM, w=15)
RQ-002  Container without resource limits                  (HIGH,   w=25)
RQ-003  Memory limit excessively high (> 8 GiB)           (MEDIUM, w=15)
RQ-004  CPU limit set to very high value (> 8.0 cores)    (HIGH,   w=20)
RQ-005  No ResourceQuota in namespace                      (MEDIUM, w=15)
RQ-006  Container with no limits in critical namespace     (HIGH,   w=25)
RQ-007  Init container without resource limits             (MEDIUM, w=10)

Usage::

    from kubernetes.resource_quota_analyzer import (
        ResourceQuotaAnalyzer,
        ResourceSpec,
        ContainerSpec,
        WorkloadSpec,
    )

    workload = WorkloadSpec(
        name="my-app",
        namespace="production",
        kind="Deployment",
        containers=[
            ContainerSpec(
                name="app",
                image="my-app:latest",
                resources=ResourceSpec(
                    cpu_request="200m",
                    cpu_limit="500m",
                    memory_request="256Mi",
                    memory_limit="512Mi",
                ),
            )
        ],
        has_namespace_quota=True,
    )

    analyzer = ResourceQuotaAnalyzer()
    result = analyzer.analyze(workload)
    print(result.summary())
    for finding in result.findings:
        print(finding.to_dict())
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Weight table — each check ID maps to its integer contribution to risk_score.
# risk_score = min(100, sum of weights for each *unique* fired check ID).
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "RQ-001": 15,  # missing CPU/memory requests
    "RQ-002": 25,  # missing resource limits
    "RQ-003": 15,  # memory limit excessively high
    "RQ-004": 20,  # CPU limit excessively high
    "RQ-005": 15,  # no ResourceQuota in namespace
    "RQ-006": 25,  # no limits in critical namespace
    "RQ-007": 10,  # init container without resource limits
}

# Namespaces considered critical — findings in these namespaces earn RQ-006.
_CRITICAL_NAMESPACES = frozenset(
    {"kube-system", "kube-public", "default", "production", "prod"}
)

# Regex for memory strings: optional digits, optional decimal, then unit suffix.
_MEMORY_RE = re.compile(
    r"^(\d+(?:\.\d+)?)\s*(Ki|Mi|Gi|Ti|Pi|Ei|K|M|G|T|P|E|)$",
    re.IGNORECASE,
)

# Binary (IEC) multipliers
_IEC_MULTIPLIERS: Dict[str, int] = {
    "ki": 1024,
    "mi": 1024 ** 2,
    "gi": 1024 ** 3,
    "ti": 1024 ** 4,
    "pi": 1024 ** 5,
    "ei": 1024 ** 6,
}

# SI (decimal) multipliers
_SI_MULTIPLIERS: Dict[str, int] = {
    "k":  1_000,
    "m":  1_000_000,
    "g":  1_000_000_000,
    "t":  1_000_000_000_000,
    "p":  1_000_000_000_000_000,
    "e":  1_000_000_000_000_000_000,
}

# Threshold constants
_MEMORY_LIMIT_THRESHOLD_BYTES: int = 8 * 1024 ** 3   # 8 GiB
_CPU_LIMIT_THRESHOLD_CORES: float = 8.0


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_memory_bytes(value: str) -> int:
    """
    Convert a Kubernetes memory string to an integer number of bytes.

    Supports IEC binary suffixes (Ki, Mi, Gi, …) and SI decimal suffixes
    (K, M, G, …).  A bare integer string is treated as plain bytes.

    Returns 0 for any string that cannot be parsed.

    Examples::

        _parse_memory_bytes("128Mi")   # → 134_217_728
        _parse_memory_bytes("1Gi")     # → 1_073_741_824
        _parse_memory_bytes("512M")    # → 512_000_000
        _parse_memory_bytes("1G")      # → 1_000_000_000
        _parse_memory_bytes("1024")    # → 1024
    """
    if not value:
        return 0
    m = _MEMORY_RE.match(value.strip())
    if not m:
        return 0
    magnitude = float(m.group(1))
    suffix = m.group(2).lower()
    if suffix == "":
        # Plain bytes — fractional bytes are floored to nearest integer.
        return int(magnitude)
    if suffix in _IEC_MULTIPLIERS:
        return int(magnitude * _IEC_MULTIPLIERS[suffix])
    if suffix in _SI_MULTIPLIERS:
        return int(magnitude * _SI_MULTIPLIERS[suffix])
    return 0


def _parse_cpu_cores(value: str) -> float:
    """
    Convert a Kubernetes CPU string to a float number of cores.

    Kubernetes CPU can be expressed as milli-cores ("500m") or as a plain
    decimal number of cores ("0.5", "2", "8000m").

    Returns 0.0 for any string that cannot be parsed.

    Examples::

        _parse_cpu_cores("500m")    # → 0.5
        _parse_cpu_cores("2")       # → 2.0
        _parse_cpu_cores("8000m")   # → 8.0
    """
    if not value:
        return 0.0
    value = value.strip()
    try:
        if value.endswith("m"):
            return float(value[:-1]) / 1000.0
        return float(value)
    except ValueError:
        return 0.0


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ResourceSpec:
    """
    CPU and memory resource requests and limits for a single container.

    Kubernetes resource strings use the formats documented at
    https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/

    Attributes:
        cpu_request:    CPU request, e.g. "100m", "0.5", "2".
        cpu_limit:      CPU limit, e.g. "500m", "1".
        memory_request: Memory request, e.g. "128Mi", "1Gi".
        memory_limit:   Memory limit, e.g. "256Mi", "2Gi".
    """

    cpu_request:    Optional[str] = None
    cpu_limit:      Optional[str] = None
    memory_request: Optional[str] = None
    memory_limit:   Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "cpu_request":    self.cpu_request,
            "cpu_limit":      self.cpu_limit,
            "memory_request": self.memory_request,
            "memory_limit":   self.memory_limit,
        }


@dataclass
class ContainerSpec:
    """
    Minimal representation of a Kubernetes container or init container.

    Attributes:
        name:              Container name as it appears in the Pod spec.
        image:             Full image reference, e.g. "nginx:1.25".
        resources:         Resource requests/limits; None means the entire
                           ``resources:`` stanza is absent from the manifest.
        is_init_container: True when this container lives under
                           ``spec.initContainers`` rather than
                           ``spec.containers``.
    """

    name:              str
    image:             str
    resources:         Optional[ResourceSpec] = None
    is_init_container: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "name":              self.name,
            "image":             self.image,
            "resources":         self.resources.to_dict() if self.resources else None,
            "is_init_container": self.is_init_container,
        }


@dataclass
class WorkloadSpec:
    """
    Minimal representation of a Kubernetes workload (Deployment, StatefulSet, …).

    Attributes:
        name:                Workload name (metadata.name).
        namespace:           Namespace; defaults to "default".
        kind:                Kubernetes kind string; e.g. "Deployment",
                             "StatefulSet", "DaemonSet", "Pod".
        containers:          All containers (regular and init) belonging to
                             this workload.
        has_namespace_quota: True when a ResourceQuota object exists in the
                             same namespace as this workload.
    """

    name:                str
    namespace:           str = "default"
    kind:                str = "Deployment"
    containers:          List[ContainerSpec] = field(default_factory=list)
    has_namespace_quota: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "name":                self.name,
            "namespace":           self.namespace,
            "kind":                self.kind,
            "containers":          [c.to_dict() for c in self.containers],
            "has_namespace_quota": self.has_namespace_quota,
        }


@dataclass
class ResourceQuotaFinding:
    """
    A single security finding produced by ResourceQuotaAnalyzer.

    Attributes:
        check_id:       Identifier of the check that produced this finding,
                        e.g. "RQ-002".
        severity:       "CRITICAL", "HIGH", "MEDIUM", or "LOW".
        workload_name:  Name of the workload that triggered the finding.
        namespace:      Namespace of the workload.
        container_name: Name of the specific container, if applicable.
        message:        Human-readable description of the finding.
        recommendation: Actionable remediation guidance.
    """

    check_id:       str
    severity:       str
    workload_name:  str
    namespace:      str
    container_name: Optional[str]
    message:        str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "check_id":       self.check_id,
            "severity":       self.severity,
            "workload_name":  self.workload_name,
            "namespace":      self.namespace,
            "container_name": self.container_name,
            "message":        self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class ResourceQuotaResult:
    """
    Aggregated result of a resource quota/limit security analysis.

    Attributes:
        workload_name: Name of the analysed workload.
        namespace:     Namespace of the analysed workload.
        findings:      All ResourceQuotaFinding objects raised for the workload.
        risk_score:    Cumulative risk score 0–100 derived from unique fired
                       check IDs and their weights from ``_CHECK_WEIGHTS``.
    """

    workload_name: str
    namespace:     str
    findings:      List[ResourceQuotaFinding] = field(default_factory=list)
    risk_score:    int = 0

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """
        Return a one-line human-readable summary of this result.

        Format::

            Workload <name> [<namespace>]: <N> findings, risk_score=<score>
        """
        count = len(self.findings)
        noun = "finding" if count == 1 else "findings"
        return (
            f"Workload {self.workload_name} [{self.namespace}]: "
            f"{count} {noun}, risk_score={self.risk_score}"
        )

    def by_severity(self) -> Dict[str, List[ResourceQuotaFinding]]:
        """
        Return findings grouped by severity level.

        The returned dict always contains keys "CRITICAL", "HIGH", "MEDIUM",
        and "LOW", even when the corresponding list is empty.
        """
        grouped: Dict[str, List[ResourceQuotaFinding]] = {
            "CRITICAL": [],
            "HIGH":     [],
            "MEDIUM":   [],
            "LOW":      [],
        }
        for finding in self.findings:
            bucket = grouped.get(finding.severity)
            if bucket is not None:
                bucket.append(finding)
            else:
                # Handle any unexpected severity gracefully.
                grouped[finding.severity] = [finding]
        return grouped

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "workload_name": self.workload_name,
            "namespace":     self.namespace,
            "risk_score":    self.risk_score,
            "findings":      [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class ResourceQuotaAnalyzer:
    """
    Analyze Kubernetes workloads for resource quota and limit misconfigurations.

    All checks operate offline on ``WorkloadSpec`` objects — no cluster
    connection is required.

    Example::

        analyzer = ResourceQuotaAnalyzer()
        result = analyzer.analyze(workload)
        results = analyzer.analyze_many([workload_a, workload_b])
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, workload: WorkloadSpec) -> ResourceQuotaResult:
        """
        Run all checks against a single ``WorkloadSpec``.

        Args:
            workload: The workload to analyse.

        Returns:
            A ``ResourceQuotaResult`` containing all findings and a risk score.
        """
        findings: List[ResourceQuotaFinding] = []

        # Gather per-container findings.
        for container in workload.containers:
            findings.extend(self._check_container(container, workload))

        # Gather workload-level findings.
        findings.extend(self._check_workload(workload))

        # Compute risk score from the set of unique fired check IDs.
        fired_ids = {f.check_id for f in findings}
        score = sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_ids)
        risk_score = min(100, score)

        return ResourceQuotaResult(
            workload_name=workload.name,
            namespace=workload.namespace,
            findings=findings,
            risk_score=risk_score,
        )

    def analyze_many(
        self, workloads: List[WorkloadSpec]
    ) -> List[ResourceQuotaResult]:
        """
        Run all checks against each workload in the provided list.

        Args:
            workloads: Iterable of ``WorkloadSpec`` objects to analyse.

        Returns:
            A list of ``ResourceQuotaResult`` objects, one per workload,
            in the same order as the input list.
        """
        return [self.analyze(w) for w in workloads]

    # ------------------------------------------------------------------
    # Internal per-container checks
    # ------------------------------------------------------------------

    def _check_container(
        self,
        container: ContainerSpec,
        workload: WorkloadSpec,
    ) -> List[ResourceQuotaFinding]:
        """Run all applicable checks for a single container."""
        findings: List[ResourceQuotaFinding] = []

        if container.is_init_container:
            # Init containers only participate in RQ-007.
            findings.extend(self._rq007(container, workload))
        else:
            # Regular containers participate in RQ-001 through RQ-006.
            findings.extend(self._rq001(container, workload))
            findings.extend(self._rq002(container, workload))
            findings.extend(self._rq003(container, workload))
            findings.extend(self._rq004(container, workload))
            findings.extend(self._rq006(container, workload))

        return findings

    # ------------------------------------------------------------------
    # Internal workload-level checks
    # ------------------------------------------------------------------

    def _check_workload(
        self, workload: WorkloadSpec
    ) -> List[ResourceQuotaFinding]:
        """Run all workload-level checks."""
        findings: List[ResourceQuotaFinding] = []
        findings.extend(self._rq005(workload))
        return findings

    # ------------------------------------------------------------------
    # Individual check implementations
    # ------------------------------------------------------------------

    def _rq001(
        self,
        container: ContainerSpec,
        workload: WorkloadSpec,
    ) -> List[ResourceQuotaFinding]:
        """
        RQ-001 — Container without CPU/memory requests (MEDIUM, weight 15).

        Fires when the container has no resources stanza at all, or when
        *both* cpu_request and memory_request are absent.  A container that
        sets only one type of request still triggers this check for the
        missing one.
        """
        res = container.resources
        missing_cpu    = res is None or res.cpu_request    is None
        missing_memory = res is None or res.memory_request is None

        if not (missing_cpu or missing_memory):
            # Both requests are present — no finding.
            return []

        missing_parts = []
        if missing_cpu:
            missing_parts.append("cpu_request")
        if missing_memory:
            missing_parts.append("memory_request")
        missing_str = " and ".join(missing_parts)

        return [
            ResourceQuotaFinding(
                check_id="RQ-001",
                severity="MEDIUM",
                workload_name=workload.name,
                namespace=workload.namespace,
                container_name=container.name,
                message=(
                    f"Container '{container.name}' in {workload.kind} "
                    f"'{workload.name}' is missing {missing_str}. "
                    "Without resource requests the scheduler cannot make "
                    "accurate placement decisions."
                ),
                recommendation=(
                    "Set explicit cpu and memory requests for every container. "
                    "Requests should reflect the container's typical resource "
                    "consumption under normal load."
                ),
            )
        ]

    def _rq002(
        self,
        container: ContainerSpec,
        workload: WorkloadSpec,
    ) -> List[ResourceQuotaFinding]:
        """
        RQ-002 — Container without resource limits (HIGH, weight 25).

        Fires when the container has no resources stanza at all, or when
        *both* cpu_limit and memory_limit are absent.  Setting only one
        limit still triggers for the missing one.
        """
        res = container.resources
        missing_cpu_limit    = res is None or res.cpu_limit    is None
        missing_memory_limit = res is None or res.memory_limit is None

        if not (missing_cpu_limit or missing_memory_limit):
            return []

        missing_parts = []
        if missing_cpu_limit:
            missing_parts.append("cpu_limit")
        if missing_memory_limit:
            missing_parts.append("memory_limit")
        missing_str = " and ".join(missing_parts)

        return [
            ResourceQuotaFinding(
                check_id="RQ-002",
                severity="HIGH",
                workload_name=workload.name,
                namespace=workload.namespace,
                container_name=container.name,
                message=(
                    f"Container '{container.name}' in {workload.kind} "
                    f"'{workload.name}' is missing {missing_str}. "
                    "Without limits the container can consume unbounded "
                    "node resources, acting as a noisy neighbour or "
                    "enabling denial-of-service conditions."
                ),
                recommendation=(
                    "Set explicit cpu and memory limits for every container. "
                    "Limits should be chosen conservatively above typical "
                    "peak consumption to prevent resource exhaustion."
                ),
            )
        ]

    def _rq003(
        self,
        container: ContainerSpec,
        workload: WorkloadSpec,
    ) -> List[ResourceQuotaFinding]:
        """
        RQ-003 — Memory limit excessively high > 8 GiB (MEDIUM, weight 15).

        Fires only when memory_limit is explicitly set and its parsed byte
        value exceeds the 8 GiB threshold.
        """
        res = container.resources
        if res is None or res.memory_limit is None:
            return []

        limit_bytes = _parse_memory_bytes(res.memory_limit)
        if limit_bytes <= _MEMORY_LIMIT_THRESHOLD_BYTES:
            return []

        return [
            ResourceQuotaFinding(
                check_id="RQ-003",
                severity="MEDIUM",
                workload_name=workload.name,
                namespace=workload.namespace,
                container_name=container.name,
                message=(
                    f"Container '{container.name}' in {workload.kind} "
                    f"'{workload.name}' has a memory limit of "
                    f"'{res.memory_limit}' ({limit_bytes:,} bytes), which "
                    "exceeds the recommended maximum of 8 GiB. "
                    "Excessively high memory limits can exhaust node "
                    "resources and cause other workloads to be evicted."
                ),
                recommendation=(
                    "Review the memory limit and lower it to the minimum "
                    "required for correct operation. Consider splitting "
                    "memory-intensive workloads across multiple pods."
                ),
            )
        ]

    def _rq004(
        self,
        container: ContainerSpec,
        workload: WorkloadSpec,
    ) -> List[ResourceQuotaFinding]:
        """
        RQ-004 — CPU limit set to very high value > 8.0 cores (HIGH, weight 20).

        Fires only when cpu_limit is explicitly set and its parsed core count
        exceeds 8.0.
        """
        res = container.resources
        if res is None or res.cpu_limit is None:
            return []

        cores = _parse_cpu_cores(res.cpu_limit)
        if cores <= _CPU_LIMIT_THRESHOLD_CORES:
            return []

        return [
            ResourceQuotaFinding(
                check_id="RQ-004",
                severity="HIGH",
                workload_name=workload.name,
                namespace=workload.namespace,
                container_name=container.name,
                message=(
                    f"Container '{container.name}' in {workload.kind} "
                    f"'{workload.name}' has a CPU limit of '{res.cpu_limit}' "
                    f"({cores:.3f} cores), which exceeds the recommended "
                    "maximum of 8.0 cores. Such a high CPU limit can "
                    "monopolise CPU resources on the node."
                ),
                recommendation=(
                    "Review the CPU limit and lower it to the actual peak "
                    "CPU demand of the container. Scale horizontally rather "
                    "than allowing individual containers to consume "
                    "excessive CPU."
                ),
            )
        ]

    def _rq005(self, workload: WorkloadSpec) -> List[ResourceQuotaFinding]:
        """
        RQ-005 — No ResourceQuota in namespace (MEDIUM, weight 15).

        Fires once per workload when the namespace has no ResourceQuota
        object.  This is a workload-level finding, not per-container.
        """
        if workload.has_namespace_quota:
            return []

        return [
            ResourceQuotaFinding(
                check_id="RQ-005",
                severity="MEDIUM",
                workload_name=workload.name,
                namespace=workload.namespace,
                container_name=None,
                message=(
                    f"Namespace '{workload.namespace}' has no ResourceQuota "
                    "object. Without a quota, workloads can claim unlimited "
                    "CPU and memory, exhausting cluster capacity."
                ),
                recommendation=(
                    "Create a ResourceQuota for the namespace that sets "
                    "sensible aggregate limits for CPU, memory, and object "
                    "counts appropriate for the workloads it hosts."
                ),
            )
        ]

    def _rq006(
        self,
        container: ContainerSpec,
        workload: WorkloadSpec,
    ) -> List[ResourceQuotaFinding]:
        """
        RQ-006 — Container with no limits in a critical namespace (HIGH, weight 25).

        Fires in addition to RQ-002 for containers in high-value namespaces
        where missing limits represent a heightened risk.  Only fires when
        *both* cpu_limit and memory_limit are absent.
        """
        if workload.namespace not in _CRITICAL_NAMESPACES:
            return []

        res = container.resources
        missing_cpu_limit    = res is None or res.cpu_limit    is None
        missing_memory_limit = res is None or res.memory_limit is None

        # RQ-006 requires that BOTH limits are missing.
        if not (missing_cpu_limit and missing_memory_limit):
            return []

        return [
            ResourceQuotaFinding(
                check_id="RQ-006",
                severity="HIGH",
                workload_name=workload.name,
                namespace=workload.namespace,
                container_name=container.name,
                message=(
                    f"Container '{container.name}' in {workload.kind} "
                    f"'{workload.name}' has no resource limits and resides "
                    f"in the critical namespace '{workload.namespace}'. "
                    "Unrestricted containers in critical namespaces pose a "
                    "heightened risk of resource exhaustion and may impact "
                    "cluster control-plane components."
                ),
                recommendation=(
                    "Apply strict resource limits to all containers in "
                    f"namespace '{workload.namespace}'. Consider enforcing "
                    "limits via a LimitRange object so new workloads cannot "
                    "be deployed without them."
                ),
            )
        ]

    def _rq007(
        self,
        container: ContainerSpec,
        workload: WorkloadSpec,
    ) -> List[ResourceQuotaFinding]:
        """
        RQ-007 — Init container without resource limits (MEDIUM, weight 10).

        Fires when an init container has no resources stanza at all, or when
        *both* cpu_limit and memory_limit are absent.
        """
        res = container.resources
        missing_cpu_limit    = res is None or res.cpu_limit    is None
        missing_memory_limit = res is None or res.memory_limit is None

        if not (missing_cpu_limit and missing_memory_limit):
            return []

        return [
            ResourceQuotaFinding(
                check_id="RQ-007",
                severity="MEDIUM",
                workload_name=workload.name,
                namespace=workload.namespace,
                container_name=container.name,
                message=(
                    f"Init container '{container.name}' in {workload.kind} "
                    f"'{workload.name}' has no resource limits. "
                    "Resource-starved init containers can delay pod startup "
                    "and block application readiness."
                ),
                recommendation=(
                    "Set explicit cpu and memory limits on init containers "
                    "that reflect their expected resource consumption. "
                    "Init containers typically have short, predictable "
                    "workloads that make sizing straightforward."
                ),
            )
        ]
