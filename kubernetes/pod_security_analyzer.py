"""
Kubernetes Pod Security Standards Analyzer
============================================
Analyzes Kubernetes Pod/Deployment/StatefulSet/DaemonSet specs against
Pod Security Standards (PSS) Baseline and Restricted profiles.

Operates on parsed manifest dicts (standard Kubernetes YAML/JSON structure).
No live cluster access required.

Check IDs
----------
PSS-001   Container runs as root (securityContext.runAsUser: 0 or runAsNonRoot: false)
PSS-002   Privileged container (securityContext.privileged: true)
PSS-003   AllowPrivilegeEscalation not set to false
PSS-004   Host network/PID/IPC namespace sharing (hostNetwork/hostPID/hostIPC: true)
PSS-005   Dangerous Linux capability added (NET_ADMIN/SYS_ADMIN/SYS_PTRACE/etc.)
PSS-006   HostPath volume mount (direct access to node filesystem)
PSS-007   No read-only root filesystem (readOnlyRootFilesystem not true)
PSS-008   Container image uses 'latest' tag or no tag

Usage::

    from kubernetes.pod_security_analyzer import PodSecurityAnalyzer, PSSFinding

    manifests = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "insecure-pod", "namespace": "default"},
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "image": "nginx:latest",
                        "securityContext": {"privileged": True},
                    }
                ]
            }
        }
    ]
    analyzer = PodSecurityAnalyzer()
    report = analyzer.analyze(manifests)
    for finding in report.findings:
        print(finding.to_dict())
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Weight of each check used to compute the aggregate risk score (0-100).
_CHECK_WEIGHTS: Dict[str, int] = {
    "PSS-001": 35,  # runs as root
    "PSS-002": 45,  # privileged container
    "PSS-003": 25,  # allowPrivilegeEscalation not false
    "PSS-004": 40,  # host namespace sharing
    "PSS-005": 40,  # dangerous Linux capabilities
    "PSS-006": 30,  # hostPath volume
    "PSS-007": 20,  # no read-only root filesystem
    "PSS-008": 15,  # latest / untagged image
}

# Capabilities that grant excessive privileges and should never appear in add[].
_DANGEROUS_CAPS: frozenset = frozenset(
    {
        "NET_ADMIN",
        "SYS_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "SYS_RAWIO",
        "SYS_BOOT",
        "SYS_NICE",
        "SYS_RESOURCE",
        "SYS_TIME",
        "MKNOD",
        "SETUID",
        "SETGID",
        "DAC_OVERRIDE",
        "DAC_READ_SEARCH",
    }
)

# Kubernetes workload kinds supported by this analyzer.
_SUPPORTED_KINDS = frozenset(
    {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class PSSSeverity(str, Enum):
    """Severity levels aligned with common vulnerability scoring conventions."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ---------------------------------------------------------------------------
# Finding & report dataclasses
# ---------------------------------------------------------------------------


@dataclass
class PSSFinding:
    """A single policy-standards violation found in a manifest."""

    check_id: str
    severity: PSSSeverity
    namespace: str
    pod_name: str
    container_name: str  # empty string for pod-level checks
    title: str
    detail: str
    remediation: str = ""
    # Optional raw evidence (truncated on serialisation to avoid bloat).
    evidence: str = ""

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a single-line human-readable summary."""
        location = f"{self.namespace}/{self.pod_name}"
        if self.container_name:
            location += f"/{self.container_name}"
        return f"[{self.check_id}] {self.severity.value} — {self.title} ({location})"

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the finding to a plain dict, capping evidence at 512 chars."""
        return {
            "check_id": self.check_id,
            "severity": self.severity.value,
            "namespace": self.namespace,
            "pod_name": self.pod_name,
            "container_name": self.container_name,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
            # Truncate evidence to keep reports reasonably sized.
            "evidence": self.evidence[:512],
        }


@dataclass
class PSSReport:
    """Aggregate report produced by :class:`PodSecurityAnalyzer`."""

    findings: List[PSSFinding] = field(default_factory=list)
    risk_score: int = 0          # 0-100
    pods_analyzed: int = 0
    generated_at: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # Derived counts (properties so they stay in sync automatically)
    # ------------------------------------------------------------------

    @property
    def total_findings(self) -> int:
        """Total number of findings in this report."""
        return len(self.findings)

    @property
    def critical_findings(self) -> List[PSSFinding]:
        """All findings with CRITICAL severity."""
        return [f for f in self.findings if f.severity == PSSSeverity.CRITICAL]

    @property
    def high_findings(self) -> List[PSSFinding]:
        """All findings with HIGH severity."""
        return [f for f in self.findings if f.severity == PSSSeverity.HIGH]

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def findings_by_check(self, check_id: str) -> List[PSSFinding]:
        """Return all findings for a specific check ID (e.g. 'PSS-002')."""
        return [f for f in self.findings if f.check_id == check_id]

    def findings_for_pod(self, namespace: str, pod_name: str) -> List[PSSFinding]:
        """Return all findings scoped to a specific pod."""
        return [
            f
            for f in self.findings
            if f.namespace == namespace and f.pod_name == pod_name
        ]

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a multi-line human-readable report summary."""
        lines = [
            "=== PSS Analysis Report ===",
            f"Pods analyzed : {self.pods_analyzed}",
            f"Total findings: {self.total_findings}",
            f"  CRITICAL     : {len(self.critical_findings)}",
            f"  HIGH         : {len(self.high_findings)}",
            f"Risk score    : {self.risk_score}/100",
        ]
        if self.findings:
            lines.append("")
            lines.append("Findings:")
            for f in self.findings:
                lines.append(f"  {f.summary()}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the full report to a plain dict."""
        return {
            "risk_score": self.risk_score,
            "pods_analyzed": self.pods_analyzed,
            "total_findings": self.total_findings,
            "generated_at": self.generated_at,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class PodSecurityAnalyzer:
    """
    Checks Kubernetes workload manifests against PSS Baseline and Restricted
    profiles without requiring live cluster access.

    Parameters
    ----------
    check_latest_tag:
        Enable PSS-008 (image tag hygiene).  Default ``True``.
    require_readonly_root:
        Enable PSS-007 (readOnlyRootFilesystem).  Default ``True``.
    """

    def __init__(
        self,
        check_latest_tag: bool = True,
        require_readonly_root: bool = True,
    ) -> None:
        self._check_latest_tag = check_latest_tag
        self._require_readonly_root = require_readonly_root

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, manifests: List[Dict]) -> PSSReport:
        """
        Analyze a list of parsed Kubernetes manifest dicts.

        Returns
        -------
        PSSReport
            Aggregated findings and risk score across all manifests.
        """
        all_findings: List[PSSFinding] = []
        pods_analyzed = 0

        for manifest in manifests:
            kind = manifest.get("kind", "")
            if kind not in _SUPPORTED_KINDS:
                continue  # skip unsupported resource types silently

            metadata = manifest.get("metadata", {})
            namespace = metadata.get("namespace") or "default"
            pod_name = metadata.get("name", "unknown")

            # Extract the pod spec depending on workload kind.
            pod_spec = self._extract_pod_spec(manifest, kind)
            if pod_spec is None:
                continue

            pods_analyzed += 1
            all_findings.extend(
                self._check_pod_spec(pod_spec, namespace, pod_name)
            )

        risk_score = self._compute_risk_score(all_findings)

        return PSSReport(
            findings=all_findings,
            risk_score=risk_score,
            pods_analyzed=pods_analyzed,
            generated_at=time.time(),
        )

    # ------------------------------------------------------------------
    # Pod spec extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_pod_spec(
        manifest: Dict, kind: str
    ) -> Optional[Dict]:
        """Return the pod spec dict for any supported workload kind."""
        spec = manifest.get("spec", {})

        if kind == "Pod":
            return spec  # spec *is* the pod spec for bare Pods

        if kind == "CronJob":
            # CronJob nests deeper: spec.jobTemplate.spec.template.spec
            return (
                spec
                .get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
                .get("spec")
            )

        # Deployment, StatefulSet, DaemonSet, Job all use spec.template.spec
        return spec.get("template", {}).get("spec")

    # ------------------------------------------------------------------
    # Core check logic
    # ------------------------------------------------------------------

    def _check_pod_spec(
        self,
        pod_spec: Dict,
        namespace: str,
        pod_name: str,
    ) -> List[PSSFinding]:
        """Run all checks against a resolved pod spec dict."""
        findings: List[PSSFinding] = []

        # --- Pod-level checks (not per-container) -------------------------

        findings.extend(
            self._check_pss004_host_namespaces(pod_spec, namespace, pod_name)
        )
        findings.extend(
            self._check_pss006_hostpath_volumes(pod_spec, namespace, pod_name)
        )

        # --- Container-level checks ---------------------------------------

        # Both regular containers and init containers are subject to the same
        # security standards; check all of them.
        containers: List[Dict] = list(pod_spec.get("containers") or [])
        init_containers: List[Dict] = list(pod_spec.get("initContainers") or [])

        for container in containers + init_containers:
            findings.extend(
                self._check_container(container, namespace, pod_name)
            )

        return findings

    def _check_container(
        self,
        container: Dict,
        namespace: str,
        pod_name: str,
    ) -> List[PSSFinding]:
        """Run all container-scoped checks and return findings."""
        findings: List[PSSFinding] = []
        cname: str = container.get("name", "")
        sc: Dict = container.get("securityContext") or {}
        image: str = container.get("image", "")

        findings.extend(
            self._check_pss001_runs_as_root(sc, namespace, pod_name, cname)
        )
        findings.extend(
            self._check_pss002_privileged(sc, namespace, pod_name, cname)
        )
        findings.extend(
            self._check_pss003_allow_privilege_escalation(sc, namespace, pod_name, cname)
        )
        findings.extend(
            self._check_pss005_dangerous_caps(sc, namespace, pod_name, cname)
        )

        if self._require_readonly_root:
            findings.extend(
                self._check_pss007_readonly_root(sc, namespace, pod_name, cname)
            )

        if self._check_latest_tag:
            findings.extend(
                self._check_pss008_image_tag(image, namespace, pod_name, cname)
            )

        return findings

    # ------------------------------------------------------------------
    # Individual check implementations
    # ------------------------------------------------------------------

    @staticmethod
    def _check_pss001_runs_as_root(
        sc: Dict,
        namespace: str,
        pod_name: str,
        container_name: str,
    ) -> List[PSSFinding]:
        """PSS-001 — container may execute as root (UID 0)."""
        # Fire if runAsUser is explicitly 0, OR if runAsNonRoot is explicitly False.
        runs_as_user_zero = sc.get("runAsUser") == 0
        run_as_non_root_false = sc.get("runAsNonRoot") is False

        if not (runs_as_user_zero or run_as_non_root_false):
            return []

        if runs_as_user_zero:
            detail = "securityContext.runAsUser is 0; the container process will run as root."
            evidence = f"runAsUser: {sc.get('runAsUser')}"
        else:
            detail = "securityContext.runAsNonRoot is false; root execution is permitted."
            evidence = f"runAsNonRoot: {sc.get('runAsNonRoot')}"

        return [
            PSSFinding(
                check_id="PSS-001",
                severity=PSSSeverity.HIGH,
                namespace=namespace,
                pod_name=pod_name,
                container_name=container_name,
                title="Container runs as root",
                detail=detail,
                remediation=(
                    "Set securityContext.runAsNonRoot: true and choose a "
                    "non-zero runAsUser (e.g. 65534)."
                ),
                evidence=evidence,
            )
        ]

    @staticmethod
    def _check_pss002_privileged(
        sc: Dict,
        namespace: str,
        pod_name: str,
        container_name: str,
    ) -> List[PSSFinding]:
        """PSS-002 — container runs in privileged mode (full host kernel access)."""
        if sc.get("privileged") is not True:
            return []

        return [
            PSSFinding(
                check_id="PSS-002",
                severity=PSSSeverity.CRITICAL,
                namespace=namespace,
                pod_name=pod_name,
                container_name=container_name,
                title="Privileged container",
                detail=(
                    "securityContext.privileged: true grants the container nearly "
                    "unrestricted access to the host kernel and all devices."
                ),
                remediation=(
                    "Remove securityContext.privileged or set it to false. "
                    "Use specific capabilities instead if elevated access is required."
                ),
                evidence="privileged: true",
            )
        ]

    @staticmethod
    def _check_pss003_allow_privilege_escalation(
        sc: Dict,
        namespace: str,
        pod_name: str,
        container_name: str,
    ) -> List[PSSFinding]:
        """PSS-003 — allowPrivilegeEscalation is not explicitly disabled."""
        # The field must be *explicitly* set to False to pass.
        # Missing key (None) or True both constitute a finding.
        ape = sc.get("allowPrivilegeEscalation")
        if ape is False:
            return []

        detail = (
            "securityContext.allowPrivilegeEscalation is not set to false. "
            "A process inside the container could gain more privileges than its parent."
        )
        evidence = f"allowPrivilegeEscalation: {ape!r} (must be false)"

        return [
            PSSFinding(
                check_id="PSS-003",
                severity=PSSSeverity.MEDIUM,
                namespace=namespace,
                pod_name=pod_name,
                container_name=container_name,
                title="AllowPrivilegeEscalation not disabled",
                detail=detail,
                remediation=(
                    "Set securityContext.allowPrivilegeEscalation: false on every container."
                ),
                evidence=evidence,
            )
        ]

    @staticmethod
    def _check_pss004_host_namespaces(
        pod_spec: Dict,
        namespace: str,
        pod_name: str,
    ) -> List[PSSFinding]:
        """PSS-004 — pod shares host network, PID, or IPC namespace."""
        violations: List[str] = []
        if pod_spec.get("hostNetwork") is True:
            violations.append("hostNetwork")
        if pod_spec.get("hostPID") is True:
            violations.append("hostPID")
        if pod_spec.get("hostIPC") is True:
            violations.append("hostIPC")

        if not violations:
            return []

        joined = ", ".join(violations)
        return [
            PSSFinding(
                check_id="PSS-004",
                severity=PSSSeverity.HIGH,
                namespace=namespace,
                pod_name=pod_name,
                container_name="",  # pod-level check; no specific container
                title="Host namespace sharing enabled",
                detail=(
                    f"The pod shares the following host namespaces: {joined}. "
                    "This breaks container isolation and may allow host-level attacks."
                ),
                remediation=(
                    f"Set {joined} to false (or remove the fields) in the pod spec."
                ),
                evidence=", ".join(f"{v}: true" for v in violations),
            )
        ]

    @staticmethod
    def _check_pss005_dangerous_caps(
        sc: Dict,
        namespace: str,
        pod_name: str,
        container_name: str,
    ) -> List[PSSFinding]:
        """PSS-005 — dangerous Linux capabilities added to the container."""
        caps_added: List[str] = list(
            (sc.get("capabilities") or {}).get("add") or []
        )
        # Normalise to upper-case for comparison.
        dangerous_found = [
            c for c in caps_added if c.upper() in _DANGEROUS_CAPS
        ]
        if not dangerous_found:
            return []

        joined = ", ".join(dangerous_found)
        return [
            PSSFinding(
                check_id="PSS-005",
                severity=PSSSeverity.CRITICAL,
                namespace=namespace,
                pod_name=pod_name,
                container_name=container_name,
                title="Dangerous Linux capability added",
                detail=(
                    f"The following dangerous capabilities are added: {joined}. "
                    "These capabilities enable significant privilege escalation paths."
                ),
                remediation=(
                    "Remove the dangerous capabilities from securityContext.capabilities.add. "
                    "Apply the principle of least privilege; prefer dropping ALL capabilities "
                    "and adding only what is strictly necessary."
                ),
                evidence=f"capabilities.add: {caps_added}",
            )
        ]

    @staticmethod
    def _check_pss006_hostpath_volumes(
        pod_spec: Dict,
        namespace: str,
        pod_name: str,
    ) -> List[PSSFinding]:
        """PSS-006 — pod mounts a HostPath volume (direct node filesystem access)."""
        volumes: List[Dict] = list(pod_spec.get("volumes") or [])
        hostpath_volumes = [v for v in volumes if "hostPath" in v]
        if not hostpath_volumes:
            return []

        paths = [v["hostPath"].get("path", "<unspecified>") for v in hostpath_volumes]
        joined = ", ".join(paths)
        return [
            PSSFinding(
                check_id="PSS-006",
                severity=PSSSeverity.HIGH,
                namespace=namespace,
                pod_name=pod_name,
                container_name="",  # pod-level check
                title="HostPath volume mount",
                detail=(
                    f"The pod mounts the following node paths directly: {joined}. "
                    "HostPath volumes bypass the storage abstraction layer and may "
                    "expose sensitive host data or enable container escape."
                ),
                remediation=(
                    "Replace HostPath volumes with PersistentVolumeClaims backed by "
                    "appropriate StorageClasses. Use emptyDir for ephemeral scratch space."
                ),
                evidence=f"hostPath volumes: {paths}",
            )
        ]

    @staticmethod
    def _check_pss007_readonly_root(
        sc: Dict,
        namespace: str,
        pod_name: str,
        container_name: str,
    ) -> List[PSSFinding]:
        """PSS-007 — root filesystem is not read-only."""
        if sc.get("readOnlyRootFilesystem") is True:
            return []

        return [
            PSSFinding(
                check_id="PSS-007",
                severity=PSSSeverity.LOW,
                namespace=namespace,
                pod_name=pod_name,
                container_name=container_name,
                title="Root filesystem is not read-only",
                detail=(
                    "securityContext.readOnlyRootFilesystem is not set to true. "
                    "A writable root filesystem makes it easier for attackers to "
                    "persist changes after a container compromise."
                ),
                remediation=(
                    "Set securityContext.readOnlyRootFilesystem: true and mount "
                    "writable emptyDir volumes only for paths that genuinely need writes."
                ),
                evidence=f"readOnlyRootFilesystem: {sc.get('readOnlyRootFilesystem')!r}",
            )
        ]

    @staticmethod
    def _check_pss008_image_tag(
        image: str,
        namespace: str,
        pod_name: str,
        container_name: str,
    ) -> List[PSSFinding]:
        """PSS-008 — container image uses 'latest' tag, empty tag, or has no tag at all."""
        if not image:
            # No image specified at all — skip (manifest likely incomplete).
            return []

        # Strip a leading registry + optional port, e.g. "registry.io:5000/org/image:tag"
        # We only care about the tag portion, which follows the last ":".
        # However, "registry.io:5000/image" looks like it has a tag "5000/image" when
        # split naively, so we look only at the part after the last "/" first.
        name_part = image.split("/")[-1]  # last path component, e.g. "nginx:latest"

        # A SHA256 digest reference ("image@sha256:...") is always pinned and safe.
        if "@sha256:" in image:
            return []

        if ":" not in name_part:
            # No tag separator in the image name component → implicitly latest.
            tag = ""
            detail = (
                f"Image '{image}' has no tag. Kubernetes will pull ':latest', "
                "which is mutable and breaks reproducibility."
            )
        else:
            tag = name_part.split(":")[-1]
            if tag.lower() != "latest":
                return []  # explicitly pinned to a non-latest tag → OK
            detail = (
                f"Image '{image}' uses the ':latest' tag, which is mutable and "
                "may cause unpredictable deployments or supply-chain attacks."
            )

        return [
            PSSFinding(
                check_id="PSS-008",
                severity=PSSSeverity.LOW,
                namespace=namespace,
                pod_name=pod_name,
                container_name=container_name,
                title="Image uses 'latest' or untagged reference",
                detail=detail,
                remediation=(
                    "Pin the image to an immutable digest or a specific semantic version tag, "
                    "e.g. 'nginx:1.27.0' or 'nginx@sha256:<digest>'."
                ),
                evidence=f"image: {image}",
            )
        ]

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_risk_score(findings: List[PSSFinding]) -> int:
        """
        Compute a 0-100 risk score.

        The score is the sum of weights for *unique* fired check IDs, capped at 100.
        Using unique check IDs prevents a single misconfiguration type from
        artificially inflating the score when it appears across many containers.
        """
        fired_checks = {f.check_id for f in findings}
        total = sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_checks)
        return min(total, 100)
