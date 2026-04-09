# CC BY 4.0 — Cyber Port Portfolio
# https://creativecommons.org/licenses/by/4.0/
#
# container_escape_detector.py
# Detect container escape risk factors in Kubernetes Pod/Deployment/StatefulSet/DaemonSet manifests.
# Configurations analysed can allow a compromised container to escape to the host.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Check weights registry
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "CEX-001": 45,  # privileged container
    "CEX-002": 40,  # hostPID enabled
    "CEX-003": 25,  # hostNetwork enabled
    "CEX-004": 45,  # container runtime socket mounted
    "CEX-005": 30,  # dangerous Linux capability added
    "CEX-006": 25,  # sensitive host filesystem path mounted
    "CEX-007": 15,  # securityContext missing entirely
}

# Capabilities considered dangerous for container escape
_DANGEROUS_CAPS = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE", "NET_ADMIN"}

# Container runtime socket paths caught by CEX-004
_RUNTIME_SOCKETS = {
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
}

# Sensitive host paths caught by CEX-006
_SENSITIVE_HOST_PATHS = ["/", "/etc", "/proc", "/sys", "/var/log", "/boot", "/usr"]

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class CEXFinding:
    """A single container escape risk finding."""

    check_id: str
    severity: str   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str     # human-readable detail; includes container name where applicable
    weight: int


@dataclass
class CEXResult:
    """Aggregated escape-risk result for a single workload."""

    workload_name: str
    workload_kind: str   # "Pod" | "Deployment" | "StatefulSet" | "DaemonSet"
    namespace: str
    findings: List[CEXFinding]
    risk_score: int      # min(100, sum of weights for unique fired check IDs)
    escape_risk: str     # "CRITICAL" / "HIGH" / "MEDIUM" / "LOW"

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a plain-dict representation suitable for JSON serialisation."""
        return {
            "workload_name": self.workload_name,
            "workload_kind": self.workload_kind,
            "namespace": self.namespace,
            "risk_score": self.risk_score,
            "escape_risk": self.escape_risk,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                }
                for f in self.findings
            ],
        }

    def summary(self) -> str:
        """One-line human-readable summary."""
        return (
            f"{self.workload_kind}/{self.workload_name} "
            f"[{self.namespace}] — escape_risk={self.escape_risk} "
            f"risk_score={self.risk_score} findings={len(self.findings)}"
        )

    def by_severity(self) -> Dict[str, List[CEXFinding]]:
        """Group findings by severity label."""
        groups: Dict[str, List[CEXFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _escape_risk_label(score: int) -> str:
    """Map a numeric risk score to a risk label."""
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def _get_pod_spec(manifest: dict) -> dict:
    """Extract the pod spec from any supported workload manifest kind."""
    kind = manifest.get("kind", "")
    if kind == "Pod":
        return manifest.get("spec", {})
    # Deployment, StatefulSet, DaemonSet all carry the pod template under spec.template.spec
    return manifest.get("spec", {}).get("template", {}).get("spec", {})


def _all_containers(pod_spec: dict) -> List[dict]:
    """Return the combined list of regular containers and init containers."""
    containers: List[dict] = list(pod_spec.get("containers", []))
    containers.extend(pod_spec.get("initContainers", []))
    return containers


def _is_sensitive_host_path(path: str) -> bool:
    """Return True when *path* matches a sensitive host path prefix.

    The root path "/" is treated as an exact match only — mounting the full
    root filesystem is an escape risk, but an arbitrary path like "/data" is
    not.  All other sensitive prefixes (/etc, /proc, /sys, /var/log, /boot,
    /usr) also match their sub-paths via a leading-slash prefix check.
    """
    # Normalise to avoid double-slash edge cases
    norm = path.rstrip("/") or "/"
    for sensitive in _SENSITIVE_HOST_PATHS:
        if sensitive == "/":
            # Only an exact mount of the root filesystem is flagged
            if norm == "/":
                return True
        else:
            # Exact match (e.g. "/etc") or sub-path (e.g. "/etc/shadow")
            if norm == sensitive or norm.startswith(sensitive + "/"):
                return True
    return False


# ---------------------------------------------------------------------------
# Per-check detection functions
# ---------------------------------------------------------------------------


def _check_cex001_privileged(pod_spec: dict) -> List[CEXFinding]:
    """CEX-001: Container has securityContext.privileged: true."""
    findings: List[CEXFinding] = []
    for container in _all_containers(pod_spec):
        sc = container.get("securityContext") or {}
        if sc.get("privileged") is True:
            name = container.get("name", "<unnamed>")
            findings.append(
                CEXFinding(
                    check_id="CEX-001",
                    severity="CRITICAL",
                    title="Privileged container",
                    detail=f"Container '{name}' runs with securityContext.privileged=true, "
                           "granting full host-level capabilities.",
                    weight=_CHECK_WEIGHTS["CEX-001"],
                )
            )
    return findings


def _check_cex002_host_pid(pod_spec: dict) -> List[CEXFinding]:
    """CEX-002: Pod has spec.hostPID: true."""
    findings: List[CEXFinding] = []
    if pod_spec.get("hostPID") is True:
        findings.append(
            CEXFinding(
                check_id="CEX-002",
                severity="CRITICAL",
                title="Host PID namespace shared",
                detail="Pod spec sets hostPID=true, allowing containers to see and signal "
                       "all host processes.",
                weight=_CHECK_WEIGHTS["CEX-002"],
            )
        )
    return findings


def _check_cex003_host_network(pod_spec: dict) -> List[CEXFinding]:
    """CEX-003: Pod has spec.hostNetwork: true."""
    findings: List[CEXFinding] = []
    if pod_spec.get("hostNetwork") is True:
        findings.append(
            CEXFinding(
                check_id="CEX-003",
                severity="HIGH",
                title="Host network namespace shared",
                detail="Pod spec sets hostNetwork=true, exposing the host network stack "
                       "to all containers in the pod.",
                weight=_CHECK_WEIGHTS["CEX-003"],
            )
        )
    return findings


def _check_cex004_runtime_socket(pod_spec: dict) -> List[CEXFinding]:
    """CEX-004: Container runtime socket mounted as a volume."""
    findings: List[CEXFinding] = []
    for vol in pod_spec.get("volumes", []):
        host_path_obj = vol.get("hostPath")
        if not host_path_obj:
            continue
        path = host_path_obj.get("path", "")
        if path in _RUNTIME_SOCKETS:
            vol_name = vol.get("name", "<unnamed>")
            findings.append(
                CEXFinding(
                    check_id="CEX-004",
                    severity="CRITICAL",
                    title="Container runtime socket mounted",
                    detail=f"Volume '{vol_name}' mounts the container runtime socket at "
                           f"'{path}', granting full container management access.",
                    weight=_CHECK_WEIGHTS["CEX-004"],
                )
            )
    return findings


def _check_cex005_dangerous_caps(pod_spec: dict) -> List[CEXFinding]:
    """CEX-005: Dangerous Linux capability added to a container."""
    findings: List[CEXFinding] = []
    for container in _all_containers(pod_spec):
        sc = container.get("securityContext") or {}
        caps = sc.get("capabilities") or {}
        added: List[str] = caps.get("add") or []
        # Normalise to uppercase for comparison
        added_upper = [c.upper() for c in added]
        dangerous_found = sorted(_DANGEROUS_CAPS.intersection(set(added_upper)))
        if dangerous_found:
            name = container.get("name", "<unnamed>")
            caps_str = ", ".join(dangerous_found)
            findings.append(
                CEXFinding(
                    check_id="CEX-005",
                    severity="HIGH",
                    title="Dangerous capability added",
                    detail=f"Container '{name}' adds dangerous capabilities: {caps_str}.",
                    weight=_CHECK_WEIGHTS["CEX-005"],
                )
            )
    return findings


def _check_cex006_sensitive_host_path(pod_spec: dict) -> List[CEXFinding]:
    """CEX-006: Sensitive host filesystem path mounted as a volume."""
    findings: List[CEXFinding] = []
    for vol in pod_spec.get("volumes", []):
        host_path_obj = vol.get("hostPath")
        if not host_path_obj:
            continue
        path = host_path_obj.get("path", "")
        # Skip runtime sockets — already caught by CEX-004
        if path in _RUNTIME_SOCKETS:
            continue
        if _is_sensitive_host_path(path):
            vol_name = vol.get("name", "<unnamed>")
            findings.append(
                CEXFinding(
                    check_id="CEX-006",
                    severity="HIGH",
                    title="Sensitive host path mounted",
                    detail=f"Volume '{vol_name}' mounts sensitive host path '{path}'.",
                    weight=_CHECK_WEIGHTS["CEX-006"],
                )
            )
    return findings


def _check_cex007_missing_security_context(pod_spec: dict) -> List[CEXFinding]:
    """CEX-007: Container securityContext is missing (neither container-level nor pod-level)."""
    findings: List[CEXFinding] = []
    pod_sc = pod_spec.get("securityContext") or {}
    pod_sc_present = bool(pod_sc)  # True if pod-level SC has at least one key
    for container in _all_containers(pod_spec):
        container_sc = container.get("securityContext") or {}
        container_sc_present = bool(container_sc)
        if not container_sc_present and not pod_sc_present:
            name = container.get("name", "<unnamed>")
            findings.append(
                CEXFinding(
                    check_id="CEX-007",
                    severity="MEDIUM",
                    title="Security context missing",
                    detail=f"Container '{name}' has no securityContext set at container "
                           "or pod level. Hardening settings (runAsNonRoot, readOnlyRootFilesystem, "
                           "allowPrivilegeEscalation=false, etc.) are absent.",
                    weight=_CHECK_WEIGHTS["CEX-007"],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze(manifest: dict) -> CEXResult:
    """Analyze a K8s Pod/Deployment/StatefulSet/DaemonSet manifest for container escape risks.

    Parameters
    ----------
    manifest:
        A plain Python dict representing the Kubernetes manifest (as parsed from YAML/JSON).

    Returns
    -------
    CEXResult
        Structured result with all findings and aggregate risk score.
    """
    kind = manifest.get("kind", "Unknown")
    metadata = manifest.get("metadata", {})
    name = metadata.get("name", "<unnamed>")
    namespace = metadata.get("namespace", "default")

    pod_spec = _get_pod_spec(manifest)

    # Run all checks and collect findings
    findings: List[CEXFinding] = []
    findings.extend(_check_cex001_privileged(pod_spec))
    findings.extend(_check_cex002_host_pid(pod_spec))
    findings.extend(_check_cex003_host_network(pod_spec))
    findings.extend(_check_cex004_runtime_socket(pod_spec))
    findings.extend(_check_cex005_dangerous_caps(pod_spec))
    findings.extend(_check_cex006_sensitive_host_path(pod_spec))
    findings.extend(_check_cex007_missing_security_context(pod_spec))

    # Deduplicate check IDs for risk score calculation (one weight per check_id)
    fired_check_ids = {f.check_id for f in findings}
    raw_score = sum(_CHECK_WEIGHTS[cid] for cid in fired_check_ids if cid in _CHECK_WEIGHTS)
    risk_score = min(100, raw_score)

    return CEXResult(
        workload_name=name,
        workload_kind=kind,
        namespace=namespace,
        findings=findings,
        risk_score=risk_score,
        escape_risk=_escape_risk_label(risk_score),
    )


def analyze_many(manifests: List[dict]) -> List[CEXResult]:
    """Analyze a list of K8s manifests and return one CEXResult per manifest.

    Parameters
    ----------
    manifests:
        List of plain Python dicts, each representing a Kubernetes manifest.

    Returns
    -------
    List[CEXResult]
        Results in the same order as the input manifests.
    """
    return [analyze(m) for m in manifests]
