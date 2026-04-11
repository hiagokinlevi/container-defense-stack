"""Offline GKE Autopilot security baseline analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


_CHECK_SEVERITIES: dict[str, str] = {
    "GKE-AP-001": "HIGH",
    "GKE-AP-002": "HIGH",
    "GKE-AP-003": "HIGH",
    "GKE-AP-004": "MEDIUM",
    "GKE-AP-005": "MEDIUM",
}

_CHECK_WEIGHTS: dict[str, int] = {
    "GKE-AP-001": 35,
    "GKE-AP-002": 25,
    "GKE-AP-003": 25,
    "GKE-AP-004": 10,
    "GKE-AP-005": 10,
}


@dataclass(frozen=True)
class GKEAutopilotConfig:
    """Minimal offline posture snapshot for one GKE cluster."""

    name: str
    location: str = ""
    autopilot_enabled: bool = False
    private_nodes_enabled: bool = False
    private_endpoint_enabled: bool = False
    master_authorized_networks_enabled: bool = False
    workload_identity_pool: str = ""
    binary_authorization_enabled: bool = False
    release_channel: str = ""


@dataclass(frozen=True)
class GKEAutopilotFinding:
    check_id: str
    severity: str
    cluster_name: str
    title: str
    detail: str
    remediation: str
    weight: int


@dataclass
class GKEAutopilotReport:
    fleet_name: str
    findings: list[GKEAutopilotFinding] = field(default_factory=list)
    risk_score: int = 0

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def summary(self) -> str:
        counts = self.by_severity()
        return (
            f"GKEAutopilotReport [{self.fleet_name}] "
            f"findings={len(self.findings)} "
            f"[HIGH={counts.get('HIGH', 0)} MEDIUM={counts.get('MEDIUM', 0)} LOW={counts.get('LOW', 0)}] "
            f"risk_score={self.risk_score}/100"
        )


def _make_finding(
    *,
    check_id: str,
    cluster_name: str,
    title: str,
    detail: str,
    remediation: str,
) -> GKEAutopilotFinding:
    return GKEAutopilotFinding(
        check_id=check_id,
        severity=_CHECK_SEVERITIES[check_id],
        cluster_name=cluster_name,
        title=title,
        detail=detail,
        remediation=remediation,
        weight=_CHECK_WEIGHTS[check_id],
    )


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "enabled", "enable"}
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def _nested_bool(payload: dict[str, Any], *path: str) -> bool:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict):
            return False
        current = current.get(key)
    return _coerce_bool(current)


def autopilot_config_from_dict(payload: dict[str, Any]) -> GKEAutopilotConfig:
    """Build a config from gcloud or reduced posture JSON payloads."""

    release_channel = payload.get("releaseChannel", payload.get("release_channel", {}))
    if isinstance(release_channel, dict):
        release_channel_name = str(release_channel.get("channel", release_channel.get("name", "")))
    else:
        release_channel_name = str(release_channel or "")

    workload_identity = payload.get("workloadIdentityConfig", payload.get("workload_identity_config", {}))
    if isinstance(workload_identity, dict):
        workload_identity_pool = str(workload_identity.get("workloadPool", workload_identity.get("workload_pool", "")))
    else:
        workload_identity_pool = str(workload_identity or "")

    binary_authorization = payload.get("binaryAuthorization", payload.get("binary_authorization", {}))
    if isinstance(binary_authorization, dict):
        binary_auth_enabled = _coerce_bool(
            binary_authorization.get("enabled")
            or str(binary_authorization.get("evaluationMode", "")).upper() == "PROJECT_SINGLETON_POLICY_ENFORCE"
        )
    else:
        binary_auth_enabled = _coerce_bool(binary_authorization)

    return GKEAutopilotConfig(
        name=str(payload.get("name", payload.get("clusterName", payload.get("cluster_name", "unnamed-gke")))),
        location=str(payload.get("location", payload.get("zone", ""))),
        autopilot_enabled=_nested_bool(payload, "autopilot", "enabled")
        or _coerce_bool(payload.get("autopilot_enabled")),
        private_nodes_enabled=_nested_bool(payload, "privateClusterConfig", "enablePrivateNodes")
        or _nested_bool(payload, "private_cluster_config", "enable_private_nodes"),
        private_endpoint_enabled=_nested_bool(payload, "privateClusterConfig", "enablePrivateEndpoint")
        or _nested_bool(payload, "private_cluster_config", "enable_private_endpoint"),
        master_authorized_networks_enabled=_nested_bool(payload, "masterAuthorizedNetworksConfig", "enabled")
        or _nested_bool(payload, "master_authorized_networks_config", "enabled"),
        workload_identity_pool=workload_identity_pool,
        binary_authorization_enabled=binary_auth_enabled,
        release_channel=release_channel_name,
    )


def _check_autopilot_enabled(config: GKEAutopilotConfig) -> GKEAutopilotFinding | None:
    if config.autopilot_enabled:
        return None
    return _make_finding(
        check_id="GKE-AP-001",
        cluster_name=config.name,
        title="Cluster is not running in Autopilot mode",
        detail=f"GKE cluster '{config.name}' does not show autopilot.enabled=true in the offline export.",
        remediation="Use Autopilot for baseline-managed node security or document why Standard mode is required.",
    )


def _check_private_nodes(config: GKEAutopilotConfig) -> GKEAutopilotFinding | None:
    if config.private_nodes_enabled:
        return None
    return _make_finding(
        check_id="GKE-AP-002",
        cluster_name=config.name,
        title="Private nodes are not enabled",
        detail=f"GKE Autopilot cluster '{config.name}' does not show private node placement.",
        remediation="Enable private nodes so worker nodes do not receive public IP addresses.",
    )


def _check_authorized_networks(config: GKEAutopilotConfig) -> GKEAutopilotFinding | None:
    if config.master_authorized_networks_enabled or config.private_endpoint_enabled:
        return None
    return _make_finding(
        check_id="GKE-AP-003",
        cluster_name=config.name,
        title="Control plane authorized networks are not enabled",
        detail=f"GKE Autopilot cluster '{config.name}' does not restrict API server source networks.",
        remediation="Enable master authorized networks or a private control-plane endpoint access pattern.",
    )


def _check_workload_identity(config: GKEAutopilotConfig) -> GKEAutopilotFinding | None:
    if config.workload_identity_pool.strip():
        return None
    return _make_finding(
        check_id="GKE-AP-004",
        cluster_name=config.name,
        title="Workload Identity pool is missing",
        detail=f"GKE Autopilot cluster '{config.name}' does not include workloadIdentityConfig.workloadPool.",
        remediation="Enable Workload Identity Federation for GKE and bind Kubernetes service accounts to scoped IAM.",
    )


def _check_binary_authorization(config: GKEAutopilotConfig) -> GKEAutopilotFinding | None:
    if config.binary_authorization_enabled:
        return None
    return _make_finding(
        check_id="GKE-AP-005",
        cluster_name=config.name,
        title="Binary Authorization enforcement is not enabled",
        detail=f"GKE Autopilot cluster '{config.name}' does not show Binary Authorization enforcement.",
        remediation="Enable Binary Authorization policy enforcement for production Autopilot clusters.",
    )


def analyze_autopilot_clusters(
    clusters: list[GKEAutopilotConfig],
    *,
    fleet_name: str = "gke-autopilot",
) -> GKEAutopilotReport:
    findings: list[GKEAutopilotFinding] = []
    for config in clusters:
        for check in (
            _check_autopilot_enabled,
            _check_private_nodes,
            _check_authorized_networks,
            _check_workload_identity,
            _check_binary_authorization,
        ):
            finding = check(config)
            if finding:
                findings.append(finding)

    risk_score = min(100, sum(_CHECK_WEIGHTS[check_id] for check_id in {f.check_id for f in findings}))
    return GKEAutopilotReport(fleet_name=fleet_name, findings=findings, risk_score=risk_score)
