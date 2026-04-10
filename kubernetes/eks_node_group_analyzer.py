"""Offline EKS managed node group hardening analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


_CHECK_SEVERITIES: dict[str, str] = {
    "EKS-001": "HIGH",
    "EKS-002": "HIGH",
    "EKS-003": "HIGH",
    "EKS-004": "MEDIUM",
    "EKS-005": "MEDIUM",
    "EKS-006": "MEDIUM",
}

_CHECK_WEIGHTS: dict[str, int] = {
    "EKS-001": 30,
    "EKS-002": 30,
    "EKS-003": 25,
    "EKS-004": 15,
    "EKS-005": 15,
    "EKS-006": 10,
}


@dataclass(frozen=True)
class EKSNodeGroupConfig:
    """Minimal offline posture snapshot for one EKS managed node group."""

    name: str
    cluster_name: str = ""
    version: str = ""
    ami_type: str = ""
    capacity_type: str = "ON_DEMAND"
    subnets: list[str] = field(default_factory=list)
    public_subnet_names: list[str] = field(default_factory=list)
    remote_access_enabled: bool = False
    imds_v2_required: bool | None = None
    labels: dict[str, str] = field(default_factory=dict)
    taints: list[dict[str, Any]] = field(default_factory=list)
    update_max_unavailable: int | None = None
    update_max_unavailable_percentage: int | None = None


@dataclass(frozen=True)
class EKSFinding:
    check_id: str
    severity: str
    node_group_name: str
    title: str
    detail: str
    remediation: str
    weight: int


@dataclass
class EKSNodeGroupReport:
    cluster_name: str
    findings: list[EKSFinding] = field(default_factory=list)
    risk_score: int = 0

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def summary(self) -> str:
        counts = self.by_severity()
        return (
            f"EKSNodeGroupReport [{self.cluster_name}] "
            f"findings={len(self.findings)} "
            f"[HIGH={counts.get('HIGH', 0)} MEDIUM={counts.get('MEDIUM', 0)} LOW={counts.get('LOW', 0)}] "
            f"risk_score={self.risk_score}/100"
        )


def _make_finding(
    *,
    check_id: str,
    node_group_name: str,
    title: str,
    detail: str,
    remediation: str,
) -> EKSFinding:
    return EKSFinding(
        check_id=check_id,
        severity=_CHECK_SEVERITIES[check_id],
        node_group_name=node_group_name,
        title=title,
        detail=detail,
        remediation=remediation,
        weight=_CHECK_WEIGHTS[check_id],
    )


def _coerce_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "enabled", "required"}:
            return True
        if normalized in {"0", "false", "no", "disabled", "optional"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return None


def _coerce_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


def _coerce_labels(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(label_value) for key, label_value in value.items()}


def _coerce_taints(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _subnet_name(subnet: Any) -> str:
    if isinstance(subnet, dict):
        return str(subnet.get("name") or subnet.get("tagName") or subnet.get("subnetId") or "")
    return str(subnet)


def _subnet_is_public(subnet: Any) -> bool:
    if isinstance(subnet, dict):
        explicit = _coerce_bool(
            subnet.get("public")
            if "public" in subnet
            else subnet.get("isPublic", subnet.get("mapPublicIpOnLaunch"))
        )
        if explicit is not None:
            return explicit
    return "public" in _subnet_name(subnet).lower()


def _extract_imds_required(payload: dict[str, Any]) -> bool | None:
    metadata_options = payload.get("metadataOptions") or payload.get("metadata_options")
    launch_template = payload.get("launchTemplate") or payload.get("launch_template")
    if not isinstance(metadata_options, dict) and isinstance(launch_template, dict):
        metadata_options = launch_template.get("metadataOptions") or launch_template.get("metadata_options")

    if not isinstance(metadata_options, dict):
        return _coerce_bool(payload.get("imdsV2Required", payload.get("imds_v2_required")))

    http_tokens = metadata_options.get("httpTokens", metadata_options.get("http_tokens"))
    if isinstance(http_tokens, str):
        return http_tokens.strip().lower() == "required"
    return _coerce_bool(http_tokens)


def node_group_from_dict(payload: dict[str, Any]) -> EKSNodeGroupConfig:
    """Build a config from AWS CLI or reduced posture JSON payloads."""

    raw_subnets = payload.get("subnets", payload.get("subnetIds", []))
    if not isinstance(raw_subnets, list):
        raw_subnets = []

    update_config = payload.get("updateConfig", payload.get("update_config", {}))
    if not isinstance(update_config, dict):
        update_config = {}

    return EKSNodeGroupConfig(
        name=str(payload.get("nodegroupName", payload.get("name", "unnamed-node-group"))),
        cluster_name=str(payload.get("clusterName", payload.get("cluster_name", ""))),
        version=str(payload.get("version", "")),
        ami_type=str(payload.get("amiType", payload.get("ami_type", ""))),
        capacity_type=str(payload.get("capacityType", payload.get("capacity_type", "ON_DEMAND"))),
        subnets=[_subnet_name(subnet) for subnet in raw_subnets],
        public_subnet_names=[_subnet_name(subnet) for subnet in raw_subnets if _subnet_is_public(subnet)],
        remote_access_enabled=bool(payload.get("remoteAccess") or payload.get("remote_access")),
        imds_v2_required=_extract_imds_required(payload),
        labels=_coerce_labels(payload.get("labels")),
        taints=_coerce_taints(payload.get("taints")),
        update_max_unavailable=_coerce_int(
            update_config.get("maxUnavailable", update_config.get("max_unavailable"))
        ),
        update_max_unavailable_percentage=_coerce_int(
            update_config.get("maxUnavailablePercentage", update_config.get("max_unavailable_percentage"))
        ),
    )


def _check_remote_access(config: EKSNodeGroupConfig) -> EKSFinding | None:
    if not config.remote_access_enabled:
        return None
    return _make_finding(
        check_id="EKS-001",
        node_group_name=config.name,
        title="Node group enables SSH remote access",
        detail=(
            f"EKS node group '{config.name}' has remoteAccess configured. "
            "SSH entry points expand the node compromise and credential theft surface."
        ),
        remediation="Disable node group remoteAccess and use SSM Session Manager with scoped IAM and audit logging.",
    )


def _check_public_subnets(config: EKSNodeGroupConfig) -> EKSFinding | None:
    if not config.public_subnet_names:
        return None
    return _make_finding(
        check_id="EKS-002",
        node_group_name=config.name,
        title="Node group is attached to public subnet inventory",
        detail=(
            f"EKS node group '{config.name}' references public subnet markers: "
            f"{', '.join(config.public_subnet_names)}."
        ),
        remediation="Place worker nodes in private subnets and expose workloads through controlled ingress only.",
    )


def _check_imds_v2(config: EKSNodeGroupConfig) -> EKSFinding | None:
    if config.imds_v2_required is True:
        return None
    return _make_finding(
        check_id="EKS-003",
        node_group_name=config.name,
        title="IMDSv2 enforcement is not confirmed",
        detail=(
            f"EKS node group '{config.name}' does not show metadataOptions.httpTokens=required "
            "in the offline export."
        ),
        remediation="Require IMDSv2 in the launch template metadata options and roll the node group.",
    )


def _check_version_pin(config: EKSNodeGroupConfig) -> EKSFinding | None:
    if config.version.strip():
        return None
    return _make_finding(
        check_id="EKS-004",
        node_group_name=config.name,
        title="Kubernetes version is not pinned in the export",
        detail=(
            f"EKS node group '{config.name}' does not include an explicit Kubernetes version. "
            "Reviewers cannot confirm upgrade skew or patch intent from the artifact."
        ),
        remediation="Include the node group Kubernetes version in review exports and keep upgrade windows documented.",
    )


def _check_workload_isolation(config: EKSNodeGroupConfig) -> EKSFinding | None:
    if config.labels or config.taints:
        return None
    return _make_finding(
        check_id="EKS-005",
        node_group_name=config.name,
        title="Node group lacks labels or taints for workload isolation",
        detail=(
            f"EKS node group '{config.name}' has no labels or taints in the export. "
            "That makes sensitive workload placement harder to enforce and audit."
        ),
        remediation="Add node labels and, for restricted pools, taints with matching workload tolerations.",
    )


def _check_update_budget(config: EKSNodeGroupConfig) -> EKSFinding | None:
    if config.update_max_unavailable is not None or config.update_max_unavailable_percentage is not None:
        return None
    return _make_finding(
        check_id="EKS-006",
        node_group_name=config.name,
        title="Managed update disruption budget is not declared",
        detail=(
            f"EKS node group '{config.name}' does not include updateConfig.maxUnavailable "
            "or maxUnavailablePercentage."
        ),
        remediation="Set an explicit managed node group update budget so security rollouts stay controlled.",
    )


def analyze_node_groups(
    node_groups: list[EKSNodeGroupConfig],
    *,
    cluster_name: str = "unknown-cluster",
) -> EKSNodeGroupReport:
    findings: list[EKSFinding] = []
    for config in node_groups:
        for check in (
            _check_remote_access,
            _check_public_subnets,
            _check_imds_v2,
            _check_version_pin,
            _check_workload_isolation,
            _check_update_budget,
        ):
            finding = check(config)
            if finding:
                findings.append(finding)

    risk_score = min(100, sum(_CHECK_WEIGHTS[check_id] for check_id in {f.check_id for f in findings}))
    return EKSNodeGroupReport(cluster_name=cluster_name, findings=findings, risk_score=risk_score)
