"""Offline AKS node pool hardening analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


_CHECK_SEVERITIES: dict[str, str] = {
    "AKS-001": "HIGH",
    "AKS-002": "HIGH",
    "AKS-003": "MEDIUM",
    "AKS-004": "HIGH",
    "AKS-005": "MEDIUM",
}

_CHECK_WEIGHTS: dict[str, int] = {
    "AKS-001": 30,
    "AKS-002": 25,
    "AKS-003": 15,
    "AKS-004": 25,
    "AKS-005": 10,
}


@dataclass(frozen=True)
class AKSNodePoolConfig:
    """Minimal offline posture snapshot for one AKS node pool."""

    name: str
    mode: str = "User"
    os_type: str = "Linux"
    os_sku: str = ""
    node_count: int = 0
    min_count: int | None = None
    max_count: int | None = None
    enable_auto_scaling: bool = False
    enable_node_public_ip: bool = False
    enable_encryption_at_host: bool = False
    enable_fips: bool = False
    vnet_subnet_id: str = ""
    only_critical_addons_enabled: bool = False
    workload_runtime: str = ""


@dataclass(frozen=True)
class AKSFinding:
    check_id: str
    severity: str
    pool_name: str
    title: str
    detail: str
    remediation: str
    weight: int


@dataclass
class AKSNodePoolReport:
    cluster_name: str
    findings: list[AKSFinding] = field(default_factory=list)
    risk_score: int = 0

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def summary(self) -> str:
        counts = self.by_severity()
        return (
            f"AKSNodePoolReport [{self.cluster_name}] "
            f"findings={len(self.findings)} "
            f"[HIGH={counts.get('HIGH', 0)} MEDIUM={counts.get('MEDIUM', 0)} LOW={counts.get('LOW', 0)}] "
            f"risk_score={self.risk_score}/100"
        )


def _make_finding(
    *,
    check_id: str,
    pool_name: str,
    title: str,
    detail: str,
    remediation: str,
) -> AKSFinding:
    return AKSFinding(
        check_id=check_id,
        severity=_CHECK_SEVERITIES[check_id],
        pool_name=pool_name,
        title=title,
        detail=detail,
        remediation=remediation,
        weight=_CHECK_WEIGHTS[check_id],
    )


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "enabled"}
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def _coerce_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


def node_pool_from_dict(payload: dict[str, Any]) -> AKSNodePoolConfig:
    """Build a config from Azure CLI or custom JSON payloads."""

    return AKSNodePoolConfig(
        name=str(payload.get("name", "unnamed-pool")),
        mode=str(payload.get("mode", payload.get("poolMode", "User"))),
        os_type=str(payload.get("osType", payload.get("os_type", "Linux"))),
        os_sku=str(payload.get("osSKU", payload.get("os_sku", ""))),
        node_count=int(payload.get("count", payload.get("node_count", 0)) or 0),
        min_count=_coerce_int(payload.get("minCount", payload.get("min_count"))),
        max_count=_coerce_int(payload.get("maxCount", payload.get("max_count"))),
        enable_auto_scaling=_coerce_bool(
            payload.get("enableAutoScaling", payload.get("enable_auto_scaling", False))
        ),
        enable_node_public_ip=_coerce_bool(
            payload.get("enableNodePublicIP", payload.get("enable_node_public_ip", False))
        ),
        enable_encryption_at_host=_coerce_bool(
            payload.get("enableEncryptionAtHost", payload.get("enable_encryption_at_host", False))
        ),
        enable_fips=_coerce_bool(payload.get("enableFIPS", payload.get("enable_fips", False))),
        vnet_subnet_id=str(payload.get("vnetSubnetID", payload.get("vnet_subnet_id", ""))),
        only_critical_addons_enabled=_coerce_bool(
            payload.get(
                "onlyCriticalAddonsEnabled",
                payload.get("only_critical_addons_enabled", False),
            )
        ),
        workload_runtime=str(payload.get("workloadRuntime", payload.get("workload_runtime", ""))),
    )


def _check_public_ip(config: AKSNodePoolConfig) -> AKSFinding | None:
    if not config.enable_node_public_ip:
        return None
    return _make_finding(
        check_id="AKS-001",
        pool_name=config.name,
        title="Node pool exposes node public IP addresses",
        detail=(
            f"AKS node pool '{config.name}' has enableNodePublicIP enabled. "
            "Direct node reachability expands the cluster attack surface."
        ),
        remediation="Disable node public IPs and front workloads with private networking plus controlled ingress.",
    )


def _check_host_encryption(config: AKSNodePoolConfig) -> AKSFinding | None:
    if config.enable_encryption_at_host:
        return None
    return _make_finding(
        check_id="AKS-002",
        pool_name=config.name,
        title="Host-based encryption is disabled",
        detail=(
            f"AKS node pool '{config.name}' does not enable EncryptionAtHost. "
            "Node caches and disks lack the stronger host-level data-at-rest control."
        ),
        remediation="Enable EncryptionAtHost for node pools that handle production or sensitive workloads.",
    )


def _check_fips(config: AKSNodePoolConfig) -> AKSFinding | None:
    if config.os_type.lower() != "linux" or config.enable_fips:
        return None
    return _make_finding(
        check_id="AKS-003",
        pool_name=config.name,
        title="Linux node pool does not use a FIPS-enabled image",
        detail=(
            f"AKS node pool '{config.name}' runs Linux nodes without FIPS mode enabled. "
            "This reduces cryptographic hardening for regulated workloads."
        ),
        remediation="Enable FIPS-backed node images for regulated workloads that require stronger crypto assurance.",
    )


def _check_system_pool_isolation(config: AKSNodePoolConfig) -> AKSFinding | None:
    if config.mode.lower() != "system" or config.only_critical_addons_enabled:
        return None
    return _make_finding(
        check_id="AKS-004",
        pool_name=config.name,
        title="System node pool accepts non-critical workloads",
        detail=(
            f"AKS system node pool '{config.name}' does not restrict scheduling to critical add-ons only. "
            "That weakens isolation for core cluster services."
        ),
        remediation="Set onlyCriticalAddonsEnabled on system pools and move application workloads onto dedicated user pools.",
    )


def _check_subnet_isolation(config: AKSNodePoolConfig) -> AKSFinding | None:
    if config.vnet_subnet_id.strip():
        return None
    return _make_finding(
        check_id="AKS-005",
        pool_name=config.name,
        title="Node pool lacks an explicit VNet subnet assignment",
        detail=(
            f"AKS node pool '{config.name}' does not declare a vnetSubnetID. "
            "That makes network segmentation harder to audit in exported posture data."
        ),
        remediation="Place node pools in dedicated subnets so NSG and route boundaries remain explicit and reviewable.",
    )


def analyze_node_pools(
    node_pools: list[AKSNodePoolConfig],
    *,
    cluster_name: str = "unknown-cluster",
) -> AKSNodePoolReport:
    findings: list[AKSFinding] = []
    for config in node_pools:
        for check in (
            _check_public_ip,
            _check_host_encryption,
            _check_fips,
            _check_system_pool_isolation,
            _check_subnet_isolation,
        ):
            finding = check(config)
            if finding:
                findings.append(finding)

    risk_score = min(100, sum(_CHECK_WEIGHTS[check_id] for check_id in {f.check_id for f in findings}))
    return AKSNodePoolReport(cluster_name=cluster_name, findings=findings, risk_score=risk_score)
