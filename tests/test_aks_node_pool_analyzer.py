"""Regression coverage for the AKS node pool analyzer."""

from __future__ import annotations

from kubernetes.aks_node_pool_analyzer import (
    AKSNodePoolConfig,
    analyze_node_pools,
    node_pool_from_dict,
)


def test_node_pool_from_dict_supports_azure_cli_shape() -> None:
    config = node_pool_from_dict(
        {
            "name": "systempool",
            "mode": "System",
            "osType": "Linux",
            "enableNodePublicIP": True,
            "enableEncryptionAtHost": False,
            "enableFIPS": False,
            "vnetSubnetID": "/subscriptions/test/subnets/system",
            "onlyCriticalAddonsEnabled": False,
        }
    )

    assert config.name == "systempool"
    assert config.mode == "System"
    assert config.enable_node_public_ip is True
    assert config.enable_encryption_at_host is False


def test_analyze_node_pools_reports_expected_high_value_findings() -> None:
    report = analyze_node_pools(
        [
            AKSNodePoolConfig(
                name="systempool",
                mode="System",
                os_type="Linux",
                enable_node_public_ip=True,
                enable_encryption_at_host=False,
                enable_fips=False,
                vnet_subnet_id="",
                only_critical_addons_enabled=False,
            )
        ],
        cluster_name="prod-aks",
    )

    check_ids = {finding.check_id for finding in report.findings}
    assert check_ids == {"AKS-001", "AKS-002", "AKS-003", "AKS-004", "AKS-005"}
    assert report.risk_score == 100
    assert "prod-aks" in report.summary()


def test_analyze_node_pools_returns_clean_report_for_hardened_pool() -> None:
    report = analyze_node_pools(
        [
            AKSNodePoolConfig(
                name="userpool-a",
                mode="User",
                os_type="Linux",
                enable_node_public_ip=False,
                enable_encryption_at_host=True,
                enable_fips=True,
                vnet_subnet_id="/subscriptions/test/subnets/apps",
                only_critical_addons_enabled=False,
            )
        ],
        cluster_name="prod-aks",
    )

    assert report.findings == []
    assert report.risk_score == 0


def test_system_pool_isolation_check_is_not_applied_to_user_pools() -> None:
    report = analyze_node_pools(
        [
            AKSNodePoolConfig(
                name="userpool-b",
                mode="User",
                os_type="Linux",
                enable_node_public_ip=False,
                enable_encryption_at_host=True,
                enable_fips=True,
                vnet_subnet_id="/subscriptions/test/subnets/apps",
                only_critical_addons_enabled=False,
            )
        ]
    )

    assert "AKS-004" not in {finding.check_id for finding in report.findings}
