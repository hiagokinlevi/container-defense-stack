"""EKS managed node group hardening analyzer coverage."""

from __future__ import annotations

from kubernetes.eks_node_group_analyzer import analyze_node_groups, node_group_from_dict


def test_eks_node_group_reports_remote_access_public_subnet_and_imds_gap() -> None:
    node_group = node_group_from_dict(
        {
            "nodegroupName": "workers-a",
            "clusterName": "prod-eks",
            "remoteAccess": {"ec2SshKey": "breakglass"},
            "subnets": [{"subnetId": "subnet-123", "name": "public-a", "mapPublicIpOnLaunch": True}],
            "metadataOptions": {"httpTokens": "optional"},
            "labels": {},
            "taints": [],
            "updateConfig": {},
        }
    )

    report = analyze_node_groups([node_group], cluster_name="prod-eks")

    check_ids = {finding.check_id for finding in report.findings}
    assert {"EKS-001", "EKS-002", "EKS-003", "EKS-004", "EKS-005", "EKS-006"} <= check_ids
    assert report.by_severity()["HIGH"] == 3
    assert report.risk_score == 100


def test_eks_node_group_succeeds_for_hardened_private_pool() -> None:
    node_group = node_group_from_dict(
        {
            "nodegroupName": "payments-private",
            "clusterName": "prod-eks",
            "version": "1.30",
            "amiType": "BOTTLEROCKET_x86_64",
            "subnets": [{"subnetId": "subnet-456", "name": "private-a", "mapPublicIpOnLaunch": False}],
            "metadataOptions": {"httpTokens": "required"},
            "labels": {"workload-tier": "restricted"},
            "taints": [{"key": "restricted", "value": "true", "effect": "NO_SCHEDULE"}],
            "updateConfig": {"maxUnavailable": 1},
        }
    )

    report = analyze_node_groups([node_group], cluster_name="prod-eks")

    assert report.findings == []
    assert report.risk_score == 0
    assert "findings=0" in report.summary()
