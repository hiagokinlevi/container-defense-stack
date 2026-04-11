"""GKE Autopilot security baseline analyzer coverage."""

from __future__ import annotations

from kubernetes.gke_autopilot_analyzer import analyze_autopilot_clusters, autopilot_config_from_dict


def test_gke_autopilot_reports_expected_baseline_gaps() -> None:
    cluster = autopilot_config_from_dict(
        {
            "name": "prod-gke",
            "location": "us-central1",
            "autopilot": {"enabled": False},
            "privateClusterConfig": {"enablePrivateNodes": False},
            "masterAuthorizedNetworksConfig": {"enabled": False},
            "workloadIdentityConfig": {},
            "binaryAuthorization": {"evaluationMode": "DISABLED"},
        }
    )

    report = analyze_autopilot_clusters([cluster], fleet_name="prod-fleet")

    check_ids = {finding.check_id for finding in report.findings}
    assert check_ids == {"GKE-AP-001", "GKE-AP-002", "GKE-AP-003", "GKE-AP-004", "GKE-AP-005"}
    assert report.by_severity()["HIGH"] == 3
    assert report.risk_score == 100
    assert "prod-fleet" in report.summary()


def test_gke_autopilot_succeeds_for_hardened_cluster() -> None:
    cluster = autopilot_config_from_dict(
        {
            "name": "payments-gke",
            "location": "us-central1",
            "autopilot": {"enabled": True},
            "privateClusterConfig": {"enablePrivateNodes": True},
            "masterAuthorizedNetworksConfig": {"enabled": True},
            "workloadIdentityConfig": {"workloadPool": "acme.svc.id.goog"},
            "binaryAuthorization": {"evaluationMode": "PROJECT_SINGLETON_POLICY_ENFORCE"},
            "releaseChannel": {"channel": "REGULAR"},
        }
    )

    report = analyze_autopilot_clusters([cluster], fleet_name="prod-fleet")

    assert report.findings == []
    assert report.risk_score == 0


def test_gke_autopilot_accepts_private_endpoint_without_authorized_networks() -> None:
    cluster = autopilot_config_from_dict(
        {
            "name": "internal-gke",
            "location": "us-central1",
            "autopilot": {"enabled": True},
            "privateClusterConfig": {
                "enablePrivateNodes": True,
                "enablePrivateEndpoint": True,
            },
            "masterAuthorizedNetworksConfig": {"enabled": False},
            "workloadIdentityConfig": {"workloadPool": "acme.svc.id.goog"},
            "binaryAuthorization": {"evaluationMode": "PROJECT_SINGLETON_POLICY_ENFORCE"},
        }
    )

    report = analyze_autopilot_clusters([cluster], fleet_name="prod-fleet")

    assert {finding.check_id for finding in report.findings} == set()
    assert report.risk_score == 0


def test_gke_autopilot_accepts_snake_case_private_endpoint_exports() -> None:
    cluster = autopilot_config_from_dict(
        {
            "cluster_name": "private-endpoint-gke",
            "location": "us-central1",
            "autopilot_enabled": True,
            "private_cluster_config": {
                "enable_private_nodes": True,
                "enable_private_endpoint": True,
            },
            "master_authorized_networks_config": {"enabled": False},
            "workload_identity_config": {"workload_pool": "acme.svc.id.goog"},
            "binary_authorization": {"enabled": True},
        }
    )

    report = analyze_autopilot_clusters([cluster], fleet_name="prod-fleet")

    assert report.findings == []
    assert report.risk_score == 0
