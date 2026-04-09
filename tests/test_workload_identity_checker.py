# SPDX-License-Identifier: CC-BY-4.0
# Cyber Port — Container Defense Stack
# Test suite: test_workload_identity_checker.py
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# Run with: python -m pytest tests/test_workload_identity_checker.py -q

import sys
import os

# Ensure the project root is on the path so the kubernetes package is importable.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from kubernetes.workload_identity_checker import (
    WorkloadIdentityConfig,
    WIDFinding,
    WIDResult,
    check,
    check_many,
    _CHECK_WEIGHTS,
    _CHECK_SEVERITIES,
    _CLOUD_ENV_VARS,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _cfg(
    *,
    workload_name: str = "test-app",
    workload_kind: str = "Deployment",
    namespace: str = "default",
    service_account: str = "app-sa",
    annotations: dict = None,
    env_var_names: list = None,
    projected_token_audiences: list = None,
    projected_token_expiry_seconds=None,
) -> WorkloadIdentityConfig:
    """Build a WorkloadIdentityConfig with sensible defaults."""
    return WorkloadIdentityConfig(
        workload_name=workload_name,
        workload_kind=workload_kind,
        namespace=namespace,
        service_account=service_account,
        annotations=annotations if annotations is not None else {},
        env_var_names=env_var_names if env_var_names is not None else [],
        projected_token_audiences=(
            projected_token_audiences if projected_token_audiences is not None else []
        ),
        projected_token_expiry_seconds=projected_token_expiry_seconds,
    )


def _ids(result: WIDResult):
    """Return the set of fired check IDs for a WIDResult."""
    return {f.check_id for f in result.findings}


# ===========================================================================
# WID-001: Cloud env vars without workload identity annotation
# ===========================================================================


def test_wid001_fires_on_aws_role_arn_env_no_annotation():
    r = check(_cfg(env_var_names=["AWS_ROLE_ARN"]))
    assert "WID-001" in _ids(r)


def test_wid001_fires_on_aws_web_identity_token_env():
    r = check(_cfg(env_var_names=["AWS_WEB_IDENTITY_TOKEN_FILE"]))
    assert "WID-001" in _ids(r)


def test_wid001_fires_on_google_application_credentials():
    r = check(_cfg(env_var_names=["GOOGLE_APPLICATION_CREDENTIALS"]))
    assert "WID-001" in _ids(r)


def test_wid001_fires_on_azure_client_id():
    r = check(_cfg(env_var_names=["AZURE_CLIENT_ID"]))
    assert "WID-001" in _ids(r)


def test_wid001_fires_on_azure_tenant_id():
    r = check(_cfg(env_var_names=["AZURE_TENANT_ID"]))
    assert "WID-001" in _ids(r)


def test_wid001_fires_on_azure_federated_token_file():
    r = check(_cfg(env_var_names=["AZURE_FEDERATED_TOKEN_FILE"]))
    assert "WID-001" in _ids(r)


def test_wid001_suppressed_when_irsa_annotation_present():
    r = check(
        _cfg(
            env_var_names=["AWS_ROLE_ARN"],
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/my-role"},
        )
    )
    assert "WID-001" not in _ids(r)


def test_wid001_suppressed_when_gcp_wi_annotation_present():
    r = check(
        _cfg(
            env_var_names=["GOOGLE_APPLICATION_CREDENTIALS"],
            annotations={"iam.gke.io/gcp-service-account": "sa@project.iam.gserviceaccount.com"},
        )
    )
    assert "WID-001" not in _ids(r)


def test_wid001_suppressed_when_azure_wi_annotation_present():
    r = check(
        _cfg(
            env_var_names=["AZURE_CLIENT_ID"],
            annotations={"azure.workload.identity/client-id": "some-client-uuid"},
        )
    )
    assert "WID-001" not in _ids(r)


def test_wid001_not_fired_when_no_cloud_env_vars():
    r = check(_cfg(env_var_names=["DATABASE_URL", "PORT"]))
    assert "WID-001" not in _ids(r)


def test_wid001_case_insensitive_env_var_matching():
    # Lowercase version of a known cloud env var should still trigger.
    r = check(_cfg(env_var_names=["aws_role_arn"]))
    assert "WID-001" in _ids(r)


def test_wid001_detail_contains_matched_var():
    r = check(_cfg(env_var_names=["AWS_ROLE_ARN"]))
    finding = next(f for f in r.findings if f.check_id == "WID-001")
    assert "AWS_ROLE_ARN" in finding.detail


def test_wid001_severity_is_high():
    r = check(_cfg(env_var_names=["AWS_ROLE_ARN"]))
    finding = next(f for f in r.findings if f.check_id == "WID-001")
    assert finding.severity == "HIGH"


def test_wid001_weight_is_25():
    r = check(_cfg(env_var_names=["AWS_ROLE_ARN"]))
    finding = next(f for f in r.findings if f.check_id == "WID-001")
    assert finding.weight == 25


# ===========================================================================
# WID-002: IRSA ARN with overly broad permissions
# ===========================================================================


def test_wid002_fires_on_admin_role_name():
    r = check(
        _cfg(annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789:role/MyAdminRole"})
    )
    assert "WID-002" in _ids(r)


def test_wid002_fires_on_fullaccess_role_name():
    r = check(
        _cfg(
            annotations={
                "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789:role/S3FullAccess"
            }
        )
    )
    assert "WID-002" in _ids(r)


def test_wid002_fires_on_poweruser_role_name():
    r = check(
        _cfg(
            annotations={
                "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789:role/PowerUser"
            }
        )
    )
    assert "WID-002" in _ids(r)


def test_wid002_fires_on_administratoraccess_role_name():
    r = check(
        _cfg(
            annotations={
                "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789:role/AdministratorAccess"
            }
        )
    )
    assert "WID-002" in _ids(r)


def test_wid002_fires_on_wildcard_in_arn():
    r = check(
        _cfg(annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789:role/*"})
    )
    assert "WID-002" in _ids(r)


def test_wid002_not_fired_for_scoped_role_name():
    r = check(
        _cfg(
            annotations={
                "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789:role/payments-reader"
            }
        )
    )
    assert "WID-002" not in _ids(r)


def test_wid002_not_fired_when_no_irsa_annotation():
    r = check(_cfg())
    assert "WID-002" not in _ids(r)


def test_wid002_case_insensitive_pattern_matching():
    # "ADMIN" in role name should still fire.
    r = check(
        _cfg(
            annotations={
                "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789:role/SUPERADMIN"
            }
        )
    )
    assert "WID-002" in _ids(r)


def test_wid002_severity_is_critical():
    r = check(
        _cfg(
            annotations={
                "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789:role/AdminRole"
            }
        )
    )
    finding = next(f for f in r.findings if f.check_id == "WID-002")
    assert finding.severity == "CRITICAL"


def test_wid002_weight_is_45():
    r = check(
        _cfg(
            annotations={
                "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789:role/AdminRole"
            }
        )
    )
    finding = next(f for f in r.findings if f.check_id == "WID-002")
    assert finding.weight == 45


def test_wid002_detail_contains_role_arn():
    arn = "arn:aws:iam::123456789:role/AdminRole"
    r = check(_cfg(annotations={"eks.amazonaws.com/role-arn": arn}))
    finding = next(f for f in r.findings if f.check_id == "WID-002")
    assert arn in finding.detail


# ===========================================================================
# WID-003: GCP Workload Identity with owner/editor project role
# ===========================================================================


def test_wid003_fires_on_roles_owner_in_annotation_value():
    r = check(
        _cfg(
            annotations={
                "iam.gke.io/gcp-service-account": "sa@project.iam.gserviceaccount.com",
                "iam.gke.io/role-binding": "roles/owner",
            }
        )
    )
    assert "WID-003" in _ids(r)


def test_wid003_fires_on_roles_editor_in_annotation_value():
    r = check(
        _cfg(
            annotations={
                "iam.gke.io/gcp-service-account": "sa@project.iam.gserviceaccount.com",
                "custom/binding": "projects/my-proj:roles/editor",
            }
        )
    )
    assert "WID-003" in _ids(r)


def test_wid003_not_fired_when_no_gcp_annotation():
    r = check(
        _cfg(
            annotations={
                "iam.gke.io/role-binding": "roles/owner",
            }
        )
    )
    assert "WID-003" not in _ids(r)


def test_wid003_not_fired_for_safe_gcp_role():
    r = check(
        _cfg(
            annotations={
                "iam.gke.io/gcp-service-account": "sa@project.iam.gserviceaccount.com",
                "iam.gke.io/role-binding": "roles/storage.objectViewer",
            }
        )
    )
    assert "WID-003" not in _ids(r)


def test_wid003_severity_is_critical():
    r = check(
        _cfg(
            annotations={
                "iam.gke.io/gcp-service-account": "sa@project.iam.gserviceaccount.com",
                "iam.gke.io/role-binding": "roles/owner",
            }
        )
    )
    finding = next(f for f in r.findings if f.check_id == "WID-003")
    assert finding.severity == "CRITICAL"


def test_wid003_weight_is_45():
    r = check(
        _cfg(
            annotations={
                "iam.gke.io/gcp-service-account": "sa@project.iam.gserviceaccount.com",
                "iam.gke.io/role-binding": "roles/owner",
            }
        )
    )
    finding = next(f for f in r.findings if f.check_id == "WID-003")
    assert finding.weight == 45


def test_wid003_detail_identifies_dangerous_annotation():
    r = check(
        _cfg(
            annotations={
                "iam.gke.io/gcp-service-account": "sa@proj.iam.gserviceaccount.com",
                "iam.gke.io/role-binding": "roles/owner",
            }
        )
    )
    finding = next(f for f in r.findings if f.check_id == "WID-003")
    assert "roles/owner" in finding.detail


def test_wid003_not_fired_gcp_annotation_present_no_dangerous_role():
    # GCP annotation exists but none of the annotation values contain owner/editor.
    r = check(
        _cfg(
            annotations={
                "iam.gke.io/gcp-service-account": "sa@project.iam.gserviceaccount.com",
            }
        )
    )
    assert "WID-003" not in _ids(r)


# ===========================================================================
# WID-004: Default ServiceAccount with cloud credential env vars
# ===========================================================================


def test_wid004_fires_on_default_sa_with_aws_env():
    r = check(
        _cfg(service_account="default", env_var_names=["AWS_ROLE_ARN"])
    )
    assert "WID-004" in _ids(r)


def test_wid004_fires_on_empty_sa_name_with_cloud_env():
    r = check(_cfg(service_account="", env_var_names=["AZURE_CLIENT_ID"]))
    assert "WID-004" in _ids(r)


def test_wid004_fires_on_google_credentials_with_default_sa():
    r = check(
        _cfg(service_account="default", env_var_names=["GOOGLE_APPLICATION_CREDENTIALS"])
    )
    assert "WID-004" in _ids(r)


def test_wid004_not_fired_when_dedicated_sa():
    r = check(
        _cfg(service_account="payments-sa", env_var_names=["AWS_ROLE_ARN"])
    )
    assert "WID-004" not in _ids(r)


def test_wid004_not_fired_when_default_sa_no_cloud_vars():
    r = check(_cfg(service_account="default", env_var_names=["DATABASE_URL"]))
    assert "WID-004" not in _ids(r)


def test_wid004_severity_is_high():
    r = check(
        _cfg(service_account="default", env_var_names=["AWS_ROLE_ARN"])
    )
    finding = next(f for f in r.findings if f.check_id == "WID-004")
    assert finding.severity == "HIGH"


def test_wid004_weight_is_25():
    r = check(
        _cfg(service_account="default", env_var_names=["AWS_ROLE_ARN"])
    )
    finding = next(f for f in r.findings if f.check_id == "WID-004")
    assert finding.weight == 25


def test_wid004_detail_mentions_default_sa():
    r = check(
        _cfg(service_account="default", env_var_names=["AWS_ROLE_ARN"])
    )
    finding = next(f for f in r.findings if f.check_id == "WID-004")
    assert "default" in finding.detail.lower()


# ===========================================================================
# WID-005: Projected token missing specific audience
# ===========================================================================


def test_wid005_fires_when_audiences_empty_and_irsa_annotation():
    r = check(
        _cfg(
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/my-role"},
            projected_token_audiences=[],
        )
    )
    assert "WID-005" in _ids(r)


def test_wid005_fires_when_audiences_contains_wildcard():
    r = check(
        _cfg(
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/my-role"},
            projected_token_audiences=["*"],
        )
    )
    assert "WID-005" in _ids(r)


def test_wid005_fires_when_audiences_contains_empty_string():
    r = check(
        _cfg(
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/my-role"},
            projected_token_audiences=[""],
        )
    )
    assert "WID-005" in _ids(r)


def test_wid005_not_fired_when_specific_audience_set():
    r = check(
        _cfg(
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/my-role"},
            projected_token_audiences=["sts.amazonaws.com"],
        )
    )
    assert "WID-005" not in _ids(r)


def test_wid005_not_fired_when_no_workload_identity_annotations():
    # Even if audiences are empty, no WID-005 without a WI annotation.
    r = check(_cfg(projected_token_audiences=[]))
    assert "WID-005" not in _ids(r)


def test_wid005_fires_for_gcp_wi_annotation_with_empty_audience():
    r = check(
        _cfg(
            annotations={"iam.gke.io/gcp-service-account": "sa@proj.iam.gserviceaccount.com"},
            projected_token_audiences=[],
        )
    )
    assert "WID-005" in _ids(r)


def test_wid005_fires_for_azure_wi_annotation_with_empty_audience():
    r = check(
        _cfg(
            annotations={"azure.workload.identity/client-id": "client-uuid"},
            projected_token_audiences=[],
        )
    )
    assert "WID-005" in _ids(r)


def test_wid005_severity_is_medium():
    r = check(
        _cfg(
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/my-role"},
            projected_token_audiences=[],
        )
    )
    finding = next(f for f in r.findings if f.check_id == "WID-005")
    assert finding.severity == "MEDIUM"


def test_wid005_weight_is_15():
    r = check(
        _cfg(
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/my-role"},
            projected_token_audiences=[],
        )
    )
    finding = next(f for f in r.findings if f.check_id == "WID-005")
    assert finding.weight == 15


def test_wid005_not_fired_when_audience_list_has_valid_value_alongside_wildcard_free():
    # Multiple valid audiences, none are wildcard or empty.
    r = check(
        _cfg(
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/my-role"},
            projected_token_audiences=["sts.amazonaws.com", "vault.example.com"],
        )
    )
    assert "WID-005" not in _ids(r)


# ===========================================================================
# WID-006: Multiple workloads sharing the same cloud identity annotation
# ===========================================================================


def test_wid006_fires_when_two_workloads_share_irsa_arn():
    arn = "arn:aws:iam::123:role/shared-role"
    configs = [
        _cfg(workload_name="app-a", annotations={"eks.amazonaws.com/role-arn": arn}),
        _cfg(workload_name="app-b", annotations={"eks.amazonaws.com/role-arn": arn}),
    ]
    results = check_many(configs)
    assert "WID-006" in _ids(results[0])
    assert "WID-006" in _ids(results[1])


def test_wid006_not_fired_when_workloads_use_different_irsa_arns():
    configs = [
        _cfg(
            workload_name="app-a",
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/role-a"},
        ),
        _cfg(
            workload_name="app-b",
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/role-b"},
        ),
    ]
    results = check_many(configs)
    assert "WID-006" not in _ids(results[0])
    assert "WID-006" not in _ids(results[1])


def test_wid006_fires_when_three_workloads_share_same_gcp_annotation():
    sa = "shared-sa@project.iam.gserviceaccount.com"
    configs = [
        _cfg(workload_name=f"app-{i}", annotations={"iam.gke.io/gcp-service-account": sa})
        for i in range(3)
    ]
    results = check_many(configs)
    for r in results:
        assert "WID-006" in _ids(r)


def test_wid006_detail_mentions_other_sharing_workload():
    arn = "arn:aws:iam::123:role/shared-role"
    configs = [
        _cfg(workload_name="app-a", annotations={"eks.amazonaws.com/role-arn": arn}),
        _cfg(workload_name="app-b", annotations={"eks.amazonaws.com/role-arn": arn}),
    ]
    results = check_many(configs)
    finding_a = next(f for f in results[0].findings if f.check_id == "WID-006")
    assert "app-b" in finding_a.detail
    finding_b = next(f for f in results[1].findings if f.check_id == "WID-006")
    assert "app-a" in finding_b.detail


def test_wid006_severity_is_medium():
    arn = "arn:aws:iam::123:role/shared-role"
    configs = [
        _cfg(workload_name="app-a", annotations={"eks.amazonaws.com/role-arn": arn}),
        _cfg(workload_name="app-b", annotations={"eks.amazonaws.com/role-arn": arn}),
    ]
    results = check_many(configs)
    finding = next(f for f in results[0].findings if f.check_id == "WID-006")
    assert finding.severity == "MEDIUM"


def test_wid006_weight_is_15():
    arn = "arn:aws:iam::123:role/shared-role"
    configs = [
        _cfg(workload_name="app-a", annotations={"eks.amazonaws.com/role-arn": arn}),
        _cfg(workload_name="app-b", annotations={"eks.amazonaws.com/role-arn": arn}),
    ]
    results = check_many(configs)
    finding = next(f for f in results[0].findings if f.check_id == "WID-006")
    assert finding.weight == 15


def test_wid006_single_workload_in_check_many_does_not_fire():
    configs = [
        _cfg(
            workload_name="solo",
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/solo-role"},
        )
    ]
    results = check_many(configs)
    assert "WID-006" not in _ids(results[0])


def test_wid006_only_workloads_sharing_annotation_are_flagged():
    arn = "arn:aws:iam::123:role/shared-role"
    configs = [
        _cfg(workload_name="app-a", annotations={"eks.amazonaws.com/role-arn": arn}),
        _cfg(workload_name="app-b", annotations={"eks.amazonaws.com/role-arn": arn}),
        _cfg(
            workload_name="app-c",
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/unique-role"},
        ),
    ]
    results = check_many(configs)
    assert "WID-006" in _ids(results[0])
    assert "WID-006" in _ids(results[1])
    assert "WID-006" not in _ids(results[2])


def test_wid006_fires_for_azure_annotation_sharing():
    client_id = "shared-azure-client-uuid"
    configs = [
        _cfg(
            workload_name="app-a",
            annotations={"azure.workload.identity/client-id": client_id},
        ),
        _cfg(
            workload_name="app-b",
            annotations={"azure.workload.identity/client-id": client_id},
        ),
    ]
    results = check_many(configs)
    assert "WID-006" in _ids(results[0])
    assert "WID-006" in _ids(results[1])


# ===========================================================================
# WID-007: Projected token missing or excessive expirationSeconds
# ===========================================================================


def test_wid007_fires_when_expiry_not_set_and_irsa_annotation():
    r = check(
        _cfg(
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/my-role"},
            projected_token_expiry_seconds=None,
        )
    )
    assert "WID-007" in _ids(r)


def test_wid007_fires_when_expiry_exceeds_86400():
    r = check(
        _cfg(
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/my-role"},
            projected_token_expiry_seconds=172800,  # 48 hours
        )
    )
    assert "WID-007" in _ids(r)


def test_wid007_fires_when_expiry_is_exactly_86401():
    r = check(
        _cfg(
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/my-role"},
            projected_token_expiry_seconds=86401,
        )
    )
    assert "WID-007" in _ids(r)


def test_wid007_not_fired_when_expiry_is_exactly_86400():
    r = check(
        _cfg(
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/my-role"},
            projected_token_expiry_seconds=86400,
        )
    )
    assert "WID-007" not in _ids(r)


def test_wid007_not_fired_when_expiry_is_3600():
    r = check(
        _cfg(
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/my-role"},
            projected_token_expiry_seconds=3600,
        )
    )
    assert "WID-007" not in _ids(r)


def test_wid007_not_fired_when_no_workload_identity_annotation():
    # No annotation means WID-007 is irrelevant even if expiry is missing.
    r = check(_cfg(projected_token_expiry_seconds=None))
    assert "WID-007" not in _ids(r)


def test_wid007_fires_for_gcp_wi_annotation_with_no_expiry():
    r = check(
        _cfg(
            annotations={"iam.gke.io/gcp-service-account": "sa@proj.iam.gserviceaccount.com"},
            projected_token_expiry_seconds=None,
        )
    )
    assert "WID-007" in _ids(r)


def test_wid007_fires_for_azure_wi_annotation_with_long_expiry():
    r = check(
        _cfg(
            annotations={"azure.workload.identity/client-id": "client-uuid"},
            projected_token_expiry_seconds=604800,  # 7 days
        )
    )
    assert "WID-007" in _ids(r)


def test_wid007_severity_is_medium():
    r = check(
        _cfg(
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/my-role"},
            projected_token_expiry_seconds=None,
        )
    )
    finding = next(f for f in r.findings if f.check_id == "WID-007")
    assert finding.severity == "MEDIUM"


def test_wid007_weight_is_15():
    r = check(
        _cfg(
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/my-role"},
            projected_token_expiry_seconds=None,
        )
    )
    finding = next(f for f in r.findings if f.check_id == "WID-007")
    assert finding.weight == 15


# ===========================================================================
# Risk score calculation
# ===========================================================================


def test_risk_score_is_zero_for_clean_workload():
    r = check(_cfg())
    assert r.risk_score == 0


def test_risk_score_equals_single_finding_weight():
    r = check(_cfg(env_var_names=["AWS_ROLE_ARN"]))
    # WID-001 weight = 25; WID-004 not fired (service_account != default).
    assert r.risk_score == 25


def test_risk_score_sums_unique_weights():
    # WID-001 (25) + WID-004 (25) = 50
    r = check(
        _cfg(
            service_account="default",
            env_var_names=["AWS_ROLE_ARN"],
        )
    )
    assert r.risk_score == 50


def test_risk_score_capped_at_100():
    # WID-002 (45) + WID-003 (45) = 90, add WID-005 (15) => 105 -> capped at 100.
    r = check(
        _cfg(
            annotations={
                "eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/AdminRole",
                "iam.gke.io/gcp-service-account": "sa@proj.iam.gserviceaccount.com",
                "iam.gke.io/role-binding": "roles/owner",
            },
            projected_token_audiences=[],
        )
    )
    assert r.risk_score <= 100


def test_risk_score_each_check_id_counted_once():
    # Two separate configs that both fire WID-001 independently; within one
    # result each check ID only adds its weight once.
    r = check(_cfg(env_var_names=["AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"]))
    # Still only one WID-001 finding — weight counted once.
    assert r.risk_score == 25


def test_risk_score_updated_after_wid006_in_check_many():
    # shared-role triggers WID-005 (15) + WID-006 (15) + WID-007 (15) = 45.
    # Audiences default to [] and expiry to None with IRSA annotation present.
    arn = "arn:aws:iam::123:role/shared-role"
    configs = [
        _cfg(workload_name="app-a", annotations={"eks.amazonaws.com/role-arn": arn}),
        _cfg(workload_name="app-b", annotations={"eks.amazonaws.com/role-arn": arn}),
    ]
    results = check_many(configs)
    # WID-006 must be present in both results.
    assert "WID-006" in _ids(results[0])
    assert "WID-006" in _ids(results[1])
    # Scores are equal for both workloads (symmetric sharing).
    assert results[0].risk_score == results[1].risk_score


# ===========================================================================
# WIDResult helper methods
# ===========================================================================


def test_to_dict_returns_expected_keys():
    r = check(_cfg())
    d = r.to_dict()
    assert set(d.keys()) == {"workload_name", "workload_kind", "namespace", "risk_score", "findings"}


def test_to_dict_findings_is_list_of_dicts():
    r = check(_cfg(env_var_names=["AWS_ROLE_ARN"]))
    d = r.to_dict()
    assert isinstance(d["findings"], list)
    assert all(isinstance(f, dict) for f in d["findings"])


def test_to_dict_finding_keys():
    r = check(_cfg(env_var_names=["AWS_ROLE_ARN"]))
    d = r.to_dict()
    assert set(d["findings"][0].keys()) == {"check_id", "severity", "title", "detail", "weight"}


def test_summary_contains_workload_name():
    r = check(_cfg(workload_name="my-app"))
    assert "my-app" in r.summary()


def test_summary_contains_risk_score():
    r = check(_cfg(env_var_names=["AWS_ROLE_ARN"]))
    assert str(r.risk_score) in r.summary()


def test_summary_contains_namespace():
    r = check(_cfg(namespace="prod"))
    assert "prod" in r.summary()


def test_by_severity_groups_correctly():
    r = check(
        _cfg(
            service_account="default",
            env_var_names=["AWS_ROLE_ARN"],
        )
    )
    groups = r.by_severity()
    # WID-001 and WID-004 are both HIGH.
    assert "HIGH" in groups
    assert all(f.severity == "HIGH" for f in groups["HIGH"])


def test_by_severity_empty_for_clean_workload():
    r = check(_cfg())
    assert r.by_severity() == {}


def test_by_severity_critical_group():
    r = check(
        _cfg(
            annotations={
                "eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/AdminRole"
            }
        )
    )
    groups = r.by_severity()
    assert "CRITICAL" in groups


# ===========================================================================
# Metadata / constants
# ===========================================================================


def test_check_weights_dict_has_all_seven_checks():
    expected = {"WID-001", "WID-002", "WID-003", "WID-004", "WID-005", "WID-006", "WID-007"}
    assert set(_CHECK_WEIGHTS.keys()) == expected


def test_check_weights_values_are_positive_ints():
    for check_id, weight in _CHECK_WEIGHTS.items():
        assert isinstance(weight, int), f"{check_id} weight is not int"
        assert weight > 0, f"{check_id} weight is not positive"


def test_check_severities_dict_has_all_seven_checks():
    expected = {"WID-001", "WID-002", "WID-003", "WID-004", "WID-005", "WID-006", "WID-007"}
    assert set(_CHECK_SEVERITIES.keys()) == expected


def test_cloud_env_vars_frozenset_contains_expected_vars():
    expected = {
        "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AZURE_CLIENT_ID",
        "AZURE_TENANT_ID",
        "AZURE_FEDERATED_TOKEN_FILE",
    }
    assert expected == set(_CLOUD_ENV_VARS)


# ===========================================================================
# Integration / combined scenarios
# ===========================================================================


def test_clean_workload_no_findings():
    r = check(
        _cfg(
            service_account="payments-sa",
            annotations={},
            env_var_names=["DATABASE_URL", "LOG_LEVEL"],
            projected_token_audiences=["sts.amazonaws.com"],
            projected_token_expiry_seconds=3600,
        )
    )
    assert r.findings == []
    assert r.risk_score == 0


def test_multiple_findings_on_single_workload():
    # WID-001 + WID-004 together.
    r = check(
        _cfg(
            service_account="default",
            annotations={},
            env_var_names=["AWS_ROLE_ARN"],
        )
    )
    assert "WID-001" in _ids(r)
    assert "WID-004" in _ids(r)


def test_irsa_with_safe_role_and_audience_fires_only_wid005_wid007():
    r = check(
        _cfg(
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/payments-reader"},
            projected_token_audiences=[],
            projected_token_expiry_seconds=None,
        )
    )
    fired = _ids(r)
    assert "WID-002" not in fired
    assert "WID-005" in fired
    assert "WID-007" in fired


def test_check_many_preserves_order():
    names = ["alpha", "beta", "gamma"]
    configs = [_cfg(workload_name=n) for n in names]
    results = check_many(configs)
    assert [r.workload_name for r in results] == names


def test_check_many_empty_list_returns_empty():
    assert check_many([]) == []


def test_check_many_single_item_returns_single_result():
    results = check_many([_cfg(workload_name="solo")])
    assert len(results) == 1
    assert results[0].workload_name == "solo"


def test_wid004_and_wid001_both_fire_for_default_sa_with_cloud_env():
    r = check(_cfg(service_account="default", env_var_names=["GOOGLE_APPLICATION_CREDENTIALS"]))
    fired = _ids(r)
    assert "WID-001" in fired
    assert "WID-004" in fired


def test_wid002_does_not_fire_for_readonly_role():
    r = check(
        _cfg(
            annotations={
                "eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/s3-readonly"
            }
        )
    )
    assert "WID-002" not in _ids(r)


def test_wid006_risk_score_includes_individual_findings_plus_wid006():
    # AdminRole triggers WID-002 (45) + WID-005 (15) + WID-006 (15) + WID-007 (15) = 90.
    # (audiences=[] and expiry=None with IRSA annotation => WID-005 and WID-007 also fire.)
    arn = "arn:aws:iam::123:role/AdminRole"
    configs = [
        _cfg(workload_name="app-a", annotations={"eks.amazonaws.com/role-arn": arn}),
        _cfg(workload_name="app-b", annotations={"eks.amazonaws.com/role-arn": arn}),
    ]
    results = check_many(configs)
    for r in results:
        # WID-002 and WID-006 must both be present.
        assert "WID-002" in _ids(r)
        assert "WID-006" in _ids(r)
        assert r.risk_score == 90  # WID-002=45 + WID-005=15 + WID-006=15 + WID-007=15


def test_workload_identity_config_fields_accessible():
    cfg = _cfg(
        workload_name="test",
        workload_kind="StatefulSet",
        namespace="staging",
        service_account="my-sa",
        annotations={"k": "v"},
        env_var_names=["FOO"],
        projected_token_audiences=["bar"],
        projected_token_expiry_seconds=1800,
    )
    assert cfg.workload_name == "test"
    assert cfg.workload_kind == "StatefulSet"
    assert cfg.namespace == "staging"
    assert cfg.service_account == "my-sa"
    assert cfg.annotations == {"k": "v"}
    assert cfg.env_var_names == ["FOO"]
    assert cfg.projected_token_audiences == ["bar"]
    assert cfg.projected_token_expiry_seconds == 1800


def test_wid_finding_fields_accessible():
    f = WIDFinding(
        check_id="WID-001",
        severity="HIGH",
        title="Test",
        detail="Some detail",
        weight=25,
    )
    assert f.check_id == "WID-001"
    assert f.severity == "HIGH"
    assert f.title == "Test"
    assert f.detail == "Some detail"
    assert f.weight == 25


def test_wid_result_default_findings_empty():
    r = WIDResult(workload_name="x", workload_kind="Pod", namespace="default")
    assert r.findings == []
    assert r.risk_score == 0


def test_wid007_expiry_exactly_1_is_valid():
    r = check(
        _cfg(
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/my-role"},
            projected_token_expiry_seconds=1,
        )
    )
    assert "WID-007" not in _ids(r)


def test_wid005_audience_list_with_only_empty_string():
    r = check(
        _cfg(
            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/my-role"},
            projected_token_audiences=[""],
        )
    )
    assert "WID-005" in _ids(r)


def test_check_many_does_not_duplicate_individual_check_findings():
    # Ensure check_many does not run individual checks twice.
    arn = "arn:aws:iam::123:role/unique-role"
    configs = [_cfg(workload_name="solo", annotations={"eks.amazonaws.com/role-arn": arn})]
    results = check_many(configs)
    check_ids = [f.check_id for f in results[0].findings]
    # No duplicates: each check ID appears at most once.
    assert len(check_ids) == len(set(check_ids))
