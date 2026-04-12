# CC BY 4.0 — Creative Commons Attribution 4.0 International
# https://creativecommons.org/licenses/by/4.0/
# Cyber Port — Container Defense Stack
# Test suite: test_service_account_auditor.py
# Tests: service_account_auditor — all 7 checks + edge cases

from __future__ import annotations

import sys
import os

# Ensure the kubernetes package directory is importable when running from repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from kubernetes.service_account_auditor import (
    SABinding,
    SAFinding,
    SAResult,
    analyze,
    analyze_many,
    _CHECK_WEIGHTS,
    _CHECK_SEVERITY,
)

# ===========================================================================
# Fixture helpers
# ===========================================================================

def make_sa(
    name: str = "my-sa",
    namespace: str = "default",
    automount: object = None,
    pull_secrets: object = None,
) -> dict:
    """Build a minimal ServiceAccount manifest dict."""
    sa: dict = {"metadata": {"name": name, "namespace": namespace}}
    if automount is not None:
        sa["automountServiceAccountToken"] = automount
    if pull_secrets is not None:
        sa["imagePullSecrets"] = pull_secrets
    return sa


def make_binding(
    binding_name: str,
    binding_kind: str,
    role_name: str,
    role_kind: str,
    sa_name: str,
    sa_namespace: str,
) -> dict:
    return {
        "kind": binding_kind,
        "metadata": {"name": binding_name},
        "roleRef": {"kind": role_kind, "name": role_name},
        "subjects": [
            {"kind": "ServiceAccount", "name": sa_name, "namespace": sa_namespace}
        ],
    }


def make_role(
    name: str,
    kind: str,
    rules: list,
) -> dict:
    return {
        "kind": kind,
        "metadata": {"name": name},
        "rules": rules,
    }


def make_rule(verbs: list, resources: list, api_groups: list = None) -> dict:
    rule: dict = {"verbs": verbs, "resources": resources}
    rule["apiGroups"] = api_groups or [""]
    return rule


# Shortcut bindings and roles used repeatedly
CLUSTER_ADMIN_BINDING = make_binding(
    "ca-binding", "ClusterRoleBinding", "cluster-admin", "ClusterRole",
    "my-sa", "default"
)

WILDCARD_ROLE = make_role("wildcard-role", "ClusterRole", [make_rule(["*"], ["pods"])])
WILDCARD_BINDING = make_binding(
    "wildcard-binding", "ClusterRoleBinding", "wildcard-role", "ClusterRole",
    "my-sa", "default"
)

SECRETS_ROLE = make_role(
    "secrets-reader", "ClusterRole",
    [make_rule(["get", "list", "watch"], ["secrets"])]
)
SECRETS_BINDING = make_binding(
    "secrets-binding", "ClusterRoleBinding", "secrets-reader", "ClusterRole",
    "my-sa", "default"
)

TOKEN_REQUEST_ROLE = make_role(
    "token-minter", "ClusterRole",
    [make_rule(["create"], ["serviceaccounts/token"])]
)
TOKEN_REQUEST_BINDING = make_binding(
    "token-request-binding", "ClusterRoleBinding", "token-minter", "ClusterRole",
    "my-sa", "default"
)


# ===========================================================================
# SA-001 — cluster-admin ClusterRoleBinding
# ===========================================================================

class TestSA001:
    """SA-001: ServiceAccount bound to cluster-admin ClusterRoleBinding."""

    def test_fires_when_cluster_admin_crb_present(self):
        sa = make_sa()
        result = analyze(sa, bindings=[CLUSTER_ADMIN_BINDING], roles=[])
        ids = [f.check_id for f in result.findings]
        assert "SA-001" in ids

    def test_severity_is_critical(self):
        sa = make_sa()
        result = analyze(sa, bindings=[CLUSTER_ADMIN_BINDING], roles=[])
        finding = next(f for f in result.findings if f.check_id == "SA-001")
        assert finding.severity == "CRITICAL"

    def test_weight_is_45(self):
        assert _CHECK_WEIGHTS["SA-001"] == 45

    def test_does_not_fire_without_binding(self):
        sa = make_sa()
        result = analyze(sa, bindings=[], roles=[])
        assert all(f.check_id != "SA-001" for f in result.findings)

    def test_does_not_fire_for_different_role_name(self):
        sa = make_sa()
        binding = make_binding(
            "other-binding", "ClusterRoleBinding", "some-other-role", "ClusterRole",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[])
        assert all(f.check_id != "SA-001" for f in result.findings)

    def test_does_not_fire_for_rolebinding_named_cluster_admin(self):
        # RoleBinding (not ClusterRoleBinding) to cluster-admin should NOT fire SA-001
        sa = make_sa()
        binding = make_binding(
            "rb-binding", "RoleBinding", "cluster-admin", "ClusterRole",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[])
        assert all(f.check_id != "SA-001" for f in result.findings)

    def test_fires_only_once_with_multiple_cluster_admin_bindings(self):
        sa = make_sa()
        b2 = make_binding(
            "ca-binding-2", "ClusterRoleBinding", "cluster-admin", "ClusterRole",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[CLUSTER_ADMIN_BINDING, b2], roles=[])
        sa001 = [f for f in result.findings if f.check_id == "SA-001"]
        assert len(sa001) == 1  # deduplicated — first match wins

    def test_does_not_fire_for_unrelated_sa(self):
        sa = make_sa(name="other-sa")
        result = analyze(sa, bindings=[CLUSTER_ADMIN_BINDING], roles=[])
        assert all(f.check_id != "SA-001" for f in result.findings)

    def test_risk_score_includes_sa001_weight(self):
        sa = make_sa(automount=False)  # disable SA-002 to isolate
        result = analyze(sa, bindings=[CLUSTER_ADMIN_BINDING], roles=[])
        assert result.risk_score >= 45

    def test_finding_detail_contains_binding_name(self):
        sa = make_sa()
        result = analyze(sa, bindings=[CLUSTER_ADMIN_BINDING], roles=[])
        finding = next(f for f in result.findings if f.check_id == "SA-001")
        assert "ca-binding" in finding.detail


# ===========================================================================
# SA-002 — automountServiceAccountToken not explicitly false
# ===========================================================================

class TestSA002:
    """SA-002: automountServiceAccountToken not explicitly disabled."""

    def test_fires_when_field_absent(self):
        sa = make_sa()  # automount key not set
        result = analyze(sa, bindings=[], roles=[])
        assert any(f.check_id == "SA-002" for f in result.findings)

    def test_fires_when_set_to_true(self):
        sa = make_sa(automount=True)
        result = analyze(sa, bindings=[], roles=[])
        assert any(f.check_id == "SA-002" for f in result.findings)

    def test_does_not_fire_when_explicitly_false(self):
        sa = make_sa(automount=False)
        result = analyze(sa, bindings=[], roles=[])
        assert all(f.check_id != "SA-002" for f in result.findings)

    def test_severity_is_medium(self):
        sa = make_sa()
        result = analyze(sa, bindings=[], roles=[])
        finding = next(f for f in result.findings if f.check_id == "SA-002")
        assert finding.severity == "MEDIUM"

    def test_weight_is_15(self):
        assert _CHECK_WEIGHTS["SA-002"] == 15

    def test_detail_mentions_not_set_when_absent(self):
        sa = make_sa()
        result = analyze(sa, bindings=[], roles=[])
        finding = next(f for f in result.findings if f.check_id == "SA-002")
        assert "not set" in finding.detail.lower() or "defaults to true" in finding.detail.lower()

    def test_detail_mentions_explicitly_true_when_set(self):
        sa = make_sa(automount=True)
        result = analyze(sa, bindings=[], roles=[])
        finding = next(f for f in result.findings if f.check_id == "SA-002")
        assert "true" in finding.detail.lower()

    def test_risk_score_includes_weight_when_absent(self):
        sa = make_sa()
        result = analyze(sa, bindings=[], roles=[])
        assert result.risk_score >= 15

    def test_automount_false_does_not_contribute_to_score(self):
        sa = make_sa(automount=False)
        result = analyze(sa, bindings=[], roles=[])
        sa002_findings = [f for f in result.findings if f.check_id == "SA-002"]
        assert len(sa002_findings) == 0


# ===========================================================================
# SA-003 — wildcard verbs
# ===========================================================================

class TestSA003:
    """SA-003: bound role contains wildcard verb."""

    def test_fires_when_wildcard_verb_in_rule(self):
        sa = make_sa(automount=False)
        result = analyze(sa, bindings=[WILDCARD_BINDING], roles=[WILDCARD_ROLE])
        assert any(f.check_id == "SA-003" for f in result.findings)

    def test_severity_is_high(self):
        sa = make_sa(automount=False)
        result = analyze(sa, bindings=[WILDCARD_BINDING], roles=[WILDCARD_ROLE])
        finding = next(f for f in result.findings if f.check_id == "SA-003")
        assert finding.severity == "HIGH"

    def test_weight_is_25(self):
        assert _CHECK_WEIGHTS["SA-003"] == 25

    def test_does_not_fire_for_explicit_verbs_only(self):
        sa = make_sa(automount=False)
        role = make_role("limited", "ClusterRole", [make_rule(["get", "list"], ["pods"])])
        binding = make_binding(
            "limited-binding", "ClusterRoleBinding", "limited", "ClusterRole",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[role])
        assert all(f.check_id != "SA-003" for f in result.findings)

    def test_does_not_fire_with_no_bindings(self):
        sa = make_sa(automount=False)
        result = analyze(sa, bindings=[], roles=[])
        assert all(f.check_id != "SA-003" for f in result.findings)

    def test_fires_for_rolebinding_with_wildcard(self):
        sa = make_sa(automount=False)
        role = make_role("rb-wildcard", "Role", [make_rule(["*"], ["configmaps"])])
        binding = make_binding(
            "rb-w-binding", "RoleBinding", "rb-wildcard", "Role",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[role])
        assert any(f.check_id == "SA-003" for f in result.findings)

    def test_fires_only_once_even_multiple_wildcard_bindings(self):
        sa = make_sa(automount=False)
        role2 = make_role("wildcard-role-2", "ClusterRole", [make_rule(["*"], ["deployments"])])
        binding2 = make_binding(
            "w-binding-2", "ClusterRoleBinding", "wildcard-role-2", "ClusterRole",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[WILDCARD_BINDING, binding2], roles=[WILDCARD_ROLE, role2])
        sa003 = [f for f in result.findings if f.check_id == "SA-003"]
        assert len(sa003) == 1

    def test_detail_mentions_binding_name(self):
        sa = make_sa(automount=False)
        result = analyze(sa, bindings=[WILDCARD_BINDING], roles=[WILDCARD_ROLE])
        finding = next(f for f in result.findings if f.check_id == "SA-003")
        assert "wildcard-binding" in finding.detail


# ===========================================================================
# SA-004 — ClusterRole grants secrets read cluster-wide
# ===========================================================================

class TestSA004:
    """SA-004: ClusterRole grants secrets get/list/watch across the cluster."""

    def test_fires_when_secrets_get_in_crb(self):
        sa = make_sa(automount=False)
        result = analyze(sa, bindings=[SECRETS_BINDING], roles=[SECRETS_ROLE])
        assert any(f.check_id == "SA-004" for f in result.findings)

    def test_severity_is_critical(self):
        sa = make_sa(automount=False)
        result = analyze(sa, bindings=[SECRETS_BINDING], roles=[SECRETS_ROLE])
        finding = next(f for f in result.findings if f.check_id == "SA-004")
        assert finding.severity == "CRITICAL"

    def test_weight_is_40(self):
        assert _CHECK_WEIGHTS["SA-004"] == 40

    def test_does_not_fire_for_rolebinding_even_with_secrets(self):
        sa = make_sa(automount=False)
        binding = make_binding(
            "rb-secrets", "RoleBinding", "secrets-reader", "ClusterRole",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[SECRETS_ROLE])
        assert all(f.check_id != "SA-004" for f in result.findings)

    def test_does_not_fire_when_no_secrets_resource(self):
        sa = make_sa(automount=False)
        role = make_role("pods-reader", "ClusterRole", [make_rule(["get", "list"], ["pods"])])
        binding = make_binding(
            "pods-rb", "ClusterRoleBinding", "pods-reader", "ClusterRole",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[role])
        assert all(f.check_id != "SA-004" for f in result.findings)

    def test_does_not_fire_when_only_write_verbs_on_secrets(self):
        sa = make_sa(automount=False)
        role = make_role(
            "secrets-creator", "ClusterRole",
            [make_rule(["create", "update", "patch", "delete"], ["secrets"])]
        )
        binding = make_binding(
            "sec-create-rb", "ClusterRoleBinding", "secrets-creator", "ClusterRole",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[role])
        assert all(f.check_id != "SA-004" for f in result.findings)

    def test_fires_when_wildcard_resource_and_list_verb(self):
        # Wildcard on resources should cover secrets
        sa = make_sa(automount=False)
        role = make_role("all-reader", "ClusterRole", [make_rule(["list"], ["*"])])
        binding = make_binding(
            "all-rb", "ClusterRoleBinding", "all-reader", "ClusterRole",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[role])
        assert any(f.check_id == "SA-004" for f in result.findings)

    def test_fires_when_wildcard_verb_on_secrets(self):
        # Wildcard verb implicitly includes get/list/watch
        sa = make_sa(automount=False)
        role = make_role("all-verbs-secrets", "ClusterRole", [make_rule(["*"], ["secrets"])])
        binding = make_binding(
            "avs-rb", "ClusterRoleBinding", "all-verbs-secrets", "ClusterRole",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[role])
        assert any(f.check_id == "SA-004" for f in result.findings)

    def test_detail_contains_binding_name(self):
        sa = make_sa(automount=False)
        result = analyze(sa, bindings=[SECRETS_BINDING], roles=[SECRETS_ROLE])
        finding = next(f for f in result.findings if f.check_id == "SA-004")
        assert "secrets-binding" in finding.detail

    def test_fires_for_get_only_verb(self):
        sa = make_sa(automount=False)
        role = make_role("secrets-getter", "ClusterRole", [make_rule(["get"], ["secrets"])])
        binding = make_binding(
            "sg-rb", "ClusterRoleBinding", "secrets-getter", "ClusterRole",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[role])
        assert any(f.check_id == "SA-004" for f in result.findings)

    def test_fires_for_watch_only_verb(self):
        sa = make_sa(automount=False)
        role = make_role("secrets-watcher", "ClusterRole", [make_rule(["watch"], ["secrets"])])
        binding = make_binding(
            "sw-rb", "ClusterRoleBinding", "secrets-watcher", "ClusterRole",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[role])
        assert any(f.check_id == "SA-004" for f in result.findings)


# ===========================================================================
# SA-005 — default SA bound to non-trivial role
# ===========================================================================

class TestSA005:
    """SA-005: default ServiceAccount bound to a non-trivial role."""

    def test_fires_when_default_sa_bound_to_custom_role(self):
        sa = make_sa(name="default", namespace="my-ns", automount=False)
        role = make_role("my-role", "Role", [make_rule(["get"], ["pods"])])
        binding = make_binding(
            "default-rb", "RoleBinding", "my-role", "Role",
            "default", "my-ns"
        )
        result = analyze(sa, bindings=[binding], roles=[role])
        assert any(f.check_id == "SA-005" for f in result.findings)

    def test_does_not_fire_for_non_default_sa_name(self):
        sa = make_sa(name="my-app-sa", automount=False)
        role = make_role("my-role", "Role", [make_rule(["get"], ["pods"])])
        binding = make_binding(
            "non-default-rb", "RoleBinding", "my-role", "Role",
            "my-app-sa", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[role])
        assert all(f.check_id != "SA-005" for f in result.findings)

    def test_does_not_fire_when_bound_to_view_role(self):
        sa = make_sa(name="default", automount=False)
        binding = make_binding(
            "view-rb", "ClusterRoleBinding", "view", "ClusterRole",
            "default", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[])
        assert all(f.check_id != "SA-005" for f in result.findings)

    def test_does_not_fire_when_bound_to_aggregate_to_view(self):
        sa = make_sa(name="default", automount=False)
        binding = make_binding(
            "agg-view-rb", "ClusterRoleBinding",
            "system:aggregate-to-view", "ClusterRole",
            "default", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[])
        assert all(f.check_id != "SA-005" for f in result.findings)

    def test_does_not_fire_when_bound_to_aggregate_to_edit(self):
        sa = make_sa(name="default", automount=False)
        binding = make_binding(
            "agg-edit-rb", "ClusterRoleBinding",
            "system:aggregate-to-edit", "ClusterRole",
            "default", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[])
        assert all(f.check_id != "SA-005" for f in result.findings)

    def test_severity_is_high(self):
        sa = make_sa(name="default", namespace="my-ns", automount=False)
        role = make_role("danger-role", "Role", [make_rule(["*"], ["*"])])
        binding = make_binding(
            "danger-rb", "RoleBinding", "danger-role", "Role",
            "default", "my-ns"
        )
        result = analyze(sa, bindings=[binding], roles=[role])
        finding = next(f for f in result.findings if f.check_id == "SA-005")
        assert finding.severity == "HIGH"

    def test_weight_is_25(self):
        assert _CHECK_WEIGHTS["SA-005"] == 25

    def test_detail_contains_role_name(self):
        sa = make_sa(name="default", namespace="prod", automount=False)
        role = make_role("prod-role", "Role", [make_rule(["get"], ["deployments"])])
        binding = make_binding(
            "prod-rb", "RoleBinding", "prod-role", "Role",
            "default", "prod"
        )
        result = analyze(sa, bindings=[binding], roles=[role])
        finding = next(f for f in result.findings if f.check_id == "SA-005")
        assert "prod-role" in finding.detail

    def test_does_not_fire_with_no_bindings(self):
        sa = make_sa(name="default", automount=False)
        result = analyze(sa, bindings=[], roles=[])
        assert all(f.check_id != "SA-005" for f in result.findings)

    def test_fires_once_even_with_multiple_non_trivial_bindings(self):
        sa = make_sa(name="default", namespace="ns1", automount=False)
        role1 = make_role("r1", "Role", [make_rule(["get"], ["pods"])])
        role2 = make_role("r2", "Role", [make_rule(["list"], ["services"])])
        b1 = make_binding("rb1", "RoleBinding", "r1", "Role", "default", "ns1")
        b2 = make_binding("rb2", "RoleBinding", "r2", "Role", "default", "ns1")
        result = analyze(sa, bindings=[b1, b2], roles=[role1, role2])
        sa005 = [f for f in result.findings if f.check_id == "SA-005"]
        assert len(sa005) == 1


# ===========================================================================
# SA-006 — imagePullSecrets present
# ===========================================================================

class TestSA006:
    """SA-006: imagePullSecrets entries expose registry credentials."""

    def test_fires_when_pull_secrets_present(self):
        sa = make_sa(automount=False, pull_secrets=[{"name": "registry-creds"}])
        result = analyze(sa, bindings=[], roles=[])
        assert any(f.check_id == "SA-006" for f in result.findings)

    def test_does_not_fire_when_pull_secrets_absent(self):
        sa = make_sa(automount=False)
        result = analyze(sa, bindings=[], roles=[])
        assert all(f.check_id != "SA-006" for f in result.findings)

    def test_does_not_fire_when_pull_secrets_empty_list(self):
        sa = make_sa(automount=False, pull_secrets=[])
        result = analyze(sa, bindings=[], roles=[])
        assert all(f.check_id != "SA-006" for f in result.findings)

    def test_severity_is_medium(self):
        sa = make_sa(automount=False, pull_secrets=[{"name": "reg"}])
        result = analyze(sa, bindings=[], roles=[])
        finding = next(f for f in result.findings if f.check_id == "SA-006")
        assert finding.severity == "MEDIUM"

    def test_weight_is_15(self):
        assert _CHECK_WEIGHTS["SA-006"] == 15

    def test_detail_contains_secret_name(self):
        sa = make_sa(automount=False, pull_secrets=[{"name": "my-registry-secret"}])
        result = analyze(sa, bindings=[], roles=[])
        finding = next(f for f in result.findings if f.check_id == "SA-006")
        assert "my-registry-secret" in finding.detail

    def test_fires_with_multiple_pull_secrets(self):
        sa = make_sa(
            automount=False,
            pull_secrets=[{"name": "creds-a"}, {"name": "creds-b"}]
        )
        result = analyze(sa, bindings=[], roles=[])
        sa006 = [f for f in result.findings if f.check_id == "SA-006"]
        assert len(sa006) == 1  # single finding even for multiple secrets

    def test_detail_contains_all_secret_names(self):
        sa = make_sa(
            automount=False,
            pull_secrets=[{"name": "alpha"}, {"name": "beta"}]
        )
        result = analyze(sa, bindings=[], roles=[])
        finding = next(f for f in result.findings if f.check_id == "SA-006")
        assert "alpha" in finding.detail
        assert "beta" in finding.detail


# ===========================================================================
# SA-007 — kube-system SA with non-system binding
# ===========================================================================

class TestSA007:
    """SA-007: kube-system ServiceAccount has a non-system binding."""

    def test_fires_for_kube_system_sa_with_custom_binding(self):
        sa = make_sa(name="coredns", namespace="kube-system", automount=False)
        binding = make_binding(
            "custom-binding", "ClusterRoleBinding", "some-role", "ClusterRole",
            "coredns", "kube-system"
        )
        result = analyze(sa, bindings=[binding], roles=[])
        assert any(f.check_id == "SA-007" for f in result.findings)

    def test_does_not_fire_for_non_kube_system_namespace(self):
        sa = make_sa(name="my-sa", namespace="production", automount=False)
        binding = make_binding(
            "custom-binding", "ClusterRoleBinding", "some-role", "ClusterRole",
            "my-sa", "production"
        )
        result = analyze(sa, bindings=[binding], roles=[])
        assert all(f.check_id != "SA-007" for f in result.findings)

    def test_does_not_fire_for_system_prefixed_binding(self):
        sa = make_sa(name="kube-proxy", namespace="kube-system", automount=False)
        binding = make_binding(
            "system:kube-proxy", "ClusterRoleBinding", "system:node-proxier", "ClusterRole",
            "kube-proxy", "kube-system"
        )
        result = analyze(sa, bindings=[binding], roles=[])
        assert all(f.check_id != "SA-007" for f in result.findings)

    def test_severity_is_high(self):
        sa = make_sa(name="coredns", namespace="kube-system", automount=False)
        binding = make_binding(
            "custom-binding", "ClusterRoleBinding", "some-role", "ClusterRole",
            "coredns", "kube-system"
        )
        result = analyze(sa, bindings=[binding], roles=[])
        finding = next(f for f in result.findings if f.check_id == "SA-007")
        assert finding.severity == "HIGH"

    def test_weight_is_20(self):
        assert _CHECK_WEIGHTS["SA-007"] == 20

    def test_detail_contains_binding_name(self):
        sa = make_sa(name="etcd", namespace="kube-system", automount=False)
        binding = make_binding(
            "etcd-custom-binding", "RoleBinding", "custom-role", "Role",
            "etcd", "kube-system"
        )
        result = analyze(sa, bindings=[binding], roles=[])
        finding = next(f for f in result.findings if f.check_id == "SA-007")
        assert "etcd-custom-binding" in finding.detail

    def test_does_not_fire_with_no_bindings(self):
        sa = make_sa(name="coredns", namespace="kube-system", automount=False)
        result = analyze(sa, bindings=[], roles=[])
        assert all(f.check_id != "SA-007" for f in result.findings)

    def test_fires_once_even_with_multiple_non_system_bindings(self):
        sa = make_sa(name="coredns", namespace="kube-system", automount=False)
        b1 = make_binding("b1", "ClusterRoleBinding", "r1", "ClusterRole", "coredns", "kube-system")
        b2 = make_binding("b2", "ClusterRoleBinding", "r2", "ClusterRole", "coredns", "kube-system")
        result = analyze(sa, bindings=[b1, b2], roles=[])
        sa007 = [f for f in result.findings if f.check_id == "SA-007"]
        assert len(sa007) == 1


# ===========================================================================
# SA-008 — ServiceAccount token minting via TokenRequest
# ===========================================================================

class TestSA008:
    """SA-008: bound role can create new ServiceAccount tokens."""

    def test_fires_when_binding_can_create_serviceaccount_tokens(self):
        sa = make_sa(automount=False)
        result = analyze(sa, bindings=[TOKEN_REQUEST_BINDING], roles=[TOKEN_REQUEST_ROLE])
        assert any(f.check_id == "SA-008" for f in result.findings)

    def test_fires_for_namespace_scoped_rolebinding(self):
        sa = make_sa(automount=False)
        role = make_role("token-minter", "Role", [make_rule(["create"], ["serviceaccounts/token"])])
        binding = make_binding(
            "ns-token-binding", "RoleBinding", "token-minter", "Role",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[role])
        assert any(f.check_id == "SA-008" for f in result.findings)

    def test_does_not_fire_for_serviceaccounts_resource_without_token_subresource(self):
        sa = make_sa(automount=False)
        role = make_role("sa-writer", "ClusterRole", [make_rule(["create"], ["serviceaccounts"])])
        binding = make_binding(
            "sa-writer-binding", "ClusterRoleBinding", "sa-writer", "ClusterRole",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[role])
        assert all(f.check_id != "SA-008" for f in result.findings)

    def test_does_not_fire_without_create_verb(self):
        sa = make_sa(automount=False)
        role = make_role("token-reader", "ClusterRole", [make_rule(["get"], ["serviceaccounts/token"])])
        binding = make_binding(
            "token-reader-binding", "ClusterRoleBinding", "token-reader", "ClusterRole",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[role])
        assert all(f.check_id != "SA-008" for f in result.findings)

    def test_severity_is_high(self):
        sa = make_sa(automount=False)
        result = analyze(sa, bindings=[TOKEN_REQUEST_BINDING], roles=[TOKEN_REQUEST_ROLE])
        finding = next(f for f in result.findings if f.check_id == "SA-008")
        assert finding.severity == "HIGH"

    def test_weight_is_35(self):
        assert _CHECK_WEIGHTS["SA-008"] == 35

    def test_detail_mentions_binding_name_and_scope(self):
        sa = make_sa(automount=False)
        result = analyze(sa, bindings=[TOKEN_REQUEST_BINDING], roles=[TOKEN_REQUEST_ROLE])
        finding = next(f for f in result.findings if f.check_id == "SA-008")
        assert "token-request-binding" in finding.detail
        assert "cluster-wide" in finding.detail


# ===========================================================================
# Risk score logic
# ===========================================================================

class TestRiskScore:
    """Tests for the risk_score computation and capping behaviour."""

    def test_score_zero_for_clean_sa(self):
        sa = make_sa(automount=False)
        result = analyze(sa, bindings=[], roles=[])
        assert result.risk_score == 0

    def test_score_capped_at_100(self):
        # SA-001 (45) + SA-004 (40) + SA-003 (25) + SA-005 (25) = 135 -> capped at 100
        sa = make_sa(name="default", namespace="default")
        crb_admin = make_binding(
            "admin-rb", "ClusterRoleBinding", "cluster-admin", "ClusterRole",
            "default", "default"
        )
        wildcard_role = make_role("all-role", "ClusterRole", [make_rule(["*"], ["*"])])
        wildcard_binding = make_binding(
            "all-rb", "ClusterRoleBinding", "all-role", "ClusterRole",
            "default", "default"
        )
        result = analyze(
            sa,
            bindings=[crb_admin, wildcard_binding],
            roles=[wildcard_role]
        )
        assert result.risk_score <= 100

    def test_score_equals_sum_of_weights_when_under_100(self):
        # Only SA-002 should fire (15) — automount not set, no bindings
        sa = make_sa()
        result = analyze(sa, bindings=[], roles=[])
        total = sum(f.weight for f in result.findings)
        assert result.risk_score == min(100, total)

    def test_score_sa002_alone_is_15(self):
        sa = make_sa()  # automount not set, no bindings
        result = analyze(sa, bindings=[], roles=[])
        # SA-002 is the only check that can fire here
        assert result.risk_score == 15

    def test_score_sa001_plus_sa002_is_60(self):
        sa = make_sa()  # automount not set
        result = analyze(sa, bindings=[CLUSTER_ADMIN_BINDING], roles=[])
        expected = min(100, 45 + 15)
        assert result.risk_score == expected

    def test_score_combines_multiple_independent_checks(self):
        sa = make_sa(automount=False, pull_secrets=[{"name": "reg"}])
        result = analyze(sa, bindings=[SECRETS_BINDING], roles=[SECRETS_ROLE])
        # SA-004 (40) + SA-006 (15) = 55
        assert result.risk_score == 55


# ===========================================================================
# SAResult data model methods
# ===========================================================================

class TestSAResultMethods:
    """Tests for to_dict(), summary(), and by_severity() methods."""

    def test_to_dict_contains_expected_keys(self):
        sa = make_sa()
        result = analyze(sa, bindings=[], roles=[])
        d = result.to_dict()
        assert "sa_name" in d
        assert "namespace" in d
        assert "risk_score" in d
        assert "findings" in d

    def test_to_dict_findings_have_required_keys(self):
        sa = make_sa()  # SA-002 fires
        result = analyze(sa, bindings=[], roles=[])
        d = result.to_dict()
        assert len(d["findings"]) >= 1
        finding_dict = d["findings"][0]
        for key in ("check_id", "severity", "title", "detail", "weight"):
            assert key in finding_dict

    def test_to_dict_risk_score_matches_result(self):
        sa = make_sa()
        result = analyze(sa, bindings=[], roles=[])
        d = result.to_dict()
        assert d["risk_score"] == result.risk_score

    def test_summary_returns_string(self):
        sa = make_sa()
        result = analyze(sa, bindings=[], roles=[])
        s = result.summary()
        assert isinstance(s, str)
        assert len(s) > 0

    def test_summary_contains_sa_name(self):
        sa = make_sa(name="webapp-sa", namespace="prod")
        result = analyze(sa, bindings=[], roles=[])
        assert "webapp-sa" in result.summary()

    def test_summary_contains_risk_score(self):
        sa = make_sa()
        result = analyze(sa, bindings=[], roles=[])
        assert str(result.risk_score) in result.summary()

    def test_by_severity_groups_correctly(self):
        sa = make_sa()  # SA-002 (MEDIUM)
        result = analyze(sa, bindings=[CLUSTER_ADMIN_BINDING], roles=[])  # + SA-001 (CRITICAL)
        grouped = result.by_severity()
        assert "CRITICAL" in grouped
        assert "MEDIUM" in grouped
        assert any(f.check_id == "SA-001" for f in grouped["CRITICAL"])
        assert any(f.check_id == "SA-002" for f in grouped["MEDIUM"])

    def test_by_severity_returns_empty_dict_for_clean_sa(self):
        sa = make_sa(automount=False)
        result = analyze(sa, bindings=[], roles=[])
        assert result.by_severity() == {}

    def test_to_dict_sa_name_and_namespace_correct(self):
        sa = make_sa(name="test-sa", namespace="test-ns", automount=False)
        result = analyze(sa, bindings=[], roles=[])
        d = result.to_dict()
        assert d["sa_name"] == "test-sa"
        assert d["namespace"] == "test-ns"


# ===========================================================================
# Edge cases — SA with no bindings, missing fields, empty inputs
# ===========================================================================

class TestEdgeCases:
    """Edge cases for robustness and graceful handling of missing data."""

    def test_sa_with_no_bindings_has_no_binding_findings(self):
        sa = make_sa(automount=False)
        result = analyze(sa, bindings=[], roles=[])
        binding_checks = {"SA-001", "SA-003", "SA-004", "SA-005", "SA-007", "SA-008"}
        for f in result.findings:
            assert f.check_id not in binding_checks

    def test_none_bindings_treated_as_empty(self):
        sa = make_sa(automount=False)
        result = analyze(sa, bindings=None, roles=None)
        assert result is not None
        assert isinstance(result.findings, list)

    def test_sa_missing_metadata_does_not_crash(self):
        sa = {"automountServiceAccountToken": False}
        result = analyze(sa, bindings=[], roles=[])
        assert result.sa_name == ""
        assert result.namespace == ""

    def test_binding_with_no_matching_subject_is_ignored(self):
        sa = make_sa(name="sa-a", namespace="ns-a", automount=False)
        binding = make_binding(
            "other-rb", "ClusterRoleBinding", "cluster-admin", "ClusterRole",
            "sa-b", "ns-a"  # different SA name
        )
        result = analyze(sa, bindings=[binding], roles=[])
        assert all(f.check_id != "SA-001" for f in result.findings)

    def test_role_not_in_roles_list_does_not_crash(self):
        sa = make_sa(automount=False)
        # Binding references a role that is not in the roles list
        binding = make_binding(
            "orphan-rb", "ClusterRoleBinding", "ghost-role", "ClusterRole",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[])
        # Should not raise, and ghost role has no verbs/resources
        assert result is not None

    def test_rolebinding_namespace_mismatch_is_ignored(self):
        sa = make_sa(name="my-sa", namespace="ns-a", automount=False)
        # Subject specifies a different namespace — should be filtered out
        binding = {
            "kind": "RoleBinding",
            "metadata": {"name": "cross-ns-rb"},
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [
                {"kind": "ServiceAccount", "name": "my-sa", "namespace": "ns-b"}
            ],
        }
        result = analyze(sa, bindings=[binding], roles=[])
        assert all(f.check_id != "SA-001" for f in result.findings)

    def test_clusterrolebinding_subject_with_no_namespace_still_matches(self):
        # CRBs may omit namespace in subject
        sa = make_sa(name="my-sa", namespace="default", automount=False)
        binding = {
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "no-ns-crb"},
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [
                {"kind": "ServiceAccount", "name": "my-sa"}  # no namespace key
            ],
        }
        result = analyze(sa, bindings=[binding], roles=[])
        assert any(f.check_id == "SA-001" for f in result.findings)

    def test_non_serviceaccount_subjects_are_ignored(self):
        sa = make_sa(automount=False)
        binding = {
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "user-rb"},
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [
                {"kind": "User", "name": "my-sa", "namespace": "default"}
            ],
        }
        result = analyze(sa, bindings=[binding], roles=[])
        assert all(f.check_id != "SA-001" for f in result.findings)

    def test_empty_rules_list_in_role(self):
        sa = make_sa(automount=False)
        role = make_role("empty-role", "ClusterRole", [])
        binding = make_binding(
            "empty-rb", "ClusterRoleBinding", "empty-role", "ClusterRole",
            "my-sa", "default"
        )
        result = analyze(sa, bindings=[binding], roles=[role])
        assert all(f.check_id not in {"SA-003", "SA-004", "SA-008"} for f in result.findings)

    def test_analyze_many_returns_list_of_same_length(self):
        sas = [make_sa(name=f"sa-{i}", automount=False) for i in range(5)]
        results = analyze_many(sas, bindings=[], roles=[])
        assert len(results) == 5

    def test_analyze_many_returns_saresult_instances(self):
        sas = [make_sa(name="sa-x", automount=False)]
        results = analyze_many(sas)
        assert isinstance(results[0], SAResult)

    def test_analyze_many_applies_shared_bindings(self):
        sas = [
            make_sa(name="sa-1", namespace="default", automount=False),
            make_sa(name="sa-2", namespace="default", automount=False),
        ]
        b1 = make_binding("rb1", "ClusterRoleBinding", "cluster-admin", "ClusterRole", "sa-1", "default")
        b2 = make_binding("rb2", "ClusterRoleBinding", "cluster-admin", "ClusterRole", "sa-2", "default")
        results = analyze_many(sas, bindings=[b1, b2], roles=[])
        assert any(f.check_id == "SA-001" for f in results[0].findings)
        assert any(f.check_id == "SA-001" for f in results[1].findings)

    def test_analyze_many_empty_list(self):
        results = analyze_many([], bindings=[], roles=[])
        assert results == []

    def test_sa_with_null_imagepullsecrets_field(self):
        sa = {"metadata": {"name": "x", "namespace": "y"}, "imagePullSecrets": None, "automountServiceAccountToken": False}
        result = analyze(sa, bindings=[], roles=[])
        assert all(f.check_id != "SA-006" for f in result.findings)

    def test_sa_result_fields(self):
        sa = make_sa(name="check-sa", namespace="check-ns", automount=False)
        result = analyze(sa, bindings=[], roles=[])
        assert result.sa_name == "check-sa"
        assert result.namespace == "check-ns"
        assert isinstance(result.findings, list)
        assert isinstance(result.risk_score, int)

    def test_all_check_ids_in_check_weights(self):
        for cid in ("SA-001", "SA-002", "SA-003", "SA-004", "SA-005", "SA-006", "SA-007", "SA-008"):
            assert cid in _CHECK_WEIGHTS

    def test_all_check_ids_in_check_severity(self):
        for cid in ("SA-001", "SA-002", "SA-003", "SA-004", "SA-005", "SA-006", "SA-007", "SA-008"):
            assert cid in _CHECK_SEVERITY

    def test_saresult_default_findings_is_empty_list(self):
        result = SAResult(sa_name="x", namespace="y", findings=[], risk_score=0)
        assert result.findings == []

    def test_safinding_fields_accessible(self):
        finding = SAFinding(
            check_id="SA-001",
            severity="CRITICAL",
            title="Test",
            detail="Detail",
            weight=45,
        )
        assert finding.check_id == "SA-001"
        assert finding.weight == 45

    def test_sabinding_fields_accessible(self):
        b = SABinding(
            binding_name="rb",
            binding_kind="ClusterRoleBinding",
            role_name="role",
            role_kind="ClusterRole",
            verbs=["get"],
            resources=["pods"],
        )
        assert b.binding_kind == "ClusterRoleBinding"
        assert "get" in b.verbs


# ===========================================================================
# Integration — combined checks on a single SA
# ===========================================================================

class TestIntegration:
    """Combined scenarios exercising multiple checks simultaneously."""

    def test_maximally_privileged_sa_fires_multiple_checks(self):
        """An SA with cluster-admin, wildcard role, and automount enabled fires many checks."""
        sa = make_sa(name="super-sa", namespace="default")
        wildcard_role = make_role("omega", "ClusterRole", [make_rule(["*"], ["*"])])
        b_admin = make_binding(
            "b-admin", "ClusterRoleBinding", "cluster-admin", "ClusterRole",
            "super-sa", "default"
        )
        b_omega = make_binding(
            "b-omega", "ClusterRoleBinding", "omega", "ClusterRole",
            "super-sa", "default"
        )
        result = analyze(sa, bindings=[b_admin, b_omega], roles=[wildcard_role])
        check_ids = {f.check_id for f in result.findings}
        assert "SA-001" in check_ids
        assert "SA-002" in check_ids
        assert "SA-003" in check_ids
        assert "SA-004" in check_ids

    def test_clean_dedicated_sa_no_findings(self):
        """A properly configured SA with automount=False and no bindings has zero findings."""
        sa = make_sa(name="clean-sa", namespace="app-ns", automount=False)
        result = analyze(sa, bindings=[], roles=[])
        assert result.findings == []
        assert result.risk_score == 0

    def test_default_sa_with_all_problems(self):
        """default SA in kube-system with all problems fires maximum checks."""
        sa = {
            "metadata": {"name": "default", "namespace": "kube-system"},
            "imagePullSecrets": [{"name": "reg"}],
            # automountServiceAccountToken absent -> SA-002 fires
        }
        crb_admin = make_binding(
            "crb-admin", "ClusterRoleBinding", "cluster-admin", "ClusterRole",
            "default", "kube-system"
        )
        secrets_role = make_role(
            "sec-reader", "ClusterRole",
            [make_rule(["get", "list"], ["secrets"])]
        )
        secrets_crb = make_binding(
            "crb-secrets", "ClusterRoleBinding", "sec-reader", "ClusterRole",
            "default", "kube-system"
        )
        custom_binding = make_binding(
            "my-custom-binding", "ClusterRoleBinding", "cluster-admin", "ClusterRole",
            "default", "kube-system"
        )
        result = analyze(
            sa,
            bindings=[crb_admin, secrets_crb, custom_binding],
            roles=[secrets_role]
        )
        check_ids = {f.check_id for f in result.findings}
        # SA-001: cluster-admin CRB
        assert "SA-001" in check_ids
        # SA-002: automount not set
        assert "SA-002" in check_ids
        # SA-004: secrets CRB
        assert "SA-004" in check_ids
        # SA-005: default SA with non-trivial binding
        assert "SA-005" in check_ids
        # SA-006: imagePullSecrets present
        assert "SA-006" in check_ids
        # SA-007: kube-system with non-system binding
        assert "SA-007" in check_ids
        # Score must be capped
        assert result.risk_score == 100

    def test_multiple_bindings_only_relevant_ones_counted(self):
        """Bindings for a different SA should not affect this SA's result."""
        sa = make_sa(name="target-sa", namespace="ns", automount=False)
        crb_other = make_binding(
            "crb-other", "ClusterRoleBinding", "cluster-admin", "ClusterRole",
            "other-sa", "ns"
        )
        result = analyze(sa, bindings=[crb_other], roles=[])
        assert all(f.check_id != "SA-001" for f in result.findings)

    def test_analyze_many_consistent_with_individual_analyze(self):
        """analyze_many should produce the same results as individual analyze calls."""
        sas = [
            make_sa(name="sa-A", namespace="nsX", automount=False),
            make_sa(name="sa-B", namespace="nsX"),
        ]
        bindings_list = [
            make_binding("b-A", "ClusterRoleBinding", "cluster-admin", "ClusterRole", "sa-A", "nsX"),
        ]
        many = analyze_many(sas, bindings=bindings_list, roles=[])
        individual = [analyze(sa, bindings=bindings_list, roles=[]) for sa in sas]
        for m, i in zip(many, individual):
            assert m.sa_name == i.sa_name
            assert m.risk_score == i.risk_score
            assert {f.check_id for f in m.findings} == {f.check_id for f in i.findings}
