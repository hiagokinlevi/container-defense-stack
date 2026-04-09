# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International License.
# https://creativecommons.org/licenses/by/4.0/
"""
Tests for kubernetes/rbac_gap_analyzer.py
==========================================
Covers all seven RBAC-GAP checks (001–007), combined scenarios, risk-score
capping, to_dict() serialisation, summary() format, by_severity() grouping,
analyze_many(), and edge cases.

Run with::

    python3 -m pytest tests/test_rbac_gap_analyzer.py --override-ini="addopts=" -q
"""
from __future__ import annotations

import pytest

from kubernetes.rbac_gap_analyzer import (
    PolicyRule,
    RBACBinding,
    RBACFinding,
    RBACGapAnalyzer,
    RBACGapResult,
    RBACRole,
    _CHECK_WEIGHTS,
)


# ===========================================================================
# Helper factories
# ===========================================================================

def _rule(
    api_groups: list = None,
    resources: list = None,
    verbs: list = None,
    resource_names: list = None,
) -> PolicyRule:
    """Build a PolicyRule with sensible defaults."""
    return PolicyRule(
        api_groups=api_groups or [""],
        resources=resources or ["pods"],
        verbs=verbs or ["get"],
        resource_names=resource_names,
    )


def _role(
    name: str = "test-role",
    namespace: str = "default",
    rules: list = None,
) -> RBACRole:
    """Build a namespaced Role."""
    return RBACRole(name=name, namespace=namespace, rules=rules or [_rule()])


def _cluster_role(
    name: str = "test-cr",
    rules: list = None,
) -> RBACRole:
    """Build a ClusterRole (namespace=None)."""
    return RBACRole(name=name, namespace=None, rules=rules or [_rule()])


def _binding(
    name: str = "test-rb",
    namespace: str = "default",
    role_ref_name: str = "test-role",
    role_ref_kind: str = "Role",
    subjects: list = None,
) -> RBACBinding:
    """Build a namespaced RoleBinding."""
    return RBACBinding(
        name=name,
        namespace=namespace,
        role_ref_name=role_ref_name,
        role_ref_kind=role_ref_kind,
        subjects=subjects or [{"kind": "ServiceAccount", "name": "my-sa", "namespace": "default"}],
    )


def _cluster_binding(
    name: str = "test-crb",
    role_ref_name: str = "test-cr",
    role_ref_kind: str = "ClusterRole",
    subjects: list = None,
) -> RBACBinding:
    """Build a ClusterRoleBinding (namespace=None)."""
    return RBACBinding(
        name=name,
        namespace=None,
        role_ref_name=role_ref_name,
        role_ref_kind=role_ref_kind,
        subjects=subjects or [{"kind": "User", "name": "alice"}],
    )


def check_ids(result: RBACGapResult) -> set:
    """Return the set of check IDs present in a result."""
    return {f.check_id for f in result.findings}


# ---------------------------------------------------------------------------
# Shared analyser instance
# ---------------------------------------------------------------------------

ANALYZER = RBACGapAnalyzer()


# ===========================================================================
# 1. Clean inputs — no findings, risk_score == 0
# ===========================================================================

class TestCleanInputs:
    def test_empty_lists_produce_no_findings(self):
        result = ANALYZER.analyze([], [])
        assert result.findings == []
        assert result.risk_score == 0

    def test_benign_role_no_findings(self):
        role = _role(rules=[_rule(resources=["pods"], verbs=["get"])])
        result = ANALYZER.analyze([role], [])
        assert result.findings == []
        assert result.risk_score == 0

    def test_benign_binding_no_findings(self):
        binding = _binding(role_ref_name="some-role", role_ref_kind="Role")
        result = ANALYZER.analyze([], [binding])
        assert result.findings == []
        assert result.risk_score == 0

    def test_benign_role_and_binding(self):
        role = _role(name="reader", rules=[_rule(resources=["pods"], verbs=["list"])])
        binding = _binding(role_ref_name="reader")
        result = ANALYZER.analyze([role], [binding])
        assert result.findings == []
        assert result.risk_score == 0

    def test_cluster_role_no_sensitive_rules(self):
        cr = _cluster_role(name="safe-cr", rules=[_rule(resources=["configmaps"], verbs=["get"])])
        result = ANALYZER.analyze([cr], [])
        assert result.findings == []

    def test_resource_names_restricted_secrets_no_finding(self):
        # resource_names does NOT prevent a finding — check 004 triggers on
        # resource/verb match regardless.  This test just confirms the
        # restriction is stored and readable.
        role = _role(
            name="narrow-secret",
            rules=[_rule(resources=["secrets"], verbs=["get"], resource_names=["my-secret"])],
        )
        result = ANALYZER.analyze([role], [])
        # 004 still fires: resources contain "secrets" with get verb
        ids = check_ids(result)
        assert "RBAC-GAP-004" in ids


# ===========================================================================
# 2. RBAC-GAP-001 — cluster-admin binding
# ===========================================================================

class TestCheck001ClusterAdmin:
    def test_cluster_admin_crb_triggers(self):
        crb = _cluster_binding(name="god-mode", role_ref_name="cluster-admin", role_ref_kind="ClusterRole")
        result = ANALYZER.analyze([], [crb])
        assert "RBAC-GAP-001" in check_ids(result)

    def test_cluster_admin_rb_triggers(self):
        # Even a namespaced RoleBinding referencing cluster-admin should fire
        rb = _binding(name="ns-god", role_ref_name="cluster-admin", role_ref_kind="ClusterRole")
        result = ANALYZER.analyze([], [rb])
        assert "RBAC-GAP-001" in check_ids(result)

    def test_cluster_admin_wrong_kind_no_trigger(self):
        # role_ref_kind = "Role" (not ClusterRole) — should NOT fire 001
        rb = _binding(name="safe-rb", role_ref_name="cluster-admin", role_ref_kind="Role")
        result = ANALYZER.analyze([], [rb])
        assert "RBAC-GAP-001" not in check_ids(result)

    def test_custom_clusterrole_no_trigger(self):
        crb = _cluster_binding(name="custom-crb", role_ref_name="my-custom-role", role_ref_kind="ClusterRole")
        result = ANALYZER.analyze([], [crb])
        assert "RBAC-GAP-001" not in check_ids(result)

    def test_001_finding_severity_is_critical(self):
        crb = _cluster_binding(role_ref_name="cluster-admin", role_ref_kind="ClusterRole")
        result = ANALYZER.analyze([], [crb])
        f = next(x for x in result.findings if x.check_id == "RBAC-GAP-001")
        assert f.severity == "CRITICAL"

    def test_001_finding_resource_kind_cluster_role_binding(self):
        crb = _cluster_binding(role_ref_name="cluster-admin", role_ref_kind="ClusterRole")
        result = ANALYZER.analyze([], [crb])
        f = next(x for x in result.findings if x.check_id == "RBAC-GAP-001")
        assert f.resource_kind == "ClusterRoleBinding"

    def test_001_weight_reflected_in_score(self):
        crb = _cluster_binding(role_ref_name="cluster-admin", role_ref_kind="ClusterRole")
        result = ANALYZER.analyze([], [crb])
        assert result.risk_score == _CHECK_WEIGHTS["RBAC-GAP-001"]

    def test_multiple_cluster_admin_bindings_score_counted_once(self):
        crb1 = _cluster_binding(name="b1", role_ref_name="cluster-admin", role_ref_kind="ClusterRole")
        crb2 = _cluster_binding(name="b2", role_ref_name="cluster-admin", role_ref_kind="ClusterRole")
        result = ANALYZER.analyze([], [crb1, crb2])
        # Two findings but check ID counted once for score
        assert result.risk_score == _CHECK_WEIGHTS["RBAC-GAP-001"]
        assert len([f for f in result.findings if f.check_id == "RBAC-GAP-001"]) == 2


# ===========================================================================
# 3. RBAC-GAP-002 — wildcard verbs
# ===========================================================================

class TestCheck002WildcardVerbs:
    def test_wildcard_verbs_triggers(self):
        role = _role(name="all-verbs", rules=[_rule(verbs=["*"])])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-002" in check_ids(result)

    def test_wildcard_verbs_severity_high(self):
        role = _role(name="all-verbs", rules=[_rule(verbs=["*"])])
        result = ANALYZER.analyze([role], [])
        f = next(x for x in result.findings if x.check_id == "RBAC-GAP-002")
        assert f.severity == "HIGH"

    def test_explicit_verbs_no_trigger(self):
        role = _role(name="safe", rules=[_rule(verbs=["get", "list", "watch"])])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-002" not in check_ids(result)

    def test_wildcard_in_one_rule_of_many(self):
        role = _role(name="mixed", rules=[
            _rule(verbs=["get"]),
            _rule(verbs=["*"], resources=["configmaps"]),
        ])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-002" in check_ids(result)

    def test_same_role_name_deduplicated(self):
        # Two RBACRole objects with the same name — only one finding for 002
        r1 = _role(name="dup-role", rules=[_rule(verbs=["*"])])
        r2 = _role(name="dup-role", rules=[_rule(verbs=["*"])])
        result = ANALYZER.analyze([r1, r2], [])
        c002 = [f for f in result.findings if f.check_id == "RBAC-GAP-002"]
        assert len(c002) == 1

    def test_002_weight_in_score(self):
        role = _role(name="star-verbs", rules=[_rule(verbs=["*"])])
        result = ANALYZER.analyze([role], [])
        assert result.risk_score >= _CHECK_WEIGHTS["RBAC-GAP-002"]


# ===========================================================================
# 4. RBAC-GAP-003 — wildcard resources
# ===========================================================================

class TestCheck003WildcardResources:
    def test_wildcard_resources_triggers(self):
        role = _role(name="all-res", rules=[_rule(resources=["*"])])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-003" in check_ids(result)

    def test_wildcard_resources_severity_high(self):
        role = _role(name="all-res", rules=[_rule(resources=["*"])])
        result = ANALYZER.analyze([role], [])
        f = next(x for x in result.findings if x.check_id == "RBAC-GAP-003")
        assert f.severity == "HIGH"

    def test_explicit_resources_no_trigger(self):
        role = _role(name="safe-res", rules=[_rule(resources=["pods", "services"])])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-003" not in check_ids(result)

    def test_wildcard_resource_in_second_rule(self):
        role = _role(name="r", rules=[
            _rule(resources=["pods"]),
            _rule(resources=["*"]),
        ])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-003" in check_ids(result)

    def test_same_role_name_deduplicated_003(self):
        r1 = _role(name="dup", rules=[_rule(resources=["*"])])
        r2 = _role(name="dup", rules=[_rule(resources=["*"])])
        result = ANALYZER.analyze([r1, r2], [])
        c003 = [f for f in result.findings if f.check_id == "RBAC-GAP-003"]
        assert len(c003) == 1

    def test_003_weight_in_score(self):
        role = _role(name="star-res", rules=[_rule(resources=["*"])])
        result = ANALYZER.analyze([role], [])
        assert result.risk_score >= _CHECK_WEIGHTS["RBAC-GAP-003"]


# ===========================================================================
# 5. RBAC-GAP-004 — secrets read access
# ===========================================================================

class TestCheck004SecretsRead:
    def test_secrets_get_triggers(self):
        role = _role(name="sr", rules=[_rule(resources=["secrets"], verbs=["get"])])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-004" in check_ids(result)

    def test_secrets_list_triggers(self):
        role = _role(name="sl", rules=[_rule(resources=["secrets"], verbs=["list"])])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-004" in check_ids(result)

    def test_secrets_watch_triggers(self):
        role = _role(name="sw", rules=[_rule(resources=["secrets"], verbs=["watch"])])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-004" in check_ids(result)

    def test_secrets_wildcard_verb_triggers(self):
        role = _role(name="sstar", rules=[_rule(resources=["secrets"], verbs=["*"])])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-004" in check_ids(result)

    def test_wildcard_resource_with_get_triggers_004(self):
        role = _role(name="ar", rules=[_rule(resources=["*"], verbs=["get"])])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-004" in check_ids(result)

    def test_secrets_delete_only_no_trigger(self):
        # "delete" is not a read verb; should not trigger 004
        role = _role(name="sd", rules=[_rule(resources=["secrets"], verbs=["delete"])])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-004" not in check_ids(result)

    def test_pods_get_no_trigger(self):
        role = _role(name="pg", rules=[_rule(resources=["pods"], verbs=["get"])])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-004" not in check_ids(result)

    def test_004_severity_high(self):
        role = _role(name="sr", rules=[_rule(resources=["secrets"], verbs=["get"])])
        result = ANALYZER.analyze([role], [])
        f = next(x for x in result.findings if x.check_id == "RBAC-GAP-004")
        assert f.severity == "HIGH"

    def test_secrets_deduplicated_per_role(self):
        r1 = _role(name="sr-dup", rules=[_rule(resources=["secrets"], verbs=["get"])])
        r2 = _role(name="sr-dup", rules=[_rule(resources=["secrets"], verbs=["list"])])
        result = ANALYZER.analyze([r1, r2], [])
        c004 = [f for f in result.findings if f.check_id == "RBAC-GAP-004"]
        assert len(c004) == 1


# ===========================================================================
# 6. RBAC-GAP-005 — default service account binding
# ===========================================================================

class TestCheck005DefaultSA:
    def test_default_sa_triggers(self):
        rb = _binding(
            name="default-rb",
            subjects=[{"kind": "ServiceAccount", "name": "default", "namespace": "default"}],
        )
        result = ANALYZER.analyze([], [rb])
        assert "RBAC-GAP-005" in check_ids(result)

    def test_named_sa_no_trigger(self):
        rb = _binding(
            name="named-rb",
            subjects=[{"kind": "ServiceAccount", "name": "my-app-sa", "namespace": "default"}],
        )
        result = ANALYZER.analyze([], [rb])
        assert "RBAC-GAP-005" not in check_ids(result)

    def test_default_user_not_default_sa(self):
        # kind=User name=default should NOT trigger 005
        rb = _binding(
            name="user-default",
            subjects=[{"kind": "User", "name": "default"}],
        )
        result = ANALYZER.analyze([], [rb])
        assert "RBAC-GAP-005" not in check_ids(result)

    def test_005_severity_medium(self):
        rb = _binding(subjects=[{"kind": "ServiceAccount", "name": "default"}])
        result = ANALYZER.analyze([], [rb])
        f = next(x for x in result.findings if x.check_id == "RBAC-GAP-005")
        assert f.severity == "MEDIUM"

    def test_multiple_subjects_default_among_them(self):
        rb = _binding(subjects=[
            {"kind": "ServiceAccount", "name": "app-sa"},
            {"kind": "ServiceAccount", "name": "default"},
        ])
        result = ANALYZER.analyze([], [rb])
        assert "RBAC-GAP-005" in check_ids(result)

    def test_005_weight_in_score(self):
        rb = _binding(subjects=[{"kind": "ServiceAccount", "name": "default"}])
        result = ANALYZER.analyze([], [rb])
        assert result.risk_score >= _CHECK_WEIGHTS["RBAC-GAP-005"]

    def test_cluster_binding_default_sa_triggers(self):
        crb = _cluster_binding(
            name="crb-default",
            subjects=[{"kind": "ServiceAccount", "name": "default", "namespace": "kube-system"}],
        )
        result = ANALYZER.analyze([], [crb])
        assert "RBAC-GAP-005" in check_ids(result)


# ===========================================================================
# 7. RBAC-GAP-006 — privilege escalation verbs
# ===========================================================================

class TestCheck006EscalationVerbs:
    def test_bind_verb_triggers(self):
        role = _role(name="binder", rules=[_rule(verbs=["bind"])])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-006" in check_ids(result)

    def test_escalate_verb_triggers(self):
        role = _role(name="escalator", rules=[_rule(verbs=["escalate"])])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-006" in check_ids(result)

    def test_impersonate_verb_triggers(self):
        role = _role(name="impersonator", rules=[_rule(verbs=["impersonate"])])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-006" in check_ids(result)

    def test_006_severity_critical(self):
        role = _role(name="esc", rules=[_rule(verbs=["bind"])])
        result = ANALYZER.analyze([role], [])
        f = next(x for x in result.findings if x.check_id == "RBAC-GAP-006")
        assert f.severity == "CRITICAL"

    def test_safe_verbs_no_trigger(self):
        role = _role(name="safe", rules=[_rule(verbs=["create", "delete", "update"])])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-006" not in check_ids(result)

    def test_006_deduplicates_by_role_name(self):
        r1 = _role(name="dup-esc", rules=[_rule(verbs=["bind"])])
        r2 = _role(name="dup-esc", rules=[_rule(verbs=["escalate"])])
        result = ANALYZER.analyze([r1, r2], [])
        c006 = [f for f in result.findings if f.check_id == "RBAC-GAP-006"]
        assert len(c006) == 1

    def test_006_weight_in_score(self):
        role = _role(name="esc2", rules=[_rule(verbs=["impersonate"])])
        result = ANALYZER.analyze([role], [])
        assert result.risk_score >= _CHECK_WEIGHTS["RBAC-GAP-006"]

    def test_multiple_escalation_verbs_in_one_rule(self):
        role = _role(name="super-esc", rules=[_rule(verbs=["bind", "escalate", "impersonate"])])
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-006" in check_ids(result)


# ===========================================================================
# 8. RBAC-GAP-007 — system:masters group binding
# ===========================================================================

class TestCheck007SystemMasters:
    def test_system_masters_triggers(self):
        crb = _cluster_binding(subjects=[{"kind": "Group", "name": "system:masters"}])
        result = ANALYZER.analyze([], [crb])
        assert "RBAC-GAP-007" in check_ids(result)

    def test_007_severity_critical(self):
        crb = _cluster_binding(subjects=[{"kind": "Group", "name": "system:masters"}])
        result = ANALYZER.analyze([], [crb])
        f = next(x for x in result.findings if x.check_id == "RBAC-GAP-007")
        assert f.severity == "CRITICAL"

    def test_other_group_no_trigger(self):
        crb = _cluster_binding(subjects=[{"kind": "Group", "name": "system:authenticated"}])
        result = ANALYZER.analyze([], [crb])
        assert "RBAC-GAP-007" not in check_ids(result)

    def test_system_masters_user_no_trigger(self):
        # kind=User, not Group — should NOT trigger 007
        crb = _cluster_binding(subjects=[{"kind": "User", "name": "system:masters"}])
        result = ANALYZER.analyze([], [crb])
        assert "RBAC-GAP-007" not in check_ids(result)

    def test_007_weight_in_score(self):
        crb = _cluster_binding(subjects=[{"kind": "Group", "name": "system:masters"}])
        result = ANALYZER.analyze([], [crb])
        assert result.risk_score == _CHECK_WEIGHTS["RBAC-GAP-007"]

    def test_namespaced_binding_system_masters_triggers(self):
        rb = _binding(subjects=[{"kind": "Group", "name": "system:masters"}])
        result = ANALYZER.analyze([], [rb])
        assert "RBAC-GAP-007" in check_ids(result)

    def test_007_and_001_together(self):
        # binding both to cluster-admin AND containing system:masters
        crb = _cluster_binding(
            name="ultimate-bad",
            role_ref_name="cluster-admin",
            role_ref_kind="ClusterRole",
            subjects=[{"kind": "Group", "name": "system:masters"}],
        )
        result = ANALYZER.analyze([], [crb])
        ids = check_ids(result)
        assert "RBAC-GAP-001" in ids
        assert "RBAC-GAP-007" in ids


# ===========================================================================
# 9. Multiple checks firing simultaneously
# ===========================================================================

class TestMultipleChecks:
    def test_all_checks_fire_simultaneously(self):
        """Construct a scenario that triggers all 7 checks at once."""
        # Roles — triggers 002, 003, 004, 006
        evil_role = RBACRole(
            name="evil-role",
            namespace="default",
            rules=[
                PolicyRule(api_groups=["*"], resources=["*"], verbs=["*"]),           # 002, 003, 004
                PolicyRule(api_groups=[""], resources=["clusterrolebindings"], verbs=["bind", "escalate"]),  # 006
            ],
        )
        # Binding — triggers 001, 005, 007
        evil_binding = RBACBinding(
            name="evil-binding",
            namespace=None,
            role_ref_name="cluster-admin",
            role_ref_kind="ClusterRole",
            subjects=[
                {"kind": "ServiceAccount", "name": "default", "namespace": "default"},  # 005
                {"kind": "Group", "name": "system:masters"},                             # 007
            ],
        )
        result = ANALYZER.analyze([evil_role], [evil_binding])
        ids = check_ids(result)
        for expected in [
            "RBAC-GAP-001", "RBAC-GAP-002", "RBAC-GAP-003",
            "RBAC-GAP-004", "RBAC-GAP-005", "RBAC-GAP-006", "RBAC-GAP-007",
        ]:
            assert expected in ids, f"Expected {expected} to fire"

    def test_two_role_checks_combined_score(self):
        role = _role(name="combo", rules=[_rule(verbs=["*"], resources=["*"])])
        result = ANALYZER.analyze([role], [])
        # 002(25) + 003(25) + 004(20) = 70 — also 004 fires (wildcard resources + wildcard verbs)
        assert result.risk_score == (
            _CHECK_WEIGHTS["RBAC-GAP-002"]
            + _CHECK_WEIGHTS["RBAC-GAP-003"]
            + _CHECK_WEIGHTS["RBAC-GAP-004"]
        )

    def test_003_and_004_together(self):
        # Wildcard resources + get verb → both 003 and 004
        role = _role(name="wr", rules=[_rule(resources=["*"], verbs=["get"])])
        result = ANALYZER.analyze([role], [])
        ids = check_ids(result)
        assert "RBAC-GAP-003" in ids
        assert "RBAC-GAP-004" in ids


# ===========================================================================
# 10. risk_score capping at 100
# ===========================================================================

class TestRiskScoreCap:
    def test_risk_score_capped_at_100(self):
        """
        001(40) + 006(35) + 007(40) = 115 → capped at 100.
        """
        crb = _cluster_binding(
            name="cap-test",
            role_ref_name="cluster-admin",
            role_ref_kind="ClusterRole",
            subjects=[{"kind": "Group", "name": "system:masters"}],
        )
        role = _role(name="esc-role", rules=[_rule(verbs=["bind"])])
        result = ANALYZER.analyze([role], [crb])
        assert result.risk_score == 100

    def test_risk_score_never_exceeds_100(self):
        """Exhaustive scenario — all checks fire; score must be <= 100."""
        evil_role = RBACRole(
            name="all-evil",
            namespace=None,
            rules=[
                PolicyRule(api_groups=["*"], resources=["*"], verbs=["*"]),
                PolicyRule(api_groups=[""], resources=["nodes"], verbs=["bind", "escalate", "impersonate"]),
            ],
        )
        evil_crb = _cluster_binding(
            name="all-evil-crb",
            role_ref_name="cluster-admin",
            role_ref_kind="ClusterRole",
            subjects=[
                {"kind": "ServiceAccount", "name": "default"},
                {"kind": "Group", "name": "system:masters"},
            ],
        )
        result = ANALYZER.analyze([evil_role], [evil_crb])
        assert result.risk_score <= 100
        assert result.risk_score == 100

    def test_zero_findings_zero_score(self):
        result = ANALYZER.analyze([], [])
        assert result.risk_score == 0

    def test_single_check_weight_exact(self):
        role = _role(name="sr", rules=[_rule(resources=["secrets"], verbs=["get"])])
        result = ANALYZER.analyze([role], [])
        assert result.risk_score == _CHECK_WEIGHTS["RBAC-GAP-004"]


# ===========================================================================
# 11. by_severity() grouping
# ===========================================================================

class TestBySeverity:
    def test_by_severity_empty_result(self):
        result = ANALYZER.analyze([], [])
        assert result.by_severity() == {}

    def test_by_severity_keys_match_findings(self):
        role = _role(name="sr", rules=[_rule(resources=["secrets"], verbs=["get"])])
        result = ANALYZER.analyze([role], [])
        sev = result.by_severity()
        assert "HIGH" in sev
        for f in sev["HIGH"]:
            assert f.severity == "HIGH"

    def test_by_severity_critical_present(self):
        crb = _cluster_binding(role_ref_name="cluster-admin", role_ref_kind="ClusterRole")
        result = ANALYZER.analyze([], [crb])
        sev = result.by_severity()
        assert "CRITICAL" in sev

    def test_by_severity_medium_present(self):
        rb = _binding(subjects=[{"kind": "ServiceAccount", "name": "default"}])
        result = ANALYZER.analyze([], [rb])
        sev = result.by_severity()
        assert "MEDIUM" in sev

    def test_by_severity_all_findings_accounted_for(self):
        role = _role(name="esc", rules=[_rule(verbs=["bind"])])
        rb = _binding(subjects=[{"kind": "ServiceAccount", "name": "default"}])
        result = ANALYZER.analyze([role], [rb])
        sev = result.by_severity()
        total = sum(len(v) for v in sev.values())
        assert total == len(result.findings)

    def test_by_severity_returns_lists(self):
        crb = _cluster_binding(role_ref_name="cluster-admin", role_ref_kind="ClusterRole")
        result = ANALYZER.analyze([], [crb])
        sev = result.by_severity()
        for v in sev.values():
            assert isinstance(v, list)


# ===========================================================================
# 12. summary() format
# ===========================================================================

class TestSummary:
    def test_summary_contains_risk_score(self):
        result = ANALYZER.analyze([], [])
        assert "0/100" in result.summary()

    def test_summary_contains_finding_count(self):
        result = ANALYZER.analyze([], [])
        assert "0 finding(s)" in result.summary()

    def test_summary_with_findings(self):
        crb = _cluster_binding(role_ref_name="cluster-admin", role_ref_kind="ClusterRole")
        result = ANALYZER.analyze([], [crb])
        s = result.summary()
        assert "finding(s)" in s
        assert "Risk Score:" in s

    def test_summary_header_text(self):
        result = ANALYZER.analyze([], [])
        assert "RBAC Gap Analysis" in result.summary()

    def test_summary_shows_correct_score(self):
        rb = _binding(subjects=[{"kind": "ServiceAccount", "name": "default"}])
        result = ANALYZER.analyze([], [rb])
        expected_score = str(_CHECK_WEIGHTS["RBAC-GAP-005"])
        assert expected_score in result.summary()

    def test_summary_is_string(self):
        result = ANALYZER.analyze([], [])
        assert isinstance(result.summary(), str)


# ===========================================================================
# 13. analyze_many()
# ===========================================================================

class TestAnalyzeMany:
    def test_returns_list(self):
        results = ANALYZER.analyze_many([])
        assert isinstance(results, list)
        assert results == []

    def test_returns_correct_length(self):
        results = ANALYZER.analyze_many([
            ([], []),
            ([], []),
            ([], []),
        ])
        assert len(results) == 3

    def test_each_element_is_rbac_gap_result(self):
        results = ANALYZER.analyze_many([([], [])])
        assert all(isinstance(r, RBACGapResult) for r in results)

    def test_results_are_independent(self):
        role_a = _role(name="sr", rules=[_rule(resources=["secrets"], verbs=["get"])])
        results = ANALYZER.analyze_many([
            ([role_a], []),
            ([], []),
        ])
        assert "RBAC-GAP-004" in check_ids(results[0])
        assert results[1].findings == []

    def test_single_tuple(self):
        crb = _cluster_binding(role_ref_name="cluster-admin", role_ref_kind="ClusterRole")
        results = ANALYZER.analyze_many([([], [crb])])
        assert len(results) == 1
        assert "RBAC-GAP-001" in check_ids(results[0])

    def test_many_independent_scores(self):
        crb = _cluster_binding(role_ref_name="cluster-admin", role_ref_kind="ClusterRole")
        rb = _binding(subjects=[{"kind": "ServiceAccount", "name": "default"}])
        results = ANALYZER.analyze_many([
            ([], [crb]),
            ([], [rb]),
        ])
        assert results[0].risk_score == _CHECK_WEIGHTS["RBAC-GAP-001"]
        assert results[1].risk_score == _CHECK_WEIGHTS["RBAC-GAP-005"]


# ===========================================================================
# 14. to_dict() for all dataclasses
# ===========================================================================

class TestToDict:
    def test_policy_rule_to_dict_basic(self):
        rule = _rule(api_groups=["apps"], resources=["deployments"], verbs=["get"])
        d = rule.to_dict()
        assert d["api_groups"] == ["apps"]
        assert d["resources"] == ["deployments"]
        assert d["verbs"] == ["get"]
        assert "resource_names" not in d  # omitted when None

    def test_policy_rule_to_dict_with_resource_names(self):
        rule = _rule(resource_names=["my-secret"])
        d = rule.to_dict()
        assert d["resource_names"] == ["my-secret"]

    def test_rbac_role_to_dict(self):
        role = _role(name="r1", namespace="ns1")
        d = role.to_dict()
        assert d["name"] == "r1"
        assert d["namespace"] == "ns1"
        assert d["is_cluster_role"] is False
        assert isinstance(d["rules"], list)

    def test_rbac_cluster_role_to_dict(self):
        cr = _cluster_role(name="cr1")
        d = cr.to_dict()
        assert d["namespace"] is None
        assert d["is_cluster_role"] is True

    def test_rbac_binding_to_dict(self):
        rb = _binding(name="rb1", namespace="ns1", role_ref_name="my-role", role_ref_kind="Role")
        d = rb.to_dict()
        assert d["name"] == "rb1"
        assert d["namespace"] == "ns1"
        assert d["role_ref_name"] == "my-role"
        assert d["role_ref_kind"] == "Role"
        assert isinstance(d["subjects"], list)

    def test_rbac_cluster_binding_to_dict(self):
        crb = _cluster_binding(name="crb1")
        d = crb.to_dict()
        assert d["namespace"] is None
        assert d["name"] == "crb1"

    def test_rbac_finding_to_dict(self):
        finding = RBACFinding(
            check_id="RBAC-GAP-001",
            severity="CRITICAL",
            resource_name="my-binding",
            resource_kind="ClusterRoleBinding",
            namespace=None,
            message="Test message",
            recommendation="Fix it",
        )
        d = finding.to_dict()
        assert d["check_id"] == "RBAC-GAP-001"
        assert d["severity"] == "CRITICAL"
        assert d["namespace"] is None
        assert d["recommendation"] == "Fix it"

    def test_rbac_gap_result_to_dict(self):
        result = ANALYZER.analyze([], [])
        d = result.to_dict()
        assert "risk_score" in d
        assert "findings" in d
        assert "summary" in d
        assert isinstance(d["findings"], list)

    def test_rbac_gap_result_to_dict_findings_serialised(self):
        crb = _cluster_binding(role_ref_name="cluster-admin", role_ref_kind="ClusterRole")
        result = ANALYZER.analyze([], [crb])
        d = result.to_dict()
        assert len(d["findings"]) >= 1
        assert isinstance(d["findings"][0], dict)
        assert "check_id" in d["findings"][0]

    def test_all_finding_dict_keys_present(self):
        crb = _cluster_binding(role_ref_name="cluster-admin", role_ref_kind="ClusterRole")
        result = ANALYZER.analyze([], [crb])
        expected_keys = {
            "check_id", "severity", "resource_name",
            "resource_kind", "namespace", "message", "recommendation",
        }
        for f in result.findings:
            assert expected_keys == set(f.to_dict().keys())


# ===========================================================================
# 15. Edge cases
# ===========================================================================

class TestEdgeCases:
    def test_role_with_empty_rules_list(self):
        role = RBACRole(name="empty-rules", namespace="default", rules=[])
        result = ANALYZER.analyze([role], [])
        assert result.findings == []
        assert result.risk_score == 0

    def test_binding_to_nonexistent_role_no_crash(self):
        # Binding refs a role that is not in the roles list — no crash, no check fires
        rb = _binding(name="orphan-rb", role_ref_name="ghost-role", role_ref_kind="Role")
        result = ANALYZER.analyze([], [rb])
        assert result.findings == []
        assert result.risk_score == 0

    def test_binding_empty_subjects_no_crash(self):
        rb = RBACBinding(
            name="no-subjects",
            namespace="default",
            role_ref_name="my-role",
            role_ref_kind="Role",
            subjects=[],
        )
        result = ANALYZER.analyze([], [rb])
        assert result.findings == []

    def test_resource_names_set_still_checked(self):
        # resource_names restricts scope at runtime but does not exempt from analysis
        role = _role(
            name="narrow",
            rules=[_rule(resources=["secrets"], verbs=["get"], resource_names=["token-xyz"])],
        )
        result = ANALYZER.analyze([role], [])
        assert "RBAC-GAP-004" in check_ids(result)

    def test_policy_rule_resource_names_none_by_default(self):
        rule = _rule()
        assert rule.resource_names is None

    def test_is_cluster_role_derived_from_namespace(self):
        cr = _cluster_role()
        assert cr.is_cluster_role is True
        r = _role()
        assert r.is_cluster_role is False

    def test_binding_kind_property(self):
        rb = _binding()
        assert rb.kind == "RoleBinding"
        crb = _cluster_binding()
        assert crb.kind == "ClusterRoleBinding"

    def test_role_kind_property(self):
        r = _role()
        assert r.kind == "Role"
        cr = _cluster_role()
        assert cr.kind == "ClusterRole"

    def test_multiple_roles_multiple_bindings(self):
        roles = [
            _role(name=f"role-{i}", rules=[_rule(resources=["pods"], verbs=["get"])])
            for i in range(10)
        ]
        bindings = [
            _binding(name=f"binding-{i}", role_ref_name=f"role-{i}")
            for i in range(10)
        ]
        result = ANALYZER.analyze(roles, bindings)
        assert result.findings == []
        assert result.risk_score == 0

    def test_cluster_role_finding_namespace_is_none(self):
        cr = _cluster_role(name="star-cr", rules=[_rule(verbs=["*"])])
        result = ANALYZER.analyze([cr], [])
        f = next(x for x in result.findings if x.check_id == "RBAC-GAP-002")
        assert f.namespace is None

    def test_check_weights_dict_has_all_seven_ids(self):
        expected = {f"RBAC-GAP-{i:03d}" for i in range(1, 8)}
        assert expected == set(_CHECK_WEIGHTS.keys())

    def test_check_weights_values_are_positive_ints(self):
        for k, v in _CHECK_WEIGHTS.items():
            assert isinstance(v, int), f"{k} weight is not int"
            assert v > 0, f"{k} weight is not positive"
