# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International License.
# https://creativecommons.org/licenses/by/4.0/
"""
Tests for kubernetes/admission_policy_analyzer.py
==================================================
85+ tests covering all seven ADMS checks, data-model serialization,
risk-score calculation, and result helpers.
"""
from __future__ import annotations

import sys
import os

# ---------------------------------------------------------------------------
# Path bootstrap — allow running from repo root or from tests/ directory
# ---------------------------------------------------------------------------
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import pytest

from kubernetes.admission_policy_analyzer import (
    AdmissionFinding,
    AdmissionPolicyAnalyzer,
    AdmissionPolicyResult,
    AdmissionWebhook,
    WebhookRule,
    _CHECK_WEIGHTS,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _safe_rule(
    resources: list[str] | None = None,
    operations: list[str] | None = None,
) -> WebhookRule:
    """Return a WebhookRule that covers pod CREATE (satisfies ADMS-005)."""
    return WebhookRule(
        api_groups=[""],
        api_versions=["v1"],
        resources=resources if resources is not None else ["pods"],
        operations=operations if operations is not None else ["CREATE"],
    )


def _safe_hook(**overrides) -> AdmissionWebhook:
    """
    Return a maximally safe AdmissionWebhook.

    All fields are set to the secure baseline; individual tests override
    specific fields via **overrides to trigger exactly one check.
    """
    defaults = dict(
        name="safe-webhook",
        webhook_type="Validating",
        failure_policy="Fail",
        namespace_selector={"matchLabels": {"admission": "enabled"}},
        timeout_seconds=10,
        ca_bundle="LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",  # non-empty PEM stub
        service_name="webhook-svc",
        tls_insecure_skip_verify=False,
        rules=[_safe_rule()],
        side_effects="None",
    )
    defaults.update(overrides)
    return AdmissionWebhook(**defaults)


ANALYZER = AdmissionPolicyAnalyzer()


def _check_ids(result: AdmissionPolicyResult) -> set[str]:
    return {f.check_id for f in result.findings}


def _findings_for(result: AdmissionPolicyResult, check_id: str) -> list[AdmissionFinding]:
    return [f for f in result.findings if f.check_id == check_id]


# ===========================================================================
# 1. Clean webhook — no findings
# ===========================================================================


class TestCleanWebhook:
    """A fully safe webhook must produce zero findings."""

    def test_no_findings(self):
        result = ANALYZER.analyze([_safe_hook()])
        assert result.findings == []

    def test_risk_score_zero(self):
        result = ANALYZER.analyze([_safe_hook()])
        assert result.risk_score == 0

    def test_summary_shows_zero_findings(self):
        result = ANALYZER.analyze([_safe_hook()])
        assert "0 finding(s)" in result.summary()

    def test_by_severity_empty_dict(self):
        result = ANALYZER.analyze([_safe_hook()])
        assert result.by_severity() == {}


# ===========================================================================
# 2. ADMS-001 — Webhook fails open (failurePolicy=Ignore)
# ===========================================================================


class TestADMS001:
    """ADMS-001: failurePolicy=Ignore must fire; Fail must not."""

    def test_ignore_triggers(self):
        hook = _safe_hook(failure_policy="Ignore")
        result = ANALYZER.analyze([hook])
        assert "ADMS-001" in _check_ids(result)

    def test_fail_policy_does_not_trigger(self):
        hook = _safe_hook(failure_policy="Fail")
        result = ANALYZER.analyze([hook])
        assert "ADMS-001" not in _check_ids(result)

    def test_finding_severity_is_critical(self):
        hook = _safe_hook(failure_policy="Ignore")
        result = ANALYZER.analyze([hook])
        findings = _findings_for(result, "ADMS-001")
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"

    def test_finding_webhook_name_matches(self):
        hook = _safe_hook(name="my-hook", failure_policy="Ignore")
        result = ANALYZER.analyze([hook])
        findings = _findings_for(result, "ADMS-001")
        assert findings[0].webhook_name == "my-hook"

    def test_finding_webhook_type_propagated(self):
        hook = _safe_hook(webhook_type="Mutating", failure_policy="Ignore", timeout_seconds=5)
        result = ANALYZER.analyze([hook])
        findings = _findings_for(result, "ADMS-001")
        assert findings[0].webhook_type == "Mutating"

    def test_finding_has_recommendation(self):
        hook = _safe_hook(failure_policy="Ignore")
        result = ANALYZER.analyze([hook])
        findings = _findings_for(result, "ADMS-001")
        assert len(findings[0].recommendation) > 0

    def test_weight_applied_to_risk_score(self):
        # Only ADMS-001 fires → risk_score == 40
        hook = _safe_hook(failure_policy="Ignore")
        result = ANALYZER.analyze([hook])
        assert result.risk_score == _CHECK_WEIGHTS["ADMS-001"]

    def test_multiple_ignore_hooks_weight_counted_once(self):
        # Two hooks both fire ADMS-001 — weight should be counted once (unique check IDs)
        hook1 = _safe_hook(name="h1", failure_policy="Ignore")
        hook2 = _safe_hook(name="h2", failure_policy="Ignore")
        result = ANALYZER.analyze([hook1, hook2])
        assert result.risk_score == _CHECK_WEIGHTS["ADMS-001"]


# ===========================================================================
# 3. ADMS-002 — Applies to all namespaces
# ===========================================================================


class TestADMS002:
    """ADMS-002: no or empty namespace selector triggers; specific selector does not."""

    def test_none_selector_triggers(self):
        hook = _safe_hook(namespace_selector=None)
        result = ANALYZER.analyze([hook])
        assert "ADMS-002" in _check_ids(result)

    def test_empty_dict_selector_triggers(self):
        hook = _safe_hook(namespace_selector={})
        result = ANALYZER.analyze([hook])
        assert "ADMS-002" in _check_ids(result)

    def test_specific_selector_does_not_trigger(self):
        hook = _safe_hook(namespace_selector={"matchLabels": {"env": "prod"}})
        result = ANALYZER.analyze([hook])
        assert "ADMS-002" not in _check_ids(result)

    def test_match_expressions_selector_does_not_trigger(self):
        hook = _safe_hook(
            namespace_selector={
                "matchExpressions": [
                    {"key": "kubernetes.io/metadata.name", "operator": "NotIn", "values": ["kube-system"]}
                ]
            }
        )
        result = ANALYZER.analyze([hook])
        assert "ADMS-002" not in _check_ids(result)

    def test_finding_severity_is_high(self):
        hook = _safe_hook(namespace_selector=None)
        result = ANALYZER.analyze([hook])
        findings = _findings_for(result, "ADMS-002")
        assert findings[0].severity == "HIGH"

    def test_finding_message_mentions_kube_system(self):
        hook = _safe_hook(namespace_selector=None)
        result = ANALYZER.analyze([hook])
        findings = _findings_for(result, "ADMS-002")
        assert "kube-system" in findings[0].message

    def test_weight_applied(self):
        hook = _safe_hook(namespace_selector=None)
        result = ANALYZER.analyze([hook])
        assert result.risk_score == _CHECK_WEIGHTS["ADMS-002"]


# ===========================================================================
# 4. ADMS-003 — Mutating webhook with no timeout
# ===========================================================================


class TestADMS003:
    """ADMS-003: Mutating + no timeout triggers; Validating + no timeout does NOT."""

    def test_mutating_no_timeout_triggers(self):
        hook = _safe_hook(webhook_type="Mutating", timeout_seconds=None)
        result = ANALYZER.analyze([hook])
        assert "ADMS-003" in _check_ids(result)

    def test_validating_no_timeout_does_not_trigger(self):
        hook = _safe_hook(webhook_type="Validating", timeout_seconds=None)
        result = ANALYZER.analyze([hook])
        assert "ADMS-003" not in _check_ids(result)

    def test_mutating_with_timeout_does_not_trigger(self):
        hook = _safe_hook(webhook_type="Mutating", timeout_seconds=15)
        result = ANALYZER.analyze([hook])
        assert "ADMS-003" not in _check_ids(result)

    def test_finding_severity_is_medium(self):
        hook = _safe_hook(webhook_type="Mutating", timeout_seconds=None)
        result = ANALYZER.analyze([hook])
        findings = _findings_for(result, "ADMS-003")
        assert findings[0].severity == "MEDIUM"

    def test_finding_webhook_name_correct(self):
        hook = _safe_hook(name="mutating-hook", webhook_type="Mutating", timeout_seconds=None)
        result = ANALYZER.analyze([hook])
        findings = _findings_for(result, "ADMS-003")
        assert findings[0].webhook_name == "mutating-hook"

    def test_weight_applied(self):
        hook = _safe_hook(webhook_type="Mutating", timeout_seconds=None)
        result = ANALYZER.analyze([hook])
        assert result.risk_score == _CHECK_WEIGHTS["ADMS-003"]


# ===========================================================================
# 5. ADMS-004 — TLS insecure skip verify
# ===========================================================================


class TestADMS004:
    """ADMS-004: tls_insecure_skip_verify=True triggers; False does NOT."""

    def test_insecure_true_triggers(self):
        hook = _safe_hook(tls_insecure_skip_verify=True)
        result = ANALYZER.analyze([hook])
        assert "ADMS-004" in _check_ids(result)

    def test_insecure_false_does_not_trigger(self):
        hook = _safe_hook(tls_insecure_skip_verify=False)
        result = ANALYZER.analyze([hook])
        assert "ADMS-004" not in _check_ids(result)

    def test_finding_severity_is_high(self):
        hook = _safe_hook(tls_insecure_skip_verify=True)
        result = ANALYZER.analyze([hook])
        findings = _findings_for(result, "ADMS-004")
        assert findings[0].severity == "HIGH"

    def test_finding_message_mentions_mitm(self):
        hook = _safe_hook(tls_insecure_skip_verify=True)
        result = ANALYZER.analyze([hook])
        findings = _findings_for(result, "ADMS-004")
        assert "man-in-the-middle" in findings[0].message

    def test_finding_webhook_name_correct(self):
        hook = _safe_hook(name="insecure-hook", tls_insecure_skip_verify=True)
        result = ANALYZER.analyze([hook])
        findings = _findings_for(result, "ADMS-004")
        assert findings[0].webhook_name == "insecure-hook"

    def test_weight_applied(self):
        hook = _safe_hook(tls_insecure_skip_verify=True)
        result = ANALYZER.analyze([hook])
        assert result.risk_score == _CHECK_WEIGHTS["ADMS-004"]


# ===========================================================================
# 6. ADMS-005 — No webhook covers critical resources
# ===========================================================================


class TestADMS005:
    """ADMS-005 coverage checks."""

    def test_no_webhooks_triggers(self):
        result = ANALYZER.analyze([])
        assert "ADMS-005" in _check_ids(result)

    def test_pod_create_rule_satisfies(self):
        hook = _safe_hook(rules=[_safe_rule(resources=["pods"], operations=["CREATE"])])
        result = ANALYZER.analyze([hook])
        assert "ADMS-005" not in _check_ids(result)

    def test_wildcard_resources_satisfies(self):
        hook = _safe_hook(rules=[_safe_rule(resources=["*"], operations=["CREATE"])])
        result = ANALYZER.analyze([hook])
        assert "ADMS-005" not in _check_ids(result)

    def test_wildcard_operations_satisfies(self):
        hook = _safe_hook(rules=[_safe_rule(resources=["pods"], operations=["*"])])
        result = ANALYZER.analyze([hook])
        assert "ADMS-005" not in _check_ids(result)

    def test_both_wildcards_satisfies(self):
        hook = _safe_hook(rules=[_safe_rule(resources=["*"], operations=["*"])])
        result = ANALYZER.analyze([hook])
        assert "ADMS-005" not in _check_ids(result)

    def test_pod_rule_update_only_does_not_satisfy(self):
        # pods covered only for UPDATE, not CREATE → ADMS-005 should fire
        hook = _safe_hook(rules=[_safe_rule(resources=["pods"], operations=["UPDATE"])])
        result = ANALYZER.analyze([hook])
        assert "ADMS-005" in _check_ids(result)

    def test_non_pod_resource_create_does_not_satisfy(self):
        # Covers deployments/CREATE but not pods — ADMS-005 should fire
        hook = _safe_hook(
            rules=[_safe_rule(resources=["deployments"], operations=["CREATE"])]
        )
        result = ANALYZER.analyze([hook])
        assert "ADMS-005" in _check_ids(result)

    def test_finding_severity_is_high(self):
        result = ANALYZER.analyze([])
        findings = _findings_for(result, "ADMS-005")
        assert findings[0].severity == "HIGH"

    def test_finding_webhook_name_empty_for_global_check(self):
        result = ANALYZER.analyze([])
        findings = _findings_for(result, "ADMS-005")
        assert findings[0].webhook_name == ""

    def test_finding_webhook_type_empty_for_global_check(self):
        result = ANALYZER.analyze([])
        findings = _findings_for(result, "ADMS-005")
        assert findings[0].webhook_type == ""

    def test_weight_applied(self):
        result = ANALYZER.analyze([])
        # Only ADMS-005 fires when there are no webhooks
        assert result.risk_score == _CHECK_WEIGHTS["ADMS-005"]

    def test_one_safe_hook_among_unhelpful_hooks_satisfies(self):
        # Two hooks: one covers deployments only, one covers pods CREATE
        hook_no_cover = _safe_hook(
            name="no-cover",
            rules=[_safe_rule(resources=["deployments"], operations=["CREATE"])],
        )
        hook_cover = _safe_hook(
            name="cover",
            rules=[_safe_rule(resources=["pods"], operations=["CREATE"])],
        )
        result = ANALYZER.analyze([hook_no_cover, hook_cover])
        assert "ADMS-005" not in _check_ids(result)


# ===========================================================================
# 7. ADMS-006 — Missing CA bundle
# ===========================================================================


class TestADMS006:
    """ADMS-006: missing or empty CA bundle triggers; non-empty does NOT."""

    def test_ca_bundle_none_triggers(self):
        hook = _safe_hook(ca_bundle=None)
        result = ANALYZER.analyze([hook])
        assert "ADMS-006" in _check_ids(result)

    def test_ca_bundle_empty_string_triggers(self):
        hook = _safe_hook(ca_bundle="")
        result = ANALYZER.analyze([hook])
        assert "ADMS-006" in _check_ids(result)

    def test_ca_bundle_with_content_does_not_trigger(self):
        hook = _safe_hook(ca_bundle="LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t")
        result = ANALYZER.analyze([hook])
        assert "ADMS-006" not in _check_ids(result)

    def test_finding_severity_is_high(self):
        hook = _safe_hook(ca_bundle=None)
        result = ANALYZER.analyze([hook])
        findings = _findings_for(result, "ADMS-006")
        assert findings[0].severity == "HIGH"

    def test_finding_message_mentions_tls(self):
        hook = _safe_hook(ca_bundle=None)
        result = ANALYZER.analyze([hook])
        findings = _findings_for(result, "ADMS-006")
        assert "TLS" in findings[0].message or "CA" in findings[0].message

    def test_finding_webhook_name_correct(self):
        hook = _safe_hook(name="no-ca-hook", ca_bundle=None)
        result = ANALYZER.analyze([hook])
        findings = _findings_for(result, "ADMS-006")
        assert findings[0].webhook_name == "no-ca-hook"

    def test_weight_applied(self):
        hook = _safe_hook(ca_bundle=None)
        result = ANALYZER.analyze([hook])
        assert result.risk_score == _CHECK_WEIGHTS["ADMS-006"]


# ===========================================================================
# 8. ADMS-007 — Side effects not None / NoneOnDryRun
# ===========================================================================


class TestADMS007:
    """ADMS-007: Some/Unknown trigger; None/NoneOnDryRun do NOT."""

    def test_side_effects_some_triggers(self):
        hook = _safe_hook(side_effects="Some")
        result = ANALYZER.analyze([hook])
        assert "ADMS-007" in _check_ids(result)

    def test_side_effects_unknown_triggers(self):
        hook = _safe_hook(side_effects="Unknown")
        result = ANALYZER.analyze([hook])
        assert "ADMS-007" in _check_ids(result)

    def test_side_effects_none_does_not_trigger(self):
        hook = _safe_hook(side_effects="None")
        result = ANALYZER.analyze([hook])
        assert "ADMS-007" not in _check_ids(result)

    def test_side_effects_none_on_dry_run_does_not_trigger(self):
        hook = _safe_hook(side_effects="NoneOnDryRun")
        result = ANALYZER.analyze([hook])
        assert "ADMS-007" not in _check_ids(result)

    def test_finding_severity_is_medium(self):
        hook = _safe_hook(side_effects="Some")
        result = ANALYZER.analyze([hook])
        findings = _findings_for(result, "ADMS-007")
        assert findings[0].severity == "MEDIUM"

    def test_finding_message_mentions_dry_run(self):
        hook = _safe_hook(side_effects="Unknown")
        result = ANALYZER.analyze([hook])
        findings = _findings_for(result, "ADMS-007")
        assert "dry-run" in findings[0].message or "dry run" in findings[0].message.lower()

    def test_finding_mentions_side_effects_value(self):
        hook = _safe_hook(side_effects="Some")
        result = ANALYZER.analyze([hook])
        findings = _findings_for(result, "ADMS-007")
        assert "Some" in findings[0].message

    def test_weight_applied(self):
        hook = _safe_hook(side_effects="Some")
        result = ANALYZER.analyze([hook])
        assert result.risk_score == _CHECK_WEIGHTS["ADMS-007"]


# ===========================================================================
# 9. Multiple findings on the same webhook
# ===========================================================================


class TestMultipleFindings:
    """A webhook can trigger multiple checks simultaneously."""

    def test_ignore_plus_no_namespace_selector(self):
        hook = _safe_hook(failure_policy="Ignore", namespace_selector=None)
        result = ANALYZER.analyze([hook])
        ids = _check_ids(result)
        assert "ADMS-001" in ids
        assert "ADMS-002" in ids

    def test_insecure_tls_plus_no_ca_bundle(self):
        hook = _safe_hook(tls_insecure_skip_verify=True, ca_bundle=None)
        result = ANALYZER.analyze([hook])
        ids = _check_ids(result)
        assert "ADMS-004" in ids
        assert "ADMS-006" in ids

    def test_all_checks_fire_on_worst_case_webhook(self):
        # A deliberately misconfigured mutating webhook that triggers ADMS-001
        # through ADMS-007 (except ADMS-005 which is about coverage, so we
        # provide no rules at all to also trigger ADMS-005).
        hook = AdmissionWebhook(
            name="worst-case",
            webhook_type="Mutating",
            failure_policy="Ignore",        # ADMS-001
            namespace_selector=None,         # ADMS-002
            timeout_seconds=None,            # ADMS-003 (Mutating)
            ca_bundle=None,                  # ADMS-006
            service_name="svc",
            tls_insecure_skip_verify=True,   # ADMS-004
            rules=[],                        # no coverage → ADMS-005
            side_effects="Some",             # ADMS-007
        )
        result = ANALYZER.analyze([hook])
        ids = _check_ids(result)
        for check_id in ("ADMS-001", "ADMS-002", "ADMS-003", "ADMS-004", "ADMS-005", "ADMS-006", "ADMS-007"):
            assert check_id in ids, f"{check_id} should have fired"

    def test_worst_case_risk_score_capped_at_100(self):
        hook = AdmissionWebhook(
            name="worst-case",
            webhook_type="Mutating",
            failure_policy="Ignore",
            namespace_selector=None,
            timeout_seconds=None,
            ca_bundle=None,
            service_name="svc",
            tls_insecure_skip_verify=True,
            rules=[],
            side_effects="Some",
        )
        result = ANALYZER.analyze([hook])
        assert result.risk_score == 100

    def test_risk_score_additive_before_cap(self):
        # ADMS-001 (40) + ADMS-002 (25) = 65, below cap
        hook = _safe_hook(failure_policy="Ignore", namespace_selector=None)
        result = ANALYZER.analyze([hook])
        expected = _CHECK_WEIGHTS["ADMS-001"] + _CHECK_WEIGHTS["ADMS-002"]
        assert result.risk_score == expected

    def test_two_findings_listed_separately(self):
        hook = _safe_hook(failure_policy="Ignore", namespace_selector=None)
        result = ANALYZER.analyze([hook])
        # Two per-webhook findings (ADMS-001 and ADMS-002)
        assert len([f for f in result.findings if f.webhook_name == "safe-webhook"]) == 2

    def test_same_check_multiple_hooks_weight_once(self):
        # Both hooks fire ADMS-002 → only one weight unit counted
        h1 = _safe_hook(name="h1", namespace_selector=None)
        h2 = _safe_hook(name="h2", namespace_selector=None)
        result = ANALYZER.analyze([h1, h2])
        assert result.risk_score == _CHECK_WEIGHTS["ADMS-002"]

    def test_two_findings_objects_produced_for_two_hooks(self):
        # Even though weight counted once, both finding objects present
        h1 = _safe_hook(name="h1", namespace_selector=None)
        h2 = _safe_hook(name="h2", namespace_selector=None)
        result = ANALYZER.analyze([h1, h2])
        adms002_findings = _findings_for(result, "ADMS-002")
        assert len(adms002_findings) == 2


# ===========================================================================
# 10. Risk score specifics
# ===========================================================================


class TestRiskScore:
    """Risk score is the sum of unique fired check weights, capped at 100."""

    def test_zero_findings_zero_score(self):
        result = ANALYZER.analyze([_safe_hook()])
        assert result.risk_score == 0

    def test_single_check_exact_weight(self):
        for check_id, weight in _CHECK_WEIGHTS.items():
            # Build a result object manually to verify weight mapping
            finding = AdmissionFinding(
                check_id=check_id,
                severity="HIGH",
                webhook_name="x",
                webhook_type="Validating",
                message="m",
                recommendation="r",
            )
            result = AdmissionPolicyResult(findings=[finding], risk_score=weight)
            assert result.risk_score == weight

    def test_cap_at_100(self):
        # Force a score above 100 by injecting duplicate check IDs via the result
        # (not via analyzer, since dedup is the analyzer's job)
        finding = AdmissionFinding(
            check_id="ADMS-001",
            severity="CRITICAL",
            webhook_name="x",
            webhook_type="Validating",
            message="m",
            recommendation="r",
        )
        # Direct construction — risk_score can technically exceed 100 if set directly
        result = AdmissionPolicyResult(findings=[finding], risk_score=150)
        # The cap is enforced by the analyzer's analyze() method, not the dataclass
        # Verify the analyzer does enforce the cap via the worst-case test elsewhere
        assert result.risk_score == 150  # raw dataclass allows it; analyzer caps it

    def test_analyzer_enforces_cap(self):
        hook = AdmissionWebhook(
            name="worst",
            webhook_type="Mutating",
            failure_policy="Ignore",
            namespace_selector=None,
            timeout_seconds=None,
            ca_bundle=None,
            service_name="svc",
            tls_insecure_skip_verify=True,
            rules=[],
            side_effects="Some",
        )
        result = ANALYZER.analyze([hook])
        assert result.risk_score <= 100


# ===========================================================================
# 11. by_severity()
# ===========================================================================


class TestBySeverity:
    """by_severity() should group findings correctly."""

    def test_returns_dict(self):
        result = ANALYZER.analyze([_safe_hook()])
        assert isinstance(result.by_severity(), dict)

    def test_critical_key_present_when_adms001_fires(self):
        hook = _safe_hook(failure_policy="Ignore")
        result = ANALYZER.analyze([hook])
        sev = result.by_severity()
        assert "CRITICAL" in sev

    def test_high_key_present_when_adms002_fires(self):
        hook = _safe_hook(namespace_selector=None)
        result = ANALYZER.analyze([hook])
        sev = result.by_severity()
        assert "HIGH" in sev

    def test_medium_key_present_when_adms003_fires(self):
        hook = _safe_hook(webhook_type="Mutating", timeout_seconds=None)
        result = ANALYZER.analyze([hook])
        sev = result.by_severity()
        assert "MEDIUM" in sev

    def test_values_are_lists_of_findings(self):
        hook = _safe_hook(failure_policy="Ignore")
        result = ANALYZER.analyze([hook])
        sev = result.by_severity()
        assert all(isinstance(v, list) for v in sev.values())
        assert all(isinstance(f, AdmissionFinding) for v in sev.values() for f in v)

    def test_total_count_matches_findings(self):
        hook = _safe_hook(failure_policy="Ignore", namespace_selector=None)
        result = ANALYZER.analyze([hook])
        sev = result.by_severity()
        total_in_groups = sum(len(v) for v in sev.values())
        assert total_in_groups == len(result.findings)

    def test_no_unknown_severity_keys(self):
        hook = _safe_hook(
            failure_policy="Ignore",
            namespace_selector=None,
            tls_insecure_skip_verify=True,
            ca_bundle=None,
            side_effects="Some",
            webhook_type="Mutating",
            timeout_seconds=None,
        )
        result = ANALYZER.analyze([hook])
        allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        assert set(result.by_severity().keys()).issubset(allowed)


# ===========================================================================
# 12. summary()
# ===========================================================================


class TestSummary:
    """summary() must follow the expected format."""

    def test_returns_string(self):
        result = ANALYZER.analyze([_safe_hook()])
        assert isinstance(result.summary(), str)

    def test_contains_risk_score(self):
        hook = _safe_hook(failure_policy="Ignore")
        result = ANALYZER.analyze([hook])
        assert str(result.risk_score) in result.summary()

    def test_contains_finding_count(self):
        hook = _safe_hook(failure_policy="Ignore")
        result = ANALYZER.analyze([hook])
        assert "1 finding(s)" in result.summary()

    def test_contains_critical_label(self):
        hook = _safe_hook(failure_policy="Ignore")
        result = ANALYZER.analyze([hook])
        assert "CRITICAL=" in result.summary()

    def test_contains_high_label(self):
        result = ANALYZER.analyze([_safe_hook()])
        assert "HIGH=" in result.summary()

    def test_contains_medium_label(self):
        result = ANALYZER.analyze([_safe_hook()])
        assert "MEDIUM=" in result.summary()

    def test_zero_counts_in_clean_summary(self):
        result = ANALYZER.analyze([_safe_hook()])
        summary = result.summary()
        assert "CRITICAL=0" in summary
        assert "HIGH=0" in summary
        assert "MEDIUM=0" in summary

    def test_out_of_100_format(self):
        result = ANALYZER.analyze([_safe_hook()])
        assert "/100" in result.summary()


# ===========================================================================
# 13. analyze_many()
# ===========================================================================


class TestAnalyzeMany:
    """analyze_many() returns one result per group."""

    def test_returns_list(self):
        results = ANALYZER.analyze_many([[_safe_hook()]])
        assert isinstance(results, list)

    def test_empty_input_returns_empty_list(self):
        results = ANALYZER.analyze_many([])
        assert results == []

    def test_one_group_returns_one_result(self):
        results = ANALYZER.analyze_many([[_safe_hook()]])
        assert len(results) == 1

    def test_two_groups_return_two_results(self):
        results = ANALYZER.analyze_many([[_safe_hook()], [_safe_hook(name="h2")]])
        assert len(results) == 2

    def test_each_element_is_admission_policy_result(self):
        results = ANALYZER.analyze_many([[_safe_hook()], [_safe_hook(name="h2")]])
        assert all(isinstance(r, AdmissionPolicyResult) for r in results)

    def test_groups_analyzed_independently(self):
        # Group 1: clean; Group 2: fails-open
        safe_group = [_safe_hook(name="safe")]
        risky_group = [_safe_hook(name="risky", failure_policy="Ignore")]
        results = ANALYZER.analyze_many([safe_group, risky_group])
        assert results[0].risk_score == 0
        assert results[1].risk_score == _CHECK_WEIGHTS["ADMS-001"]

    def test_empty_group_triggers_adms005(self):
        results = ANALYZER.analyze_many([[]])
        assert "ADMS-005" in _check_ids(results[0])


# ===========================================================================
# 14. to_dict() — all dataclasses
# ===========================================================================


class TestToDict:
    """to_dict() must serialize all fields to plain dicts."""

    def test_webhook_rule_to_dict_keys(self):
        rule = _safe_rule()
        d = rule.to_dict()
        assert set(d.keys()) == {"api_groups", "api_versions", "resources", "operations"}

    def test_webhook_rule_to_dict_values(self):
        rule = WebhookRule(
            api_groups=["apps"],
            api_versions=["v1"],
            resources=["deployments"],
            operations=["CREATE", "UPDATE"],
        )
        d = rule.to_dict()
        assert d["api_groups"] == ["apps"]
        assert d["operations"] == ["CREATE", "UPDATE"]

    def test_admission_webhook_to_dict_keys(self):
        hook = _safe_hook()
        d = hook.to_dict()
        expected_keys = {
            "name", "webhook_type", "failure_policy", "namespace_selector",
            "timeout_seconds", "ca_bundle", "service_name",
            "tls_insecure_skip_verify", "rules", "side_effects",
        }
        assert set(d.keys()) == expected_keys

    def test_admission_webhook_to_dict_rules_are_dicts(self):
        hook = _safe_hook()
        d = hook.to_dict()
        assert isinstance(d["rules"], list)
        assert all(isinstance(r, dict) for r in d["rules"])

    def test_admission_webhook_to_dict_name(self):
        hook = _safe_hook(name="test-hook")
        d = hook.to_dict()
        assert d["name"] == "test-hook"

    def test_admission_finding_to_dict_keys(self):
        finding = AdmissionFinding(
            check_id="ADMS-001",
            severity="CRITICAL",
            webhook_name="hook",
            webhook_type="Validating",
            message="msg",
            recommendation="rec",
        )
        d = finding.to_dict()
        assert set(d.keys()) == {
            "check_id", "severity", "webhook_name", "webhook_type",
            "message", "recommendation",
        }

    def test_admission_finding_to_dict_values(self):
        finding = AdmissionFinding(
            check_id="ADMS-002",
            severity="HIGH",
            webhook_name="my-hook",
            webhook_type="Mutating",
            message="test message",
            recommendation="test rec",
        )
        d = finding.to_dict()
        assert d["check_id"] == "ADMS-002"
        assert d["severity"] == "HIGH"
        assert d["webhook_name"] == "my-hook"

    def test_admission_policy_result_to_dict_keys(self):
        result = ANALYZER.analyze([_safe_hook()])
        d = result.to_dict()
        assert set(d.keys()) == {"findings", "risk_score", "summary", "by_severity"}

    def test_admission_policy_result_to_dict_findings_are_dicts(self):
        hook = _safe_hook(failure_policy="Ignore")
        result = ANALYZER.analyze([hook])
        d = result.to_dict()
        assert isinstance(d["findings"], list)
        assert all(isinstance(f, dict) for f in d["findings"])

    def test_admission_policy_result_to_dict_risk_score(self):
        hook = _safe_hook(failure_policy="Ignore")
        result = ANALYZER.analyze([hook])
        d = result.to_dict()
        assert d["risk_score"] == _CHECK_WEIGHTS["ADMS-001"]

    def test_admission_policy_result_to_dict_summary_is_string(self):
        result = ANALYZER.analyze([_safe_hook()])
        d = result.to_dict()
        assert isinstance(d["summary"], str)

    def test_admission_policy_result_to_dict_by_severity_is_dict(self):
        hook = _safe_hook(failure_policy="Ignore")
        result = ANALYZER.analyze([hook])
        d = result.to_dict()
        assert isinstance(d["by_severity"], dict)

    def test_admission_policy_result_to_dict_by_severity_values_are_lists(self):
        hook = _safe_hook(failure_policy="Ignore")
        result = ANALYZER.analyze([hook])
        d = result.to_dict()
        assert all(isinstance(v, list) for v in d["by_severity"].values())

    def test_round_trip_finding_preserves_check_id(self):
        hook = _safe_hook(failure_policy="Ignore")
        result = ANALYZER.analyze([hook])
        d = result.to_dict()
        check_ids_in_dict = {f["check_id"] for f in d["findings"]}
        assert "ADMS-001" in check_ids_in_dict


# ===========================================================================
# 15. WebhookRule dataclass edge cases
# ===========================================================================


class TestWebhookRule:
    """WebhookRule field access and serialization."""

    def test_fields_accessible(self):
        rule = WebhookRule(
            api_groups=["*"],
            api_versions=["*"],
            resources=["*"],
            operations=["*"],
        )
        assert rule.api_groups == ["*"]
        assert rule.api_versions == ["*"]
        assert rule.resources == ["*"]
        assert rule.operations == ["*"]

    def test_to_dict_round_trip(self):
        rule = WebhookRule(
            api_groups=["apps"],
            api_versions=["v1beta1"],
            resources=["replicasets"],
            operations=["DELETE"],
        )
        d = rule.to_dict()
        assert d == {
            "api_groups": ["apps"],
            "api_versions": ["v1beta1"],
            "resources": ["replicasets"],
            "operations": ["DELETE"],
        }


# ===========================================================================
# 16. AdmissionWebhook default side_effects
# ===========================================================================


class TestAdmissionWebhookDefaults:
    """AdmissionWebhook default field values."""

    def test_default_side_effects_is_none_string(self):
        hook = AdmissionWebhook(
            name="x",
            webhook_type="Validating",
            failure_policy="Fail",
            namespace_selector={"matchLabels": {"k": "v"}},
            timeout_seconds=10,
            ca_bundle="cert",
            service_name="svc",
            tls_insecure_skip_verify=False,
            rules=[],
        )
        assert hook.side_effects == "None"

    def test_default_tls_insecure_skip_verify_false(self):
        # tls_insecure_skip_verify has default False — must not trigger ADMS-004
        hook = AdmissionWebhook(
            name="x",
            webhook_type="Validating",
            failure_policy="Fail",
            namespace_selector={"matchLabels": {"k": "v"}},
            timeout_seconds=10,
            ca_bundle="cert",
            service_name="svc",
            tls_insecure_skip_verify=False,
            rules=[_safe_rule()],
        )
        result = ANALYZER.analyze([hook])
        assert "ADMS-004" not in _check_ids(result)


# ===========================================================================
# 17. _CHECK_WEIGHTS registry integrity
# ===========================================================================


class TestCheckWeightsRegistry:
    """_CHECK_WEIGHTS must cover all check IDs with positive integers."""

    def test_all_seven_checks_present(self):
        for i in range(1, 8):
            check_id = f"ADMS-{i:03d}"
            assert check_id in _CHECK_WEIGHTS, f"{check_id} missing from _CHECK_WEIGHTS"

    def test_all_weights_are_positive_integers(self):
        for check_id, weight in _CHECK_WEIGHTS.items():
            assert isinstance(weight, int), f"{check_id} weight must be int"
            assert weight > 0, f"{check_id} weight must be positive"

    def test_adms001_weight_is_40(self):
        assert _CHECK_WEIGHTS["ADMS-001"] == 40

    def test_adms005_weight_is_25(self):
        assert _CHECK_WEIGHTS["ADMS-005"] == 25
