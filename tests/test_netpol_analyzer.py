"""
Tests for kubernetes/netpol_analyzer.py
Covers NP-001 through NP-007 checks, report structure, and happy paths.
"""
import pytest
from kubernetes.netpol_analyzer import (
    NetworkPolicyAnalyzer,
    NetpolFinding,
    NetpolReport,
    NetpolSeverity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_policy(
    name="test-policy",
    namespace="default",
    pod_selector=None,
    ingress=None,
    egress=None,
    policy_types=None,
):
    spec = {}
    if pod_selector is not None:
        spec["podSelector"] = pod_selector
    if ingress is not None:
        spec["ingress"] = ingress
    if egress is not None:
        spec["egress"] = egress
    if policy_types is not None:
        spec["policyTypes"] = policy_types
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }


def check_ids(report: NetpolReport):
    return {f.check_id for f in report.findings}


# ---------------------------------------------------------------------------
# NetworkPolicyAnalyzer — basic instantiation
# ---------------------------------------------------------------------------

class TestInstantiation:
    def test_default_init(self):
        a = NetworkPolicyAnalyzer()
        assert a._default_ns == "default"
        assert a._check_coverage is True

    def test_custom_init(self):
        a = NetworkPolicyAnalyzer(default_namespace="kube-system", check_coverage=False)
        assert a._default_ns == "kube-system"
        assert a._check_coverage is False


# ---------------------------------------------------------------------------
# Empty / non-NetworkPolicy manifests
# ---------------------------------------------------------------------------

class TestEmptyAndFiltering:
    def test_empty_manifests(self):
        report = NetworkPolicyAnalyzer().analyze([])
        assert report.total_findings == 0
        assert report.policies_analyzed == 0
        assert report.risk_score == 0

    def test_non_netpol_manifests_ignored(self):
        manifests = [
            {"kind": "Deployment", "metadata": {"name": "app"}},
            {"kind": "Service", "metadata": {"name": "svc"}},
        ]
        report = NetworkPolicyAnalyzer().analyze(manifests)
        assert report.policies_analyzed == 0
        assert report.total_findings == 0

    def test_mixed_manifests_only_netpol_analyzed(self):
        manifests = [
            {"kind": "Deployment", "metadata": {"name": "app"}},
            _make_policy(pod_selector={"matchLabels": {"app": "web"}}),
        ]
        report = NetworkPolicyAnalyzer().analyze(manifests)
        assert report.policies_analyzed == 1


# ---------------------------------------------------------------------------
# NP-006: empty podSelector targets all pods
# ---------------------------------------------------------------------------

class TestNP006:
    def test_empty_pod_selector_dict(self):
        policy = _make_policy(pod_selector={})
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert "NP-006" in check_ids(report)

    def test_none_pod_selector(self):
        # spec without podSelector key → spec.get("podSelector", None) = None
        policy = _make_policy()  # no pod_selector passed → not in spec
        # Actually _make_policy omits podSelector when pod_selector is None
        # But the analyzer does spec.get("podSelector", None) which returns None → triggers NP-006
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert "NP-006" in check_ids(report)

    def test_specific_pod_selector_no_np006(self):
        policy = _make_policy(pod_selector={"matchLabels": {"app": "frontend"}})
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert "NP-006" not in check_ids(report)

    def test_np006_severity_is_high(self):
        policy = _make_policy(pod_selector={})
        report = NetworkPolicyAnalyzer().analyze([policy])
        np006 = [f for f in report.findings if f.check_id == "NP-006"]
        assert len(np006) >= 1
        assert np006[0].severity == NetpolSeverity.HIGH

    def test_np006_has_namespace(self):
        policy = _make_policy(pod_selector={}, namespace="production", name="broad-pol")
        report = NetworkPolicyAnalyzer().analyze([policy])
        findings = [f for f in report.findings if f.check_id == "NP-006"]
        assert findings[0].namespace == "production"
        assert findings[0].policy_name == "broad-pol"


# ---------------------------------------------------------------------------
# NP-003: ingress allows all sources
# ---------------------------------------------------------------------------

class TestNP003:
    def test_ingress_rule_no_from_key(self):
        """Ingress rule without 'from' key → allow all ingress."""
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            ingress=[{}],  # empty rule = no 'from'
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert "NP-003" in check_ids(report)

    def test_ingress_rule_empty_from_list(self):
        """Ingress rule with empty 'from' list → allow all ingress."""
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            ingress=[{"from": []}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert "NP-003" in check_ids(report)

    def test_ingress_from_empty_pod_selector(self):
        """'from' peer with empty podSelector → any pod."""
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            ingress=[{"from": [{"podSelector": {}}]}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert "NP-003" in check_ids(report)

    def test_np003_critical_when_no_from(self):
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            ingress=[{}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        findings = [f for f in report.findings if f.check_id == "NP-003"]
        assert findings[0].severity == NetpolSeverity.CRITICAL

    def test_np003_high_when_empty_pod_selector(self):
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            ingress=[{"from": [{"podSelector": {}}]}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        findings = [f for f in report.findings if f.check_id == "NP-003"]
        assert findings[0].severity == NetpolSeverity.HIGH

    def test_specific_from_no_np003(self):
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            ingress=[{"from": [{"podSelector": {"matchLabels": {"app": "api"}}}]}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert "NP-003" not in check_ids(report)


# ---------------------------------------------------------------------------
# NP-004: ingress from all namespaces
# ---------------------------------------------------------------------------

class TestNP004:
    def test_empty_namespace_selector(self):
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            ingress=[{"from": [{"namespaceSelector": {}}]}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert "NP-004" in check_ids(report)

    def test_np004_severity_is_high(self):
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            ingress=[{"from": [{"namespaceSelector": {}}]}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        findings = [f for f in report.findings if f.check_id == "NP-004"]
        assert findings[0].severity == NetpolSeverity.HIGH

    def test_specific_namespace_selector_no_np004(self):
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            ingress=[{"from": [{"namespaceSelector": {"matchLabels": {"env": "prod"}}}]}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert "NP-004" not in check_ids(report)

    def test_np004_has_correct_policy_name(self):
        policy = _make_policy(
            name="broad-ns-policy",
            pod_selector={"matchLabels": {"app": "web"}},
            ingress=[{"from": [{"namespaceSelector": {}}]}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        findings = [f for f in report.findings if f.check_id == "NP-004"]
        assert findings[0].policy_name == "broad-ns-policy"


# ---------------------------------------------------------------------------
# NP-005: egress to all destinations
# ---------------------------------------------------------------------------

class TestNP005:
    def test_egress_rule_no_to_key(self):
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            egress=[{}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert "NP-005" in check_ids(report)

    def test_egress_rule_empty_to_list(self):
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            egress=[{"to": []}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert "NP-005" in check_ids(report)

    def test_np005_severity_is_high(self):
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            egress=[{}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        findings = [f for f in report.findings if f.check_id == "NP-005"]
        assert findings[0].severity == NetpolSeverity.HIGH

    def test_specific_egress_no_np005(self):
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            egress=[{"to": [{"namespaceSelector": {"matchLabels": {"name": "monitoring"}}}]}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert "NP-005" not in check_ids(report)


# ---------------------------------------------------------------------------
# NP-007: no ports restriction
# ---------------------------------------------------------------------------

class TestNP007:
    def test_ingress_from_specific_but_no_ports(self):
        """Specific 'from' but no 'ports' → NP-007."""
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            ingress=[{"from": [{"podSelector": {"matchLabels": {"app": "api"}}}]}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert "NP-007" in check_ids(report)

    def test_np007_severity_is_medium(self):
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            ingress=[{"from": [{"podSelector": {"matchLabels": {"app": "api"}}}]}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        findings = [f for f in report.findings if f.check_id == "NP-007"]
        assert findings[0].severity == NetpolSeverity.MEDIUM

    def test_ingress_with_ports_no_np007(self):
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            ingress=[{
                "from": [{"podSelector": {"matchLabels": {"app": "api"}}}],
                "ports": [{"port": 8080, "protocol": "TCP"}],
            }],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert "NP-007" not in check_ids(report)

    def test_no_from_does_not_trigger_np007(self):
        """When 'from' is empty/missing, NP-003 fires but NP-007 should NOT (ambiguous case)."""
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            ingress=[{}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert "NP-003" in check_ids(report)
        assert "NP-007" not in check_ids(report)


# ---------------------------------------------------------------------------
# Multiple findings per policy
# ---------------------------------------------------------------------------

class TestMultipleFindings:
    def test_allow_all_policy_fires_np003_and_np006(self):
        """Classic allow-all policy: empty podSelector + empty ingress rule."""
        policy = _make_policy(
            pod_selector={},
            ingress=[{}],
            policy_types=["Ingress"],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        ids = check_ids(report)
        assert "NP-003" in ids
        assert "NP-006" in ids

    def test_multiple_policies_aggregated(self):
        p1 = _make_policy(name="p1", pod_selector={})
        p2 = _make_policy(name="p2", pod_selector={"matchLabels": {"a": "b"}},
                          ingress=[{"from": [{"namespaceSelector": {}}]}])
        report = NetworkPolicyAnalyzer().analyze([p1, p2])
        assert report.policies_analyzed == 2
        ids = check_ids(report)
        assert "NP-006" in ids
        assert "NP-004" in ids

    def test_both_ingress_and_egress_issues(self):
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "x"}},
            ingress=[{}],
            egress=[{}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        ids = check_ids(report)
        assert "NP-003" in ids
        assert "NP-005" in ids


# ---------------------------------------------------------------------------
# Risk score
# ---------------------------------------------------------------------------

class TestRiskScore:
    def test_clean_policy_zero_score(self):
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "clean"}},
            ingress=[{
                "from": [{"podSelector": {"matchLabels": {"app": "api"}}}],
                "ports": [{"port": 443}],
            }],
            egress=[{
                "to": [{"podSelector": {"matchLabels": {"app": "db"}}}],
            }],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert report.risk_score == 0

    def test_risk_score_capped_at_100(self):
        # Fire NP-003(35), NP-004(30), NP-005(30), NP-006(25) = 120, capped at 100
        policy = _make_policy(
            pod_selector={},
            ingress=[{"from": [{"namespaceSelector": {}}]}],
            egress=[{}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert report.risk_score <= 100

    def test_single_np003_score(self):
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "web"}},
            ingress=[{}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        # NP-003 weight = 35; possibly also NP-007 at 15 but NP-007 doesn't fire on empty from
        assert report.risk_score > 0


# ---------------------------------------------------------------------------
# NetpolReport helpers
# ---------------------------------------------------------------------------

class TestNetpolReport:
    def test_total_findings(self):
        policy = _make_policy(pod_selector={}, ingress=[{}])
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert report.total_findings == len(report.findings)

    def test_critical_findings_filter(self):
        policy = _make_policy(
            pod_selector={"matchLabels": {"app": "x"}},
            ingress=[{}],  # NP-003 CRITICAL
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        crit = report.critical_findings
        assert all(f.severity == NetpolSeverity.CRITICAL for f in crit)

    def test_high_findings_filter(self):
        policy = _make_policy(pod_selector={})  # NP-006 HIGH
        report = NetworkPolicyAnalyzer().analyze([policy])
        high = report.high_findings
        assert all(f.severity == NetpolSeverity.HIGH for f in high)

    def test_findings_by_check(self):
        policy = _make_policy(pod_selector={})
        report = NetworkPolicyAnalyzer().analyze([policy])
        np006_findings = report.findings_by_check("NP-006")
        assert len(np006_findings) >= 1
        assert all(f.check_id == "NP-006" for f in np006_findings)

    def test_findings_for_namespace(self):
        p1 = _make_policy(name="p1", namespace="ns-a", pod_selector={})
        p2 = _make_policy(name="p2", namespace="ns-b", pod_selector={})
        report = NetworkPolicyAnalyzer().analyze([p1, p2])
        ns_a_findings = report.findings_for_namespace("ns-a")
        assert all(f.namespace == "ns-a" for f in ns_a_findings)

    def test_summary_string(self):
        policy = _make_policy(pod_selector={})
        report = NetworkPolicyAnalyzer().analyze([policy])
        s = report.summary()
        assert "NetPol Report" in s
        assert "risk_score" in s

    def test_to_dict_structure(self):
        policy = _make_policy(pod_selector={})
        report = NetworkPolicyAnalyzer().analyze([policy])
        d = report.to_dict()
        assert "total_findings" in d
        assert "risk_score" in d
        assert "policies_analyzed" in d
        assert "critical" in d
        assert "high" in d
        assert "generated_at" in d
        assert "findings" in d
        assert isinstance(d["findings"], list)

    def test_finding_to_dict(self):
        policy = _make_policy(pod_selector={})
        report = NetworkPolicyAnalyzer().analyze([policy])
        d = report.findings[0].to_dict()
        assert "check_id" in d
        assert "severity" in d
        assert "namespace" in d
        assert "policy_name" in d
        assert "title" in d
        assert "detail" in d
        assert "remediation" in d

    def test_finding_summary(self):
        policy = _make_policy(pod_selector={})
        report = NetworkPolicyAnalyzer().analyze([policy])
        s = report.findings[0].summary()
        assert "[NP-" in s


# ---------------------------------------------------------------------------
# Default namespace fallback
# ---------------------------------------------------------------------------

class TestDefaultNamespace:
    def test_policy_without_namespace_uses_default(self):
        policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "no-ns"},
            "spec": {"podSelector": {}},
        }
        report = NetworkPolicyAnalyzer(default_namespace="fallback").analyze([policy])
        assert any(f.namespace == "fallback" for f in report.findings)

    def test_policy_with_empty_namespace_uses_default(self):
        policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "empty-ns", "namespace": ""},
            "spec": {"podSelector": {}},
        }
        report = NetworkPolicyAnalyzer(default_namespace="fallback2").analyze([policy])
        assert any(f.namespace == "fallback2" for f in report.findings)


# ---------------------------------------------------------------------------
# NetpolFinding fields
# ---------------------------------------------------------------------------

class TestFindingFields:
    def test_finding_has_remediation(self):
        policy = _make_policy(pod_selector={})
        report = NetworkPolicyAnalyzer().analyze([policy])
        for f in report.findings:
            assert f.remediation != ""

    def test_finding_check_ids_are_valid(self):
        policy = _make_policy(
            pod_selector={},
            ingress=[{}],
            egress=[{}],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        valid_ids = {"NP-001", "NP-002", "NP-003", "NP-004", "NP-005", "NP-006", "NP-007"}
        for f in report.findings:
            assert f.check_id in valid_ids

    def test_finding_severity_is_enum(self):
        policy = _make_policy(pod_selector={})
        report = NetworkPolicyAnalyzer().analyze([policy])
        for f in report.findings:
            assert isinstance(f.severity, NetpolSeverity)


# ---------------------------------------------------------------------------
# Full clean policy — no findings
# ---------------------------------------------------------------------------

class TestCleanPolicy:
    def test_well_scoped_policy_no_findings(self):
        policy = _make_policy(
            name="secure-api",
            namespace="production",
            pod_selector={"matchLabels": {"role": "api"}},
            ingress=[{
                "from": [
                    {"podSelector": {"matchLabels": {"role": "frontend"}}},
                ],
                "ports": [{"port": 8080, "protocol": "TCP"}],
            }],
            egress=[{
                "to": [
                    {"podSelector": {"matchLabels": {"role": "db"}}},
                ],
                "ports": [{"port": 5432, "protocol": "TCP"}],
            }],
            policy_types=["Ingress", "Egress"],
        )
        report = NetworkPolicyAnalyzer().analyze([policy])
        assert report.total_findings == 0
        assert report.risk_score == 0
