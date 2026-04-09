# Copyright 2024 hiagokinlevi
#
# Licensed under the Creative Commons Attribution 4.0 International License
# (CC BY 4.0). You may obtain a copy of the License at:
#   https://creativecommons.org/licenses/by/4.0/

"""
test_cis_benchmark_scanner.py
------------------------------
85+ tests for the CIS Kubernetes Benchmark scanner.

Coverage matrix:
  - Fully hardened cluster    -> zero findings, compliance_score=100
  - Each of 7 checks          -> fires on the bad value, silent on the good value
  - Score arithmetic          -> risk_score = sum of weights, capped at 100
  - compliance_score          -> always max(0, 100 - risk_score)
  - by_severity()             -> grouping, empty cluster, unknown severity
  - summary()                 -> contains both score values
  - scan_many()               -> list length and types
  - to_dict()                 -> all dataclasses round-trip
  - CIS reference field       -> populated on every finding
"""

from __future__ import annotations

import sys
import os

# ---------------------------------------------------------------------------
# Path bootstrap — allow running from repo root or from /tests directly.
# ---------------------------------------------------------------------------
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import pytest

from shared.compliance.cis_benchmark_scanner import (
    APIServerConfig,
    CISBenchmarkResult,
    CISBenchmarkScanner,
    CISFinding,
    ClusterConfig,
    EtcdConfig,
    KubeletConfig,
    _CHECK_WEIGHTS,
)

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _hardened_api_server() -> APIServerConfig:
    """API server config that satisfies every CIS check."""
    return APIServerConfig(
        anonymous_auth_enabled=False,
        tls_cert_file="/etc/kubernetes/pki/apiserver.crt",
        tls_private_key_file="/etc/kubernetes/pki/apiserver.key",
        audit_log_path="/var/log/kubernetes/audit.log",
        audit_policy_file="/etc/kubernetes/audit-policy.yaml",
        authorization_mode="Node,RBAC",
        insecure_port=0,
        pod_security_admission_enabled=True,
    )


def _hardened_etcd() -> EtcdConfig:
    """Etcd config that satisfies every CIS check."""
    return EtcdConfig(
        encryption_config_file="/etc/kubernetes/enc.yaml",
        tls_cert_file="/etc/etcd/pki/etcd.crt",
        tls_key_file="/etc/etcd/pki/etcd.key",
    )


def _hardened_kubelet() -> KubeletConfig:
    """Kubelet config that satisfies every CIS check."""
    return KubeletConfig(
        read_only_port=0,
        anonymous_auth_enabled=False,
        authorization_mode="Webhook",
        rotate_certificates=True,
    )


def _hardened_cluster(name: str = "hardened-cluster") -> ClusterConfig:
    """A fully hardened ClusterConfig that should produce zero findings."""
    return ClusterConfig(
        name=name,
        api_server=_hardened_api_server(),
        etcd=_hardened_etcd(),
        kubelet=_hardened_kubelet(),
        kube_system_sa_automount=False,
    )


@pytest.fixture
def scanner() -> CISBenchmarkScanner:
    return CISBenchmarkScanner()


@pytest.fixture
def hardened(scanner: CISBenchmarkScanner) -> CISBenchmarkResult:
    return scanner.scan(_hardened_cluster())


# ---------------------------------------------------------------------------
# 1. Fully hardened cluster
# ---------------------------------------------------------------------------


class TestHardenedCluster:
    def test_no_findings(self, hardened: CISBenchmarkResult) -> None:
        assert hardened.findings == []

    def test_risk_score_zero(self, hardened: CISBenchmarkResult) -> None:
        assert hardened.risk_score == 0

    def test_compliance_score_100(self, hardened: CISBenchmarkResult) -> None:
        assert hardened.compliance_score == 100

    def test_cluster_name_preserved(self, hardened: CISBenchmarkResult) -> None:
        assert hardened.cluster_name == "hardened-cluster"

    def test_by_severity_empty(self, hardened: CISBenchmarkResult) -> None:
        assert hardened.by_severity() == {}

    def test_summary_contains_zero_findings(self, hardened: CISBenchmarkResult) -> None:
        assert "0 finding" in hardened.summary()

    def test_summary_contains_risk_score(self, hardened: CISBenchmarkResult) -> None:
        assert "risk_score=0" in hardened.summary()

    def test_summary_contains_compliance_score(self, hardened: CISBenchmarkResult) -> None:
        assert "compliance_score=100" in hardened.summary()


# ---------------------------------------------------------------------------
# 2. CIS-K8S-001 — API server anonymous authentication
# ---------------------------------------------------------------------------


class TestCISK8S001:
    def test_triggers_on_true(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.anonymous_auth_enabled = True
        result = scanner.scan(cluster)
        check_ids = [f.check_id for f in result.findings]
        assert "CIS-K8S-001" in check_ids

    def test_does_not_trigger_on_false(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.anonymous_auth_enabled = False
        result = scanner.scan(cluster)
        check_ids = [f.check_id for f in result.findings]
        assert "CIS-K8S-001" not in check_ids

    def test_severity_is_critical(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.anonymous_auth_enabled = True
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-001")
        assert finding.severity == "CRITICAL"

    def test_cis_reference_populated(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.anonymous_auth_enabled = True
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-001")
        assert finding.cis_reference != ""
        assert "1.2.1" in finding.cis_reference

    def test_weight_applied(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.anonymous_auth_enabled = True
        result = scanner.scan(cluster)
        assert result.risk_score == _CHECK_WEIGHTS["CIS-K8S-001"]

    def test_title_is_not_empty(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.anonymous_auth_enabled = True
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-001")
        assert finding.title != ""

    def test_remediation_is_not_empty(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.anonymous_auth_enabled = True
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-001")
        assert finding.remediation != ""


# ---------------------------------------------------------------------------
# 3. CIS-K8S-002 — Etcd encryption at rest
# ---------------------------------------------------------------------------


class TestCISK8S002:
    def test_triggers_when_none(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.etcd.encryption_config_file = None
        result = scanner.scan(cluster)
        assert "CIS-K8S-002" in [f.check_id for f in result.findings]

    def test_triggers_when_empty_string(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.etcd.encryption_config_file = ""
        result = scanner.scan(cluster)
        assert "CIS-K8S-002" in [f.check_id for f in result.findings]

    def test_does_not_trigger_when_set(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.etcd.encryption_config_file = "/etc/kubernetes/enc.yaml"
        result = scanner.scan(cluster)
        assert "CIS-K8S-002" not in [f.check_id for f in result.findings]

    def test_severity_is_high(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.etcd.encryption_config_file = None
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-002")
        assert finding.severity == "HIGH"

    def test_cis_reference_contains_1_2_31(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.etcd.encryption_config_file = None
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-002")
        assert "1.2.31" in finding.cis_reference

    def test_weight_applied(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.etcd.encryption_config_file = None
        result = scanner.scan(cluster)
        assert result.risk_score == _CHECK_WEIGHTS["CIS-K8S-002"]


# ---------------------------------------------------------------------------
# 4. CIS-K8S-003 — Kubelet read-only port
# ---------------------------------------------------------------------------


class TestCISK8S003:
    def test_triggers_on_default_port_10255(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kubelet.read_only_port = 10255
        result = scanner.scan(cluster)
        assert "CIS-K8S-003" in [f.check_id for f in result.findings]

    def test_does_not_trigger_on_zero(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kubelet.read_only_port = 0
        result = scanner.scan(cluster)
        assert "CIS-K8S-003" not in [f.check_id for f in result.findings]

    def test_triggers_on_other_nonzero_port(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kubelet.read_only_port = 9000
        result = scanner.scan(cluster)
        assert "CIS-K8S-003" in [f.check_id for f in result.findings]

    def test_triggers_on_port_1(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kubelet.read_only_port = 1
        result = scanner.scan(cluster)
        assert "CIS-K8S-003" in [f.check_id for f in result.findings]

    def test_severity_is_high(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kubelet.read_only_port = 10255
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-003")
        assert finding.severity == "HIGH"

    def test_cis_reference_contains_4_2_4(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kubelet.read_only_port = 10255
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-003")
        assert "4.2.4" in finding.cis_reference

    def test_message_contains_port_number(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kubelet.read_only_port = 10255
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-003")
        assert "10255" in finding.message

    def test_weight_applied(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kubelet.read_only_port = 10255
        result = scanner.scan(cluster)
        assert result.risk_score == _CHECK_WEIGHTS["CIS-K8S-003"]


# ---------------------------------------------------------------------------
# 5. CIS-K8S-004 — API server audit logging
# ---------------------------------------------------------------------------


class TestCISK8S004:
    def test_triggers_when_audit_log_path_none(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.audit_log_path = None
        result = scanner.scan(cluster)
        assert "CIS-K8S-004" in [f.check_id for f in result.findings]

    def test_triggers_when_audit_policy_file_none(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.audit_policy_file = None
        result = scanner.scan(cluster)
        assert "CIS-K8S-004" in [f.check_id for f in result.findings]

    def test_triggers_when_both_none(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.audit_log_path = None
        cluster.api_server.audit_policy_file = None
        result = scanner.scan(cluster)
        assert "CIS-K8S-004" in [f.check_id for f in result.findings]

    def test_does_not_trigger_when_both_set(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.audit_log_path = "/var/log/audit.log"
        cluster.api_server.audit_policy_file = "/etc/k8s/audit-policy.yaml"
        result = scanner.scan(cluster)
        assert "CIS-K8S-004" not in [f.check_id for f in result.findings]

    def test_only_one_finding_when_both_missing(self, scanner: CISBenchmarkScanner) -> None:
        """Triggering both sub-conditions still produces exactly one CIS-K8S-004 finding."""
        cluster = _hardened_cluster()
        cluster.api_server.audit_log_path = None
        cluster.api_server.audit_policy_file = None
        result = scanner.scan(cluster)
        assert sum(1 for f in result.findings if f.check_id == "CIS-K8S-004") == 1

    def test_severity_is_high(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.audit_log_path = None
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-004")
        assert finding.severity == "HIGH"

    def test_cis_reference_contains_3_2(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.audit_log_path = None
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-004")
        assert "3.2" in finding.cis_reference

    def test_weight_applied(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.audit_log_path = None
        result = scanner.scan(cluster)
        assert result.risk_score == _CHECK_WEIGHTS["CIS-K8S-004"]


# ---------------------------------------------------------------------------
# 6. CIS-K8S-005 — API server TLS configuration
# ---------------------------------------------------------------------------


class TestCISK8S005:
    def test_triggers_when_cert_none(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.tls_cert_file = None
        result = scanner.scan(cluster)
        assert "CIS-K8S-005" in [f.check_id for f in result.findings]

    def test_triggers_when_key_none(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.tls_private_key_file = None
        result = scanner.scan(cluster)
        assert "CIS-K8S-005" in [f.check_id for f in result.findings]

    def test_triggers_when_both_none(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.tls_cert_file = None
        cluster.api_server.tls_private_key_file = None
        result = scanner.scan(cluster)
        assert "CIS-K8S-005" in [f.check_id for f in result.findings]

    def test_does_not_trigger_when_both_set(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.tls_cert_file = "/etc/kubernetes/pki/apiserver.crt"
        cluster.api_server.tls_private_key_file = "/etc/kubernetes/pki/apiserver.key"
        result = scanner.scan(cluster)
        assert "CIS-K8S-005" not in [f.check_id for f in result.findings]

    def test_only_one_finding_when_both_missing(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.tls_cert_file = None
        cluster.api_server.tls_private_key_file = None
        result = scanner.scan(cluster)
        assert sum(1 for f in result.findings if f.check_id == "CIS-K8S-005") == 1

    def test_severity_is_critical(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.tls_cert_file = None
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-005")
        assert finding.severity == "CRITICAL"

    def test_cis_reference_contains_1_2_26(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.tls_cert_file = None
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-005")
        assert "1.2.26" in finding.cis_reference

    def test_weight_applied(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.tls_cert_file = None
        result = scanner.scan(cluster)
        assert result.risk_score == _CHECK_WEIGHTS["CIS-K8S-005"]


# ---------------------------------------------------------------------------
# 7. CIS-K8S-006 — PodSecurity admission controller
# ---------------------------------------------------------------------------


class TestCISK8S006:
    def test_triggers_on_false(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.pod_security_admission_enabled = False
        result = scanner.scan(cluster)
        assert "CIS-K8S-006" in [f.check_id for f in result.findings]

    def test_does_not_trigger_on_true(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.pod_security_admission_enabled = True
        result = scanner.scan(cluster)
        assert "CIS-K8S-006" not in [f.check_id for f in result.findings]

    def test_severity_is_high(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.pod_security_admission_enabled = False
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-006")
        assert finding.severity == "HIGH"

    def test_cis_reference_contains_5_2(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.pod_security_admission_enabled = False
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-006")
        assert "5.2" in finding.cis_reference

    def test_weight_applied(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.pod_security_admission_enabled = False
        result = scanner.scan(cluster)
        assert result.risk_score == _CHECK_WEIGHTS["CIS-K8S-006"]

    def test_remediation_is_not_empty(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.pod_security_admission_enabled = False
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-006")
        assert finding.remediation != ""


# ---------------------------------------------------------------------------
# 8. CIS-K8S-007 — kube-system SA token automounting
# ---------------------------------------------------------------------------


class TestCISK8S007:
    def test_triggers_on_true(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kube_system_sa_automount = True
        result = scanner.scan(cluster)
        assert "CIS-K8S-007" in [f.check_id for f in result.findings]

    def test_does_not_trigger_on_false(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kube_system_sa_automount = False
        result = scanner.scan(cluster)
        assert "CIS-K8S-007" not in [f.check_id for f in result.findings]

    def test_severity_is_medium(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kube_system_sa_automount = True
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-007")
        assert finding.severity == "MEDIUM"

    def test_cis_reference_contains_5_1_5(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kube_system_sa_automount = True
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-007")
        assert "5.1.5" in finding.cis_reference

    def test_weight_applied(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kube_system_sa_automount = True
        result = scanner.scan(cluster)
        assert result.risk_score == _CHECK_WEIGHTS["CIS-K8S-007"]

    def test_remediation_is_not_empty(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kube_system_sa_automount = True
        result = scanner.scan(cluster)
        finding = next(f for f in result.findings if f.check_id == "CIS-K8S-007")
        assert finding.remediation != ""


# ---------------------------------------------------------------------------
# 9. Score arithmetic
# ---------------------------------------------------------------------------


class TestScoreArithmetic:
    def test_compliance_score_equals_100_minus_risk(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kubelet.read_only_port = 10255  # weight 20
        result = scanner.scan(cluster)
        assert result.compliance_score == 100 - result.risk_score

    def test_two_findings_sum_weights(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kubelet.read_only_port = 10255           # weight 20
        cluster.etcd.encryption_config_file = None       # weight 25
        result = scanner.scan(cluster)
        expected = _CHECK_WEIGHTS["CIS-K8S-003"] + _CHECK_WEIGHTS["CIS-K8S-002"]
        assert result.risk_score == expected
        assert result.compliance_score == 100 - expected

    def test_risk_score_capped_at_100(self, scanner: CISBenchmarkScanner) -> None:
        """Trigger checks whose weights sum beyond 100 and verify the cap."""
        cluster = _hardened_cluster()
        # Activate all 7 checks; sum of weights = 45+25+20+20+40+25+15 = 190
        cluster.api_server.anonymous_auth_enabled = True
        cluster.etcd.encryption_config_file = None
        cluster.kubelet.read_only_port = 10255
        cluster.api_server.audit_log_path = None
        cluster.api_server.tls_cert_file = None
        cluster.api_server.pod_security_admission_enabled = False
        cluster.kube_system_sa_automount = True
        result = scanner.scan(cluster)
        assert result.risk_score == 100

    def test_compliance_score_never_negative(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.anonymous_auth_enabled = True
        cluster.etcd.encryption_config_file = None
        cluster.kubelet.read_only_port = 10255
        cluster.api_server.audit_log_path = None
        cluster.api_server.tls_cert_file = None
        cluster.api_server.pod_security_admission_enabled = False
        cluster.kube_system_sa_automount = True
        result = scanner.scan(cluster)
        assert result.compliance_score >= 0

    def test_compliance_score_when_risk_zero(self, hardened: CISBenchmarkResult) -> None:
        assert hardened.compliance_score == 100

    def test_three_findings_weight_sum(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.anonymous_auth_enabled = True   # 45
        cluster.api_server.tls_cert_file = None            # 40
        cluster.etcd.encryption_config_file = ""           # 25
        result = scanner.scan(cluster)
        expected = min(100, 45 + 40 + 25)
        assert result.risk_score == expected

    def test_single_medium_finding_compliance(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kube_system_sa_automount = True  # weight 15
        result = scanner.scan(cluster)
        assert result.compliance_score == 85

    def test_unique_check_ids_deduplicated_in_scoring(self, scanner: CISBenchmarkScanner) -> None:
        """Duplicate check IDs (if ever produced) must not double-count weight."""
        cluster = _hardened_cluster()
        # Trigger audit check via only audit_log_path missing
        cluster.api_server.audit_log_path = None
        result = scanner.scan(cluster)
        # Regardless of sub-conditions, CIS-K8S-004 should appear at most once.
        count = sum(1 for f in result.findings if f.check_id == "CIS-K8S-004")
        assert count == 1
        assert result.risk_score == _CHECK_WEIGHTS["CIS-K8S-004"]


# ---------------------------------------------------------------------------
# 10. by_severity()
# ---------------------------------------------------------------------------


class TestBySeverity:
    def test_critical_findings_grouped(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.anonymous_auth_enabled = True  # CRITICAL
        result = scanner.scan(cluster)
        by_sev = result.by_severity()
        assert "CRITICAL" in by_sev
        assert any(f.check_id == "CIS-K8S-001" for f in by_sev["CRITICAL"])

    def test_high_findings_grouped(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.etcd.encryption_config_file = None  # HIGH
        result = scanner.scan(cluster)
        by_sev = result.by_severity()
        assert "HIGH" in by_sev

    def test_medium_findings_grouped(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kube_system_sa_automount = True  # MEDIUM
        result = scanner.scan(cluster)
        by_sev = result.by_severity()
        assert "MEDIUM" in by_sev
        assert any(f.check_id == "CIS-K8S-007" for f in by_sev["MEDIUM"])

    def test_no_cross_contamination(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kube_system_sa_automount = True  # MEDIUM only
        result = scanner.scan(cluster)
        by_sev = result.by_severity()
        assert "CRITICAL" not in by_sev
        assert "HIGH" not in by_sev

    def test_returns_dict(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        result = scanner.scan(cluster)
        assert isinstance(result.by_severity(), dict)

    def test_multiple_high_findings_all_present(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.etcd.encryption_config_file = None   # CIS-K8S-002 HIGH
        cluster.kubelet.read_only_port = 10255        # CIS-K8S-003 HIGH
        result = scanner.scan(cluster)
        high_ids = {f.check_id for f in result.by_severity().get("HIGH", [])}
        assert "CIS-K8S-002" in high_ids
        assert "CIS-K8S-003" in high_ids


# ---------------------------------------------------------------------------
# 11. summary()
# ---------------------------------------------------------------------------


class TestSummary:
    def test_contains_cluster_name(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster("my-prod-cluster")
        result = scanner.scan(cluster)
        assert "my-prod-cluster" in result.summary()

    def test_contains_risk_score(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kube_system_sa_automount = True
        result = scanner.scan(cluster)
        assert "risk_score=15" in result.summary()

    def test_contains_compliance_score(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kube_system_sa_automount = True
        result = scanner.scan(cluster)
        assert "compliance_score=85" in result.summary()

    def test_contains_finding_count(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kube_system_sa_automount = True
        result = scanner.scan(cluster)
        assert "1 finding" in result.summary()

    def test_summary_returns_string(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        result = scanner.scan(cluster)
        assert isinstance(result.summary(), str)

    def test_both_scores_present_when_all_clear(self, hardened: CISBenchmarkResult) -> None:
        s = hardened.summary()
        assert "risk_score=0" in s
        assert "compliance_score=100" in s


# ---------------------------------------------------------------------------
# 12. scan_many()
# ---------------------------------------------------------------------------


class TestScanMany:
    def test_returns_list(self, scanner: CISBenchmarkScanner) -> None:
        result = scanner.scan_many([_hardened_cluster("a"), _hardened_cluster("b")])
        assert isinstance(result, list)

    def test_returns_correct_length(self, scanner: CISBenchmarkScanner) -> None:
        clusters = [_hardened_cluster(f"c{i}") for i in range(5)]
        results = scanner.scan_many(clusters)
        assert len(results) == 5

    def test_each_element_is_result(self, scanner: CISBenchmarkScanner) -> None:
        results = scanner.scan_many([_hardened_cluster("x")])
        assert all(isinstance(r, CISBenchmarkResult) for r in results)

    def test_empty_list(self, scanner: CISBenchmarkScanner) -> None:
        assert scanner.scan_many([]) == []

    def test_cluster_names_preserved(self, scanner: CISBenchmarkScanner) -> None:
        names = ["alpha", "beta", "gamma"]
        results = scanner.scan_many([_hardened_cluster(n) for n in names])
        assert [r.cluster_name for r in results] == names

    def test_heterogeneous_configs(self, scanner: CISBenchmarkScanner) -> None:
        good = _hardened_cluster("good")
        bad = _hardened_cluster("bad")
        bad.api_server.anonymous_auth_enabled = True
        results = scanner.scan_many([good, bad])
        assert results[0].risk_score == 0
        assert results[1].risk_score == _CHECK_WEIGHTS["CIS-K8S-001"]


# ---------------------------------------------------------------------------
# 13. to_dict() for all dataclasses
# ---------------------------------------------------------------------------


class TestToDict:
    def test_api_server_config_to_dict_keys(self) -> None:
        d = APIServerConfig().to_dict()
        expected_keys = {
            "anonymous_auth_enabled", "tls_cert_file", "tls_private_key_file",
            "audit_log_path", "audit_policy_file", "authorization_mode",
            "insecure_port", "pod_security_admission_enabled",
        }
        assert set(d.keys()) == expected_keys

    def test_etcd_config_to_dict_keys(self) -> None:
        d = EtcdConfig().to_dict()
        assert set(d.keys()) == {"encryption_config_file", "tls_cert_file", "tls_key_file"}

    def test_kubelet_config_to_dict_keys(self) -> None:
        d = KubeletConfig().to_dict()
        expected_keys = {"read_only_port", "anonymous_auth_enabled",
                         "authorization_mode", "rotate_certificates"}
        assert set(d.keys()) == expected_keys

    def test_cluster_config_to_dict_keys(self) -> None:
        d = ClusterConfig(name="test").to_dict()
        assert set(d.keys()) == {"name", "api_server", "etcd", "kubelet",
                                  "kube_system_sa_automount"}

    def test_cluster_config_to_dict_nested(self) -> None:
        d = ClusterConfig(name="test").to_dict()
        assert isinstance(d["api_server"], dict)
        assert isinstance(d["etcd"], dict)
        assert isinstance(d["kubelet"], dict)

    def test_cis_finding_to_dict_keys(self) -> None:
        f = CISFinding(
            check_id="CIS-K8S-001",
            cis_reference="CIS 1.2.1",
            severity="CRITICAL",
            title="Test",
            message="msg",
            remediation="rem",
        )
        d = f.to_dict()
        assert set(d.keys()) == {
            "check_id", "cis_reference", "severity", "title", "message", "remediation"
        }

    def test_cis_finding_to_dict_values(self) -> None:
        f = CISFinding(
            check_id="CIS-K8S-007",
            cis_reference="CIS 5.1.5",
            severity="MEDIUM",
            title="SA automount",
            message="details",
            remediation="fix it",
        )
        d = f.to_dict()
        assert d["check_id"] == "CIS-K8S-007"
        assert d["severity"] == "MEDIUM"

    def test_benchmark_result_to_dict_keys(self, scanner: CISBenchmarkScanner) -> None:
        result = scanner.scan(_hardened_cluster())
        d = result.to_dict()
        assert set(d.keys()) == {
            "cluster_name", "findings", "risk_score", "compliance_score", "summary"
        }

    def test_benchmark_result_to_dict_findings_are_dicts(
        self, scanner: CISBenchmarkScanner
    ) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.anonymous_auth_enabled = True
        result = scanner.scan(cluster)
        d = result.to_dict()
        assert all(isinstance(f, dict) for f in d["findings"])

    def test_benchmark_result_to_dict_scores_correct(
        self, scanner: CISBenchmarkScanner
    ) -> None:
        cluster = _hardened_cluster()
        cluster.kube_system_sa_automount = True
        result = scanner.scan(cluster)
        d = result.to_dict()
        assert d["risk_score"] == 15
        assert d["compliance_score"] == 85

    def test_api_server_config_roundtrip(self) -> None:
        cfg = APIServerConfig(
            anonymous_auth_enabled=True,
            tls_cert_file="/cert",
            tls_private_key_file="/key",
            audit_log_path="/log",
            audit_policy_file="/policy",
            authorization_mode="AlwaysAllow",
            insecure_port=8080,
            pod_security_admission_enabled=False,
        )
        d = cfg.to_dict()
        assert d["anonymous_auth_enabled"] is True
        assert d["tls_cert_file"] == "/cert"
        assert d["insecure_port"] == 8080
        assert d["pod_security_admission_enabled"] is False


# ---------------------------------------------------------------------------
# 14. CIS reference field — populated in every possible finding
# ---------------------------------------------------------------------------


class TestCISReferences:
    """Every check must set a non-empty cis_reference when fired."""

    def _fire_all(self, scanner: CISBenchmarkScanner) -> CISBenchmarkResult:
        cluster = _hardened_cluster()
        cluster.api_server.anonymous_auth_enabled = True
        cluster.etcd.encryption_config_file = None
        cluster.kubelet.read_only_port = 10255
        cluster.api_server.audit_log_path = None
        cluster.api_server.tls_cert_file = None
        cluster.api_server.pod_security_admission_enabled = False
        cluster.kube_system_sa_automount = True
        return scanner.scan(cluster)

    def test_all_findings_have_cis_reference(self, scanner: CISBenchmarkScanner) -> None:
        result = self._fire_all(scanner)
        for f in result.findings:
            assert f.cis_reference != "", f"Empty cis_reference on {f.check_id}"

    def test_all_seven_checks_fire(self, scanner: CISBenchmarkScanner) -> None:
        result = self._fire_all(scanner)
        fired = {f.check_id for f in result.findings}
        expected = {f"CIS-K8S-{i:03d}" for i in range(1, 8)}
        assert fired == expected

    def test_001_cis_reference(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.anonymous_auth_enabled = True
        f = next(x for x in scanner.scan(cluster).findings if x.check_id == "CIS-K8S-001")
        assert f.cis_reference

    def test_002_cis_reference(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.etcd.encryption_config_file = None
        f = next(x for x in scanner.scan(cluster).findings if x.check_id == "CIS-K8S-002")
        assert f.cis_reference

    def test_003_cis_reference(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kubelet.read_only_port = 10255
        f = next(x for x in scanner.scan(cluster).findings if x.check_id == "CIS-K8S-003")
        assert f.cis_reference

    def test_004_cis_reference(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.audit_log_path = None
        f = next(x for x in scanner.scan(cluster).findings if x.check_id == "CIS-K8S-004")
        assert f.cis_reference

    def test_005_cis_reference(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.tls_cert_file = None
        f = next(x for x in scanner.scan(cluster).findings if x.check_id == "CIS-K8S-005")
        assert f.cis_reference

    def test_006_cis_reference(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.pod_security_admission_enabled = False
        f = next(x for x in scanner.scan(cluster).findings if x.check_id == "CIS-K8S-006")
        assert f.cis_reference

    def test_007_cis_reference(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster()
        cluster.kube_system_sa_automount = True
        f = next(x for x in scanner.scan(cluster).findings if x.check_id == "CIS-K8S-007")
        assert f.cis_reference


# ---------------------------------------------------------------------------
# 15. Edge-cases / boundary conditions
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_default_cluster_config_has_findings(self, scanner: CISBenchmarkScanner) -> None:
        """Default ClusterConfig (all defaults) should trigger several checks."""
        cluster = ClusterConfig(name="default-cluster")
        result = scanner.scan(cluster)
        # kube_system_sa_automount defaults True -> at least CIS-K8S-007 fires,
        # and TLS defaults to None -> CIS-K8S-005, audit -> CIS-K8S-004,
        # etcd encryption -> CIS-K8S-002
        assert len(result.findings) > 0

    def test_risk_score_type_is_int(self, scanner: CISBenchmarkScanner) -> None:
        result = scanner.scan(_hardened_cluster())
        assert isinstance(result.risk_score, int)

    def test_compliance_score_type_is_int(self, scanner: CISBenchmarkScanner) -> None:
        result = scanner.scan(_hardened_cluster())
        assert isinstance(result.compliance_score, int)

    def test_findings_list_is_list(self, scanner: CISBenchmarkScanner) -> None:
        result = scanner.scan(_hardened_cluster())
        assert isinstance(result.findings, list)

    def test_scan_returns_benchmark_result(self, scanner: CISBenchmarkScanner) -> None:
        result = scanner.scan(_hardened_cluster())
        assert isinstance(result, CISBenchmarkResult)

    def test_check_weights_has_seven_entries(self) -> None:
        assert len(_CHECK_WEIGHTS) == 7

    def test_all_check_ids_present_in_weights(self) -> None:
        for i in range(1, 8):
            assert f"CIS-K8S-{i:03d}" in _CHECK_WEIGHTS

    def test_risk_score_never_exceeds_100(self, scanner: CISBenchmarkScanner) -> None:
        cluster = ClusterConfig(name="worst-case")
        cluster.api_server = APIServerConfig(
            anonymous_auth_enabled=True,
            tls_cert_file=None,
            tls_private_key_file=None,
            audit_log_path=None,
            audit_policy_file=None,
            pod_security_admission_enabled=False,
        )
        cluster.etcd = EtcdConfig(encryption_config_file=None)
        cluster.kubelet = KubeletConfig(read_only_port=10255)
        cluster.kube_system_sa_automount = True
        result = scanner.scan(cluster)
        assert result.risk_score <= 100

    def test_cluster_name_in_result(self, scanner: CISBenchmarkScanner) -> None:
        cluster = _hardened_cluster("special-name-cluster")
        result = scanner.scan(cluster)
        assert result.cluster_name == "special-name-cluster"

    def test_etcd_empty_string_triggers_002(self, scanner: CISBenchmarkScanner) -> None:
        """Explicitly verify empty string (not None) also triggers CIS-K8S-002."""
        cluster = _hardened_cluster()
        cluster.etcd.encryption_config_file = ""
        result = scanner.scan(cluster)
        assert any(f.check_id == "CIS-K8S-002" for f in result.findings)

    def test_compliance_and_risk_always_sum_to_100_or_less(
        self, scanner: CISBenchmarkScanner
    ) -> None:
        cluster = _hardened_cluster()
        cluster.api_server.anonymous_auth_enabled = True
        result = scanner.scan(cluster)
        assert result.risk_score + result.compliance_score == 100
