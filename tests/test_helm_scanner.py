"""Unit tests for Helm chart security scanner."""
import textwrap
from pathlib import Path

import pytest

from validators.helm_scanner import (
    HelmScanResult,
    Severity,
    scan_chart,
    scan_values_file,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_values(tmp_path: Path, content: str) -> Path:
    """Write a values.yaml to a temp directory and return its path."""
    p = tmp_path / "values.yaml"
    p.write_text(textwrap.dedent(content))
    return p


def _make_chart(tmp_path: Path, values_content: str, chart_name: str = "testchart") -> Path:
    """Create a minimal chart directory structure for testing."""
    chart_dir = tmp_path / chart_name
    chart_dir.mkdir()
    (chart_dir / "Chart.yaml").write_text(f"name: {chart_name}\nversion: 0.1.0\n")
    (chart_dir / "values.yaml").write_text(textwrap.dedent(values_content))
    (chart_dir / "templates").mkdir()
    return chart_dir


# ---------------------------------------------------------------------------
# Image tag checks
# ---------------------------------------------------------------------------


def test_latest_tag_flagged(tmp_path):
    p = _write_values(tmp_path, """
        image:
          repository: myapp
          tag: latest
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
        resources:
          limits:
            memory: 256Mi
            cpu: 500m
        serviceAccount:
          automountServiceAccountToken: false
    """)
    result = scan_values_file(p, "testchart")
    ids = [f.rule_id for f in result.findings]
    assert "HELM001" in ids


def test_no_tag_flagged(tmp_path):
    p = _write_values(tmp_path, """
        image:
          repository: myapp
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
        resources:
          limits:
            memory: 256Mi
            cpu: 500m
        serviceAccount:
          automountServiceAccountToken: false
    """)
    result = scan_values_file(p, "testchart")
    ids = [f.rule_id for f in result.findings]
    assert "HELM001" in ids


def test_pinned_tag_no_flag(tmp_path):
    p = _write_values(tmp_path, """
        image:
          repository: myapp
          tag: "1.2.3"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
        resources:
          limits:
            memory: 256Mi
            cpu: 500m
        serviceAccount:
          automountServiceAccountToken: false
    """)
    result = scan_values_file(p, "testchart")
    ids = [f.rule_id for f in result.findings]
    assert "HELM001" not in ids


# ---------------------------------------------------------------------------
# Security context checks
# ---------------------------------------------------------------------------


def test_privileged_is_critical(tmp_path):
    p = _write_values(tmp_path, """
        image:
          tag: "1.0.0"
        securityContext:
          privileged: true
    """)
    result = scan_values_file(p, "testchart")
    critical = [f for f in result.findings if f.rule_id == "HELM002"]
    assert critical
    assert critical[0].severity == Severity.CRITICAL


def test_privilege_escalation_flagged(tmp_path):
    p = _write_values(tmp_path, """
        image:
          tag: "1.0.0"
        securityContext: {}
    """)
    result = scan_values_file(p, "testchart")
    ids = [f.rule_id for f in result.findings]
    assert "HELM003" in ids


def test_root_uid_flagged(tmp_path):
    p = _write_values(tmp_path, """
        image:
          tag: "1.0.0"
        securityContext:
          runAsUser: 0
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: false
    """)
    result = scan_values_file(p, "testchart")
    ids = [f.rule_id for f in result.findings]
    assert "HELM006" in ids


# ---------------------------------------------------------------------------
# Resource limits
# ---------------------------------------------------------------------------


def test_missing_limits_flagged(tmp_path):
    p = _write_values(tmp_path, """
        image:
          tag: "1.0.0"
        resources: {}
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
        serviceAccount:
          automountServiceAccountToken: false
    """)
    result = scan_values_file(p, "testchart")
    ids = [f.rule_id for f in result.findings]
    assert "HELM007" in ids


def test_partial_limits_flagged(tmp_path):
    p = _write_values(tmp_path, """
        image:
          tag: "1.0.0"
        resources:
          limits:
            memory: 256Mi
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
        serviceAccount:
          automountServiceAccountToken: false
    """)
    result = scan_values_file(p, "testchart")
    ids = [f.rule_id for f in result.findings]
    assert "HELM009" in ids
    assert "HELM008" not in ids


# ---------------------------------------------------------------------------
# Credential detection
# ---------------------------------------------------------------------------


def test_hardcoded_password_flagged(tmp_path):
    p = _write_values(tmp_path, """
        image:
          tag: "1.0.0"
        database:
          password: "SuperSecret123"
    """)
    result = scan_values_file(p, "testchart")
    cred_findings = [f for f in result.findings if f.rule_id == "HELM013"]
    assert cred_findings
    assert cred_findings[0].severity == Severity.CRITICAL


def test_placeholder_password_not_flagged(tmp_path):
    p = _write_values(tmp_path, """
        image:
          tag: "1.0.0"
        database:
          password: ""
    """)
    result = scan_values_file(p, "testchart")
    ids = [f.rule_id for f in result.findings]
    assert "HELM013" not in ids


# ---------------------------------------------------------------------------
# Service account automount
# ---------------------------------------------------------------------------


def test_automount_not_false_flagged(tmp_path):
    p = _write_values(tmp_path, """
        image:
          tag: "1.0.0"
        serviceAccount:
          create: true
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
        resources:
          limits:
            memory: 256Mi
            cpu: 500m
    """)
    result = scan_values_file(p, "testchart")
    ids = [f.rule_id for f in result.findings]
    assert "HELM010" in ids


# ---------------------------------------------------------------------------
# Chart scan (directory-level)
# ---------------------------------------------------------------------------


def test_scan_chart_reads_chart_name(tmp_path):
    chart_dir = _make_chart(tmp_path, """
        image:
          tag: "1.0.0"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
        resources:
          limits:
            memory: 128Mi
            cpu: 200m
        serviceAccount:
          automountServiceAccountToken: false
    """, chart_name="myapp")
    result = scan_chart(chart_dir)
    assert result.chart_name == "myapp"


def test_scan_chart_detects_template_secret(tmp_path):
    chart_dir = _make_chart(tmp_path, "image:\n  tag: '1.0'\n", "secretchart")
    tmpl = chart_dir / "templates" / "secret.yaml"
    tmpl.write_text("data:\n  password: SuperHardcodedSecret123\n")
    result = scan_chart(chart_dir)
    ids = [f.rule_id for f in result.findings]
    assert "HELM014" in ids


def test_passed_property(tmp_path):
    """A chart with only INFO/MEDIUM findings should pass."""
    chart_dir = _make_chart(tmp_path, """
        image:
          tag: "2.0.0"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
        resources:
          limits:
            memory: 128Mi
        serviceAccount:
          automountServiceAccountToken: false
        service:
          type: LoadBalancer
    """, "goodchart")
    result = scan_chart(chart_dir)
    # LoadBalancer → INFO, missing cpu limit → LOW, none should be CRITICAL or HIGH
    # But HELM003 (allowPrivilegeEscalation) and HELM005 are explicitly set so should be clean
    high_or_critical = [f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert result.passed == (len(high_or_critical) == 0)
