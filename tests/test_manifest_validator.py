"""
Tests for validators.manifest_validator.

Each test writes a minimal YAML manifest to a temporary file,
runs validate_manifest(), and asserts the expected rule IDs are (or are not)
present in the findings.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from validators.manifest_validator import validate_manifest, Severity


def _write_manifest(tmp_path: Path, content: str) -> Path:
    """Helper: write a YAML string to a temp file and return its path."""
    p = tmp_path / "manifest.yaml"
    p.write_text(textwrap.dedent(content))
    return p


# ---------------------------------------------------------------------------
# SEC001 — privileged container
# ---------------------------------------------------------------------------
def test_privileged_detected(tmp_path: Path) -> None:
    """SEC001 is raised when a container has privileged: true."""
    manifest = _write_manifest(tmp_path, """\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: bad-deploy
        spec:
          template:
            spec:
              automountServiceAccountToken: false
              containers:
                - name: app
                  image: myapp:1.0
                  securityContext:
                    privileged: true
                    allowPrivilegeEscalation: false
                    readOnlyRootFilesystem: true
                    runAsNonRoot: true
                    capabilities:
                      drop: [ALL]
                  resources:
                    limits:
                      memory: "256Mi"
                      cpu: "500m"
    """)
    findings = validate_manifest(manifest)
    rule_ids = [f.rule_id for f in findings]
    assert "SEC001" in rule_ids, "Expected SEC001 for privileged container"


# ---------------------------------------------------------------------------
# Fully secure manifest — zero findings expected
# ---------------------------------------------------------------------------
def test_secure_manifest_passes(tmp_path: Path) -> None:
    """A manifest with all security context fields set correctly produces no findings."""
    manifest = _write_manifest(tmp_path, """\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: secure-deploy
        spec:
          template:
            spec:
              securityContext:
                seccompProfile:
                  type: RuntimeDefault
              automountServiceAccountToken: false
              containers:
                - name: app
                  image: myapp:1.0
                  securityContext:
                    privileged: false
                    allowPrivilegeEscalation: false
                    readOnlyRootFilesystem: true
                    runAsNonRoot: true
                    capabilities:
                      drop: [ALL]
                  resources:
                    requests:
                      memory: "128Mi"
                      cpu: "100m"
                    limits:
                      memory: "256Mi"
                      cpu: "500m"
    """)
    findings = validate_manifest(manifest)
    assert findings == [], (
        f"Expected 0 findings for secure manifest, got: {[f.rule_id for f in findings]}"
    )


# ---------------------------------------------------------------------------
# SEC006 / SEC007 — missing resource limits
# ---------------------------------------------------------------------------
def test_missing_resource_limits(tmp_path: Path) -> None:
    """SEC006 and SEC007 are raised when memory and CPU limits are absent."""
    manifest = _write_manifest(tmp_path, """\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: no-limits
        spec:
          template:
            spec:
              automountServiceAccountToken: false
              containers:
                - name: app
                  image: myapp:1.0
                  securityContext:
                    allowPrivilegeEscalation: false
                    readOnlyRootFilesystem: true
                    runAsNonRoot: true
                    capabilities:
                      drop: [ALL]
                  # Intentionally no resources block at all.
    """)
    findings = validate_manifest(manifest)
    rule_ids = [f.rule_id for f in findings]
    assert "SEC006" in rule_ids, "Expected SEC006 for missing memory limit"
    assert "SEC007" in rule_ids, "Expected SEC007 for missing CPU limit"


# ---------------------------------------------------------------------------
# SEC005 — capabilities not dropped
# ---------------------------------------------------------------------------
def test_no_capabilities_drop(tmp_path: Path) -> None:
    """SEC005 is raised when capabilities.drop does not include ALL."""
    manifest = _write_manifest(tmp_path, """\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: caps-missing
        spec:
          template:
            spec:
              automountServiceAccountToken: false
              containers:
                - name: app
                  image: myapp:1.0
                  securityContext:
                    allowPrivilegeEscalation: false
                    readOnlyRootFilesystem: true
                    runAsNonRoot: true
                    # capabilities block exists but does not drop ALL.
                    capabilities:
                      drop: [NET_RAW]
                  resources:
                    limits:
                      memory: "256Mi"
                      cpu: "500m"
    """)
    findings = validate_manifest(manifest)
    rule_ids = [f.rule_id for f in findings]
    assert "SEC005" in rule_ids, "Expected SEC005 when ALL is not in capabilities.drop"


def test_missing_seccomp_profile_detected(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path, """\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: no-seccomp
        spec:
          template:
            spec:
              automountServiceAccountToken: false
              containers:
                - name: app
                  image: myapp:1.0
                  securityContext:
                    allowPrivilegeEscalation: false
                    readOnlyRootFilesystem: true
                    runAsNonRoot: true
                    capabilities:
                      drop: [ALL]
                  resources:
                    limits:
                      memory: "256Mi"
                      cpu: "500m"
    """)
    findings = validate_manifest(manifest)
    seccomp_finding = next(f for f in findings if f.rule_id == "SEC009")
    assert seccomp_finding.severity == Severity.MEDIUM


def test_pod_level_seccomp_profile_passes(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path, """\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: pod-seccomp
        spec:
          template:
            spec:
              securityContext:
                seccompProfile:
                  type: RuntimeDefault
              automountServiceAccountToken: false
              containers:
                - name: app
                  image: myapp:1.0
                  securityContext:
                    allowPrivilegeEscalation: false
                    readOnlyRootFilesystem: true
                    runAsNonRoot: true
                    capabilities:
                      drop: [ALL]
                  resources:
                    limits:
                      memory: "256Mi"
                      cpu: "500m"
    """)
    findings = validate_manifest(manifest)
    rule_ids = [f.rule_id for f in findings]
    assert "SEC009" not in rule_ids


# ---------------------------------------------------------------------------
# SEC010 / SEC011 / SEC012 — host namespace sharing
# ---------------------------------------------------------------------------
def test_host_namespaces_flagged(tmp_path: Path) -> None:
    """Host PID, network, and IPC sharing should align with admission policies."""
    manifest = _write_manifest(tmp_path, """\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: host-ns
        spec:
          template:
            spec:
              automountServiceAccountToken: false
              hostPID: true
              hostNetwork: true
              hostIPC: true
              containers:
                - name: app
                  image: myapp:1.0
                  securityContext:
                    allowPrivilegeEscalation: false
                    readOnlyRootFilesystem: true
                    runAsNonRoot: true
                    capabilities:
                      drop: [ALL]
                  resources:
                    limits:
                      memory: "256Mi"
                      cpu: "500m"
    """)
    findings = validate_manifest(manifest)
    by_rule = {f.rule_id: f for f in findings}

    assert "SEC010" in by_rule, "Expected SEC010 for hostPID: true"
    assert "SEC011" in by_rule, "Expected SEC011 for hostNetwork: true"
    assert "SEC012" in by_rule, "Expected SEC012 for hostIPC: true"
    assert by_rule["SEC010"].severity == Severity.CRITICAL
    assert by_rule["SEC011"].severity == Severity.CRITICAL
    assert by_rule["SEC012"].severity == Severity.HIGH
