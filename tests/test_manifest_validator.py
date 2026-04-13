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
              automountServiceAccountToken: false
              securityContext:
                seccompProfile:
                  type: RuntimeDefault
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
# SEC004 — non-root execution
# ---------------------------------------------------------------------------
def test_run_as_user_zero_flagged(tmp_path: Path) -> None:
    """SEC004 is raised when a container explicitly runs as UID 0 (root)."""
    manifest = _write_manifest(tmp_path, """\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: uid-zero
        spec:
          template:
            spec:
              automountServiceAccountToken: false
              securityContext:
                seccompProfile:
                  type: RuntimeDefault
              containers:
                - name: app
                  image: myapp:1.0
                  securityContext:
                    privileged: false
                    allowPrivilegeEscalation: false
                    readOnlyRootFilesystem: true
                    runAsNonRoot: true
                    runAsUser: 0
                    capabilities:
                      drop: [ALL]
                  resources:
                    limits:
                      memory: "256Mi"
                      cpu: "500m"
    """)
    findings = validate_manifest(manifest)
    assert [f.rule_id for f in findings] == ["SEC004"]
    assert findings[0].severity == Severity.HIGH
    assert findings[0].path.endswith(".securityContext.runAsUser")


def test_pod_level_run_as_user_zero_flagged(tmp_path: Path) -> None:
    """SEC004 is raised when the pod security context sets runAsUser: 0."""
    manifest = _write_manifest(tmp_path, """\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: uid-zero-pod
        spec:
          template:
            spec:
              automountServiceAccountToken: false
              securityContext:
                seccompProfile:
                  type: RuntimeDefault
                runAsUser: 0
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
                    limits:
                      memory: "256Mi"
                      cpu: "500m"
    """)
    findings = validate_manifest(manifest)
    assert [f.rule_id for f in findings] == ["SEC004"]
    assert findings[0].severity == Severity.HIGH
    assert findings[0].path.endswith(".securityContext.runAsUser") or findings[0].path.endswith(".runAsUser")


# ---------------------------------------------------------------------------
# SEC009 — missing or unsafe seccomp profile
# ---------------------------------------------------------------------------
def test_missing_seccomp_profile_flagged(tmp_path: Path) -> None:
    """SEC009 is raised when neither the container nor pod sets an approved seccomp profile."""
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
    by_rule = {f.rule_id: f for f in findings}

    assert "SEC009" in by_rule, "Expected SEC009 when seccompProfile.type is missing"
    assert by_rule["SEC009"].severity == Severity.MEDIUM


def test_pod_level_runtime_default_seccomp_profile_passes(tmp_path: Path) -> None:
    """SEC009 accepts a pod-level RuntimeDefault seccomp profile inherited by the container."""
    manifest = _write_manifest(tmp_path, """\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: pod-seccomp
        spec:
          template:
            spec:
              automountServiceAccountToken: false
              securityContext:
                seccompProfile:
                  type: RuntimeDefault
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
                    limits:
                      memory: "256Mi"
                      cpu: "500m"
    """)
    findings = validate_manifest(manifest)
    rule_ids = [f.rule_id for f in findings]

    assert "SEC009" not in rule_ids, "Did not expect SEC009 for inherited RuntimeDefault seccompProfile.type"


def test_localhost_seccomp_profile_passes(tmp_path: Path) -> None:
    """SEC009 accepts a reviewed Localhost seccomp profile."""
    manifest = _write_manifest(tmp_path, """\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: localhost-seccomp
        spec:
          template:
            spec:
              automountServiceAccountToken: false
              securityContext:
                seccompProfile:
                  type: Localhost
                  localhostProfile: profiles/runtime-seccomp.json
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
                    limits:
                      memory: "256Mi"
                      cpu: "500m"
    """)
    findings = validate_manifest(manifest)
    rule_ids = [f.rule_id for f in findings]

    assert "SEC009" not in rule_ids, "Did not expect SEC009 for Localhost seccompProfile.type"


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
              securityContext:
                seccompProfile:
                  type: RuntimeDefault
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
              securityContext:
                seccompProfile:
                  type: RuntimeDefault
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


# ---------------------------------------------------------------------------
# SEC013 — dangerous capabilities added
# ---------------------------------------------------------------------------
def test_dangerous_capability_add_is_flagged(tmp_path: Path) -> None:
    """SEC013 is raised when a container adds a dangerous Linux capability."""
    manifest = _write_manifest(tmp_path, """\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: dangerous-cap
        spec:
          template:
            spec:
              automountServiceAccountToken: false
              securityContext:
                seccompProfile:
                  type: RuntimeDefault
              containers:
                - name: app
                  image: myapp:1.0
                  securityContext:
                    allowPrivilegeEscalation: false
                    readOnlyRootFilesystem: true
                    runAsNonRoot: true
                    capabilities:
                      drop: [ALL]
                      add: [SYS_ADMIN]
                  resources:
                    limits:
                      memory: "256Mi"
                      cpu: "500m"
    """)
    findings = validate_manifest(manifest)
    by_rule = {f.rule_id: f for f in findings}

    assert "SEC013" in by_rule, "Expected SEC013 when a dangerous capability is added"
    assert by_rule["SEC013"].severity == Severity.CRITICAL
    assert "SYS_ADMIN" in by_rule["SEC013"].message


def test_non_dangerous_capability_add_is_allowed(tmp_path: Path) -> None:
    """SEC013 ignores non-dangerous capabilities so the validator stays precise."""
    manifest = _write_manifest(tmp_path, """\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: benign-cap
        spec:
          template:
            spec:
              automountServiceAccountToken: false
              securityContext:
                seccompProfile:
                  type: RuntimeDefault
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
                      add: [CHOWN]
                  resources:
                    limits:
                      memory: "256Mi"
                      cpu: "500m"
    """)
    findings = validate_manifest(manifest)
    rule_ids = [f.rule_id for f in findings]

    assert "SEC013" not in rule_ids, "Did not expect SEC013 for non-dangerous capability adds"


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
              securityContext:
                seccompProfile:
                  type: RuntimeDefault
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


def test_ephemeral_container_is_validated(tmp_path: Path) -> None:
    """Ephemeral containers should not bypass core security-context checks."""
    manifest = _write_manifest(tmp_path, """\
        apiVersion: v1
        kind: Pod
        metadata:
          name: debug-pod
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
                limits:
                  memory: "256Mi"
                  cpu: "500m"
          ephemeralContainers:
            - name: debugger
              image: busybox:1.36
              targetContainerName: app
              securityContext:
                privileged: true
                allowPrivilegeEscalation: false
                readOnlyRootFilesystem: true
                runAsNonRoot: true
                capabilities:
                  drop: [ALL]
    """)

    findings = validate_manifest(manifest)

    privileged_finding = next(f for f in findings if f.rule_id == "SEC001")
    assert privileged_finding.message == "Container 'debugger' runs as privileged"
    assert privileged_finding.path == "debug-pod.ephemeralContainers.debugger.securityContext.privileged"


def test_ephemeral_container_skips_resource_limit_checks(tmp_path: Path) -> None:
    """Ephemeral containers do not support resources, so limit findings should not fire."""
    manifest = _write_manifest(tmp_path, """\
        apiVersion: v1
        kind: Pod
        metadata:
          name: debug-pod
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
                limits:
                  memory: "256Mi"
                  cpu: "500m"
          ephemeralContainers:
            - name: debugger
              image: busybox:1.36
              targetContainerName: app
              securityContext:
                privileged: false
                allowPrivilegeEscalation: false
                readOnlyRootFilesystem: true
                runAsNonRoot: true
                capabilities:
                  drop: [ALL]
    """)

    findings = validate_manifest(manifest)
    rule_ids = {f.rule_id for f in findings}

    assert "SEC006" not in rule_ids
    assert "SEC007" not in rule_ids


# ---------------------------------------------------------------------------
# SEC014 — hostPath volumes
# ---------------------------------------------------------------------------
def test_hostpath_volume_flagged(tmp_path: Path) -> None:
    """SEC014 is raised when a workload declares a hostPath volume."""
    manifest = _write_manifest(tmp_path, """\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: hostpath-volume
        spec:
          template:
            spec:
              automountServiceAccountToken: false
              securityContext:
                seccompProfile:
                  type: RuntimeDefault
              containers:
                - name: app
                  image: myapp:1.0
                  volumeMounts:
                    - name: node-logs
                      mountPath: /host/var/log
                      readOnly: true
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
              volumes:
                - name: node-logs
                  hostPath:
                    path: /var/log
                    type: Directory
    """)
    findings = validate_manifest(manifest)
    by_rule = {f.rule_id: f for f in findings}

    assert "SEC014" in by_rule, "Expected SEC014 for hostPath volumes"
    assert by_rule["SEC014"].severity == Severity.HIGH
    assert "/var/log" in by_rule["SEC014"].message


def test_non_hostpath_volume_is_allowed(tmp_path: Path) -> None:
    """SEC014 does not fire for safer in-cluster volume types."""
    manifest = _write_manifest(tmp_path, """\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: emptydir-volume
        spec:
          template:
            spec:
              automountServiceAccountToken: false
              securityContext:
                seccompProfile:
                  type: RuntimeDefault
              containers:
                - name: app
                  image: myapp:1.0
                  volumeMounts:
                    - name: scratch
                      mountPath: /tmp/scratch
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
              volumes:
                - name: scratch
                  emptyDir: {}
    """)
    findings = validate_manifest(manifest)
    rule_ids = [f.rule_id for f in findings]

    assert "SEC014" not in rule_ids, "Did not expect SEC014 for emptyDir volumes"


# ---------------------------------------------------------------------------
# SEC015 — hostPort exposure
# ---------------------------------------------------------------------------
def test_hostport_is_flagged(tmp_path: Path) -> None:
    """SEC015 is raised when a container binds a hostPort."""
    manifest = _write_manifest(tmp_path, """\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: hostport
        spec:
          template:
            spec:
              automountServiceAccountToken: false
              securityContext:
                seccompProfile:
                  type: RuntimeDefault
              containers:
                - name: app
                  image: myapp:1.0
                  ports:
                    - name: http
                      containerPort: 8080
                      hostPort: 8080
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

    assert "SEC015" in by_rule, "Expected SEC015 for hostPort exposure"
    assert by_rule["SEC015"].severity == Severity.HIGH
    assert by_rule["SEC015"].path == "hostport.containers.app.ports[0].hostPort"


def test_container_port_without_hostport_is_allowed(tmp_path: Path) -> None:
    """SEC015 does not fire when only containerPort is set."""
    manifest = _write_manifest(tmp_path, """\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: no-hostport
        spec:
          template:
            spec:
              automountServiceAccountToken: false
              securityContext:
                seccompProfile:
                  type: RuntimeDefault
              containers:
                - name: app
                  image: myapp:1.0
                  ports:
                    - name: http
                      containerPort: 8080
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
    rule_ids = {f.rule_id for f in findings}

    assert "SEC015" not in rule_ids, "Did not expect SEC015 for containerPort-only"
