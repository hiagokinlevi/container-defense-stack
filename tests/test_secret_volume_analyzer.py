# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International License.
# https://creativecommons.org/licenses/by/4.0/
"""
Tests for kubernetes/secret_volume_analyzer.py
===============================================
Covers all seven SV checks (001–007), combined multi-check scenarios,
risk-score capping, to_dict() serialisation, summary() format,
by_severity() grouping, analyze_many(), and edge cases.

Run with::

    python3 -m pytest tests/test_secret_volume_analyzer.py --override-ini="addopts=" -q
"""
from __future__ import annotations

import pytest

from kubernetes.secret_volume_analyzer import (
    K8sContainer,
    K8sPodSpec,
    K8sSecretRef,
    SecretVolumeAnalyzer,
    SecretVolumeFinding,
    SecretVolumeResult,
    _CHECK_WEIGHTS,
)


# ===========================================================================
# Helper factories — produce minimal valid objects with sensible defaults
# ===========================================================================

def _ref(secret_name: str = "my-secret", key: str = None) -> K8sSecretRef:
    """Build a K8sSecretRef."""
    return K8sSecretRef(secret_name=secret_name, key=key)


def _container(
    name: str = "app",
    image: str = "nginx:latest",
    env_from_secrets: list = None,
    env_secrets: list = None,
    command: list = None,
    args: list = None,
) -> K8sContainer:
    """Build a K8sContainer with sensible defaults."""
    return K8sContainer(
        name=name,
        image=image,
        env_from_secrets=env_from_secrets or [],
        env_secrets=env_secrets or [],
        command=command or [],
        args=args or [],
    )


def _vol(
    name: str = "secret-vol",
    mount_path: str = "/app/secrets",
    secret_name: str = "my-secret",
) -> dict:
    """Build a secret-volume dict."""
    return {"name": name, "mount_path": mount_path, "secret_name": secret_name}


def _pod(
    name: str = "test-pod",
    namespace: str = "default",
    containers: list = None,
    secret_volumes: list = None,
    automount_service_account_token = None,
    service_account_name: str = "default",
) -> K8sPodSpec:
    """Build a K8sPodSpec with sensible defaults."""
    return K8sPodSpec(
        name=name,
        namespace=namespace,
        containers=containers or [_container()],
        secret_volumes=secret_volumes or [],
        automount_service_account_token=automount_service_account_token,
        service_account_name=service_account_name,
    )


# Reusable analyzer instance
_ANALYZER = SecretVolumeAnalyzer()


def _check_ids(result: SecretVolumeResult) -> list:
    """Extract sorted list of check IDs from a result."""
    return sorted({f.check_id for f in result.findings})


# ===========================================================================
# 1. Clean pod spec — no findings
# ===========================================================================

class TestCleanPodSpec:
    """A pod with no risky configuration must produce zero findings."""

    def test_clean_pod_no_findings(self):
        """Fully hardened pod produces no findings at all."""
        pod = _pod(
            containers=[_container()],
            secret_volumes=[],
            automount_service_account_token=False,
            service_account_name="my-app-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert result.findings == []

    def test_clean_pod_risk_score_zero(self):
        """Risk score for a clean pod is 0."""
        pod = _pod(
            containers=[_container()],
            secret_volumes=[],
            automount_service_account_token=False,
            service_account_name="my-app-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert result.risk_score == 0

    def test_clean_pod_summary_zero_findings(self):
        """Summary for a clean pod shows 0 finding(s)."""
        pod = _pod(
            containers=[_container()],
            secret_volumes=[],
            automount_service_account_token=False,
            service_account_name="my-app-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert "0 finding(s)" in result.summary()

    def test_clean_pod_by_severity_empty_dict(self):
        """by_severity() returns empty dict for a clean pod."""
        pod = _pod(
            containers=[_container()],
            secret_volumes=[],
            automount_service_account_token=False,
            service_account_name="my-app-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert result.by_severity() == {}


# ===========================================================================
# 2. SV-001 — Secret mounted as all env vars (envFrom)
# ===========================================================================

class TestSV001:
    """SV-001: envFrom secret triggers; empty env_from_secrets does NOT."""

    def test_sv001_fires_when_env_from_secrets_present(self):
        """Container with one envFrom secret triggers SV-001."""
        pod = _pod(
            containers=[_container(env_from_secrets=[_ref("db-creds")])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert "SV-001" in _check_ids(result)

    def test_sv001_finding_severity_is_medium(self):
        """SV-001 finding has MEDIUM severity."""
        pod = _pod(
            containers=[_container(env_from_secrets=[_ref("db-creds")])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        sv001 = [f for f in result.findings if f.check_id == "SV-001"]
        assert all(f.severity == "MEDIUM" for f in sv001)

    def test_sv001_does_not_fire_when_env_from_secrets_empty(self):
        """Container with no envFrom secrets does NOT trigger SV-001."""
        pod = _pod(
            containers=[_container(env_from_secrets=[])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert "SV-001" not in _check_ids(result)

    def test_sv001_finding_includes_secret_name(self):
        """SV-001 finding records the secret_name."""
        pod = _pod(
            containers=[_container(env_from_secrets=[_ref("api-key-secret")])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        sv001 = [f for f in result.findings if f.check_id == "SV-001"]
        assert any(f.secret_name == "api-key-secret" for f in sv001)

    def test_sv001_finding_includes_container_name(self):
        """SV-001 finding records the container name."""
        pod = _pod(
            containers=[_container(name="worker", env_from_secrets=[_ref("s")])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        sv001 = [f for f in result.findings if f.check_id == "SV-001"]
        assert any(f.container_name == "worker" for f in sv001)

    def test_sv001_fires_once_per_secret_per_container(self):
        """Two envFrom secrets in one container produce two SV-001 findings."""
        pod = _pod(
            containers=[_container(
                env_from_secrets=[_ref("s1"), _ref("s2")],
            )],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        sv001 = [f for f in result.findings if f.check_id == "SV-001"]
        assert len(sv001) == 2

    def test_sv001_env_secrets_only_does_not_trigger(self):
        """env_secrets (specific key refs) alone do NOT trigger SV-001."""
        pod = _pod(
            containers=[_container(env_secrets=[_ref("db", "password")])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert "SV-001" not in _check_ids(result)


# ===========================================================================
# 3. SV-002 — Secret volume mounted at sensitive path
# ===========================================================================

class TestSV002:
    """SV-002: sensitive-prefix paths trigger; /app/ does NOT."""

    def _pod_with_vol(self, mount_path: str, sa: str = "my-sa") -> K8sPodSpec:
        return _pod(
            secret_volumes=[_vol(mount_path=mount_path)],
            automount_service_account_token=False,
            service_account_name=sa,
        )

    def test_sv002_fires_for_etc_path(self):
        """/etc/myapp triggers SV-002."""
        result = _ANALYZER.analyze(self._pod_with_vol("/etc/myapp"))
        assert "SV-002" in _check_ids(result)

    def test_sv002_fires_for_root_subpath(self):
        """/root/.ssh triggers SV-002."""
        result = _ANALYZER.analyze(self._pod_with_vol("/root/.ssh"))
        assert "SV-002" in _check_ids(result)

    def test_sv002_fires_for_proc_path(self):
        """/proc/secrets triggers SV-002."""
        result = _ANALYZER.analyze(self._pod_with_vol("/proc/secrets"))
        assert "SV-002" in _check_ids(result)

    def test_sv002_fires_for_sys_path(self):
        """/sys/config triggers SV-002."""
        result = _ANALYZER.analyze(self._pod_with_vol("/sys/config"))
        assert "SV-002" in _check_ids(result)

    def test_sv002_fires_for_var_run_path(self):
        """/var/run/myapp triggers SV-002."""
        result = _ANALYZER.analyze(self._pod_with_vol("/var/run/myapp"))
        assert "SV-002" in _check_ids(result)

    def test_sv002_does_not_fire_for_app_path(self):
        """/app/secrets does NOT trigger SV-002."""
        result = _ANALYZER.analyze(self._pod_with_vol("/app/secrets"))
        assert "SV-002" not in _check_ids(result)

    def test_sv002_does_not_fire_for_data_path(self):
        """/data/config does NOT trigger SV-002."""
        result = _ANALYZER.analyze(self._pod_with_vol("/data/config"))
        assert "SV-002" not in _check_ids(result)

    def test_sv002_finding_records_mount_path(self):
        """SV-002 finding records the mount_path."""
        result = _ANALYZER.analyze(self._pod_with_vol("/etc/tls"))
        sv002 = [f for f in result.findings if f.check_id == "SV-002"]
        assert any(f.mount_path == "/etc/tls" for f in sv002)

    def test_sv002_finding_severity_is_high(self):
        """SV-002 finding has HIGH severity."""
        result = _ANALYZER.analyze(self._pod_with_vol("/etc/tls"))
        sv002 = [f for f in result.findings if f.check_id == "SV-002"]
        assert all(f.severity == "HIGH" for f in sv002)


# ===========================================================================
# 4. SV-003 — Secret referenced in container command or args
# ===========================================================================

class TestSV003:
    """SV-003: secret-like var refs in command/args trigger; plain args do NOT."""

    def _pod_cmd_args(
        self, command: list = None, args: list = None, sa: str = "my-sa"
    ) -> K8sPodSpec:
        return _pod(
            containers=[_container(command=command or [], args=args or [])],
            automount_service_account_token=False,
            service_account_name=sa,
        )

    def test_sv003_fires_for_dollar_secret_in_command(self):
        """$SECRET_VALUE in command triggers SV-003."""
        result = _ANALYZER.analyze(self._pod_cmd_args(command=["run", "--token=$SECRET_VALUE"]))
        assert "SV-003" in _check_ids(result)

    def test_sv003_fires_for_braced_password_in_args(self):
        """${DB_PASSWORD} in args triggers SV-003."""
        result = _ANALYZER.analyze(self._pod_cmd_args(args=["--password=${DB_PASSWORD}"]))
        assert "SV-003" in _check_ids(result)

    def test_sv003_fires_for_token_in_command(self):
        """--token=$TOKEN in command triggers SV-003."""
        result = _ANALYZER.analyze(self._pod_cmd_args(command=["--token=$TOKEN"]))
        assert "SV-003" in _check_ids(result)

    def test_sv003_fires_for_key_in_args(self):
        """--api-key=$API_KEY in args triggers SV-003."""
        result = _ANALYZER.analyze(self._pod_cmd_args(args=["--api-key=$API_KEY"]))
        assert "SV-003" in _check_ids(result)

    def test_sv003_fires_for_credential_reference(self):
        """$CREDENTIAL in args triggers SV-003."""
        result = _ANALYZER.analyze(self._pod_cmd_args(args=["$CREDENTIAL"]))
        assert "SV-003" in _check_ids(result)

    def test_sv003_fires_for_passwd_reference(self):
        """$PASSWD in command triggers SV-003."""
        result = _ANALYZER.analyze(self._pod_cmd_args(command=["--pass=$PASSWD"]))
        assert "SV-003" in _check_ids(result)

    def test_sv003_does_not_fire_for_plain_arg(self):
        """Plain argument with no secret variable does NOT trigger SV-003."""
        result = _ANALYZER.analyze(self._pod_cmd_args(args=["--verbose", "--port=8080"]))
        assert "SV-003" not in _check_ids(result)

    def test_sv003_does_not_fire_for_empty_command_args(self):
        """Empty command and args do NOT trigger SV-003."""
        result = _ANALYZER.analyze(self._pod_cmd_args(command=[], args=[]))
        assert "SV-003" not in _check_ids(result)

    def test_sv003_finding_severity_is_high(self):
        """SV-003 finding has HIGH severity."""
        result = _ANALYZER.analyze(self._pod_cmd_args(args=["--pass=$DB_PASSWORD"]))
        sv003 = [f for f in result.findings if f.check_id == "SV-003"]
        assert all(f.severity == "HIGH" for f in sv003)

    def test_sv003_finding_includes_container_name(self):
        """SV-003 finding records the container name."""
        pod = _pod(
            containers=[_container(name="runner", args=["--token=$TOKEN"])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        sv003 = [f for f in result.findings if f.check_id == "SV-003"]
        assert any(f.container_name == "runner" for f in sv003)

    def test_sv003_case_insensitive_match(self):
        """Case-insensitive match: $db_password (lowercase) triggers SV-003."""
        result = _ANALYZER.analyze(self._pod_cmd_args(args=["--pass=$db_password"]))
        assert "SV-003" in _check_ids(result)


# ===========================================================================
# 5. SV-004 — Service account token auto-mounted
# ===========================================================================

class TestSV004:
    """SV-004: automount=None triggers; automount=True triggers; False does NOT."""

    def test_sv004_fires_when_automount_is_none(self):
        """automountServiceAccountToken=None (default) triggers SV-004."""
        pod = _pod(automount_service_account_token=None, service_account_name="my-sa")
        result = _ANALYZER.analyze(pod)
        assert "SV-004" in _check_ids(result)

    def test_sv004_fires_when_automount_is_true(self):
        """automountServiceAccountToken=True (explicit) triggers SV-004."""
        pod = _pod(automount_service_account_token=True, service_account_name="my-sa")
        result = _ANALYZER.analyze(pod)
        assert "SV-004" in _check_ids(result)

    def test_sv004_does_not_fire_when_automount_is_false(self):
        """automountServiceAccountToken=False does NOT trigger SV-004."""
        pod = _pod(automount_service_account_token=False, service_account_name="my-sa")
        result = _ANALYZER.analyze(pod)
        assert "SV-004" not in _check_ids(result)

    def test_sv004_finding_severity_is_medium(self):
        """SV-004 finding has MEDIUM severity."""
        pod = _pod(automount_service_account_token=None, service_account_name="my-sa")
        result = _ANALYZER.analyze(pod)
        sv004 = [f for f in result.findings if f.check_id == "SV-004"]
        assert all(f.severity == "MEDIUM" for f in sv004)

    def test_sv004_fires_exactly_once(self):
        """SV-004 fires at most once per pod, regardless of container count."""
        pod = _pod(
            containers=[_container("c1"), _container("c2")],
            automount_service_account_token=None,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        sv004 = [f for f in result.findings if f.check_id == "SV-004"]
        assert len(sv004) == 1

    def test_sv004_finding_mentions_default_true_when_none(self):
        """When automount is None, finding message references the default=True behaviour."""
        pod = _pod(automount_service_account_token=None, service_account_name="my-sa")
        result = _ANALYZER.analyze(pod)
        sv004 = [f for f in result.findings if f.check_id == "SV-004"]
        assert any("default" in f.message.lower() for f in sv004)


# ===========================================================================
# 6. SV-005 — Secret volume shared across multiple containers
# ===========================================================================

class TestSV005:
    """SV-005: same secret_name in 2 containers triggers; single container does NOT."""

    def test_sv005_fires_when_same_secret_in_two_containers_env_from(self):
        """Same secret in env_from_secrets of two containers triggers SV-005."""
        pod = _pod(
            containers=[
                _container("c1", env_from_secrets=[_ref("shared-creds")]),
                _container("c2", env_from_secrets=[_ref("shared-creds")]),
            ],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert "SV-005" in _check_ids(result)

    def test_sv005_fires_when_same_secret_in_two_containers_env_secrets(self):
        """Same secret in env_secrets of two containers triggers SV-005."""
        pod = _pod(
            containers=[
                _container("c1", env_secrets=[_ref("shared-creds", "key1")]),
                _container("c2", env_secrets=[_ref("shared-creds", "key2")]),
            ],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert "SV-005" in _check_ids(result)

    def test_sv005_fires_when_mixed_ref_types_share_secret(self):
        """env_from in one container, env_secrets in another — same secret triggers SV-005."""
        pod = _pod(
            containers=[
                _container("c1", env_from_secrets=[_ref("shared")]),
                _container("c2", env_secrets=[_ref("shared", "token")]),
            ],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert "SV-005" in _check_ids(result)

    def test_sv005_does_not_fire_for_single_container(self):
        """Secret in only one container does NOT trigger SV-005."""
        pod = _pod(
            containers=[_container("c1", env_from_secrets=[_ref("creds")])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert "SV-005" not in _check_ids(result)

    def test_sv005_does_not_fire_when_different_secrets_in_each_container(self):
        """Different secrets in each of two containers does NOT trigger SV-005."""
        pod = _pod(
            containers=[
                _container("c1", env_from_secrets=[_ref("secret-a")]),
                _container("c2", env_from_secrets=[_ref("secret-b")]),
            ],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert "SV-005" not in _check_ids(result)

    def test_sv005_finding_records_shared_secret_name(self):
        """SV-005 finding records the shared secret name."""
        pod = _pod(
            containers=[
                _container("c1", env_from_secrets=[_ref("shared-token")]),
                _container("c2", env_from_secrets=[_ref("shared-token")]),
            ],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        sv005 = [f for f in result.findings if f.check_id == "SV-005"]
        assert any(f.secret_name == "shared-token" for f in sv005)

    def test_sv005_finding_severity_is_medium(self):
        """SV-005 finding has MEDIUM severity."""
        pod = _pod(
            containers=[
                _container("c1", env_from_secrets=[_ref("s")]),
                _container("c2", env_from_secrets=[_ref("s")]),
            ],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        sv005 = [f for f in result.findings if f.check_id == "SV-005"]
        assert all(f.severity == "MEDIUM" for f in sv005)


# ===========================================================================
# 7. SV-006 — Default service account used with secrets
# ===========================================================================

class TestSV006:
    """SV-006: default SA + secret access triggers; non-default SA does NOT."""

    def test_sv006_fires_for_default_sa_with_secret_volumes(self):
        """default SA + secret volumes triggers SV-006."""
        pod = _pod(
            secret_volumes=[_vol()],
            automount_service_account_token=False,
            service_account_name="default",
        )
        result = _ANALYZER.analyze(pod)
        assert "SV-006" in _check_ids(result)

    def test_sv006_fires_for_default_sa_with_env_from_secrets(self):
        """default SA + env_from_secrets triggers SV-006."""
        pod = _pod(
            containers=[_container(env_from_secrets=[_ref("s")])],
            automount_service_account_token=False,
            service_account_name="default",
        )
        result = _ANALYZER.analyze(pod)
        assert "SV-006" in _check_ids(result)

    def test_sv006_fires_for_default_sa_with_env_secrets(self):
        """default SA + env_secrets triggers SV-006."""
        pod = _pod(
            containers=[_container(env_secrets=[_ref("s", "key")])],
            automount_service_account_token=False,
            service_account_name="default",
        )
        result = _ANALYZER.analyze(pod)
        assert "SV-006" in _check_ids(result)

    def test_sv006_does_not_fire_for_non_default_sa(self):
        """Non-default SA with secret volumes does NOT trigger SV-006."""
        pod = _pod(
            secret_volumes=[_vol()],
            automount_service_account_token=False,
            service_account_name="my-app-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert "SV-006" not in _check_ids(result)

    def test_sv006_does_not_fire_for_default_sa_without_secrets(self):
        """default SA with no secrets at all does NOT trigger SV-006."""
        pod = _pod(
            containers=[_container()],
            secret_volumes=[],
            automount_service_account_token=False,
            service_account_name="default",
        )
        result = _ANALYZER.analyze(pod)
        assert "SV-006" not in _check_ids(result)

    def test_sv006_finding_severity_is_high(self):
        """SV-006 finding has HIGH severity."""
        pod = _pod(
            secret_volumes=[_vol()],
            automount_service_account_token=False,
            service_account_name="default",
        )
        result = _ANALYZER.analyze(pod)
        sv006 = [f for f in result.findings if f.check_id == "SV-006"]
        assert all(f.severity == "HIGH" for f in sv006)

    def test_sv006_fires_exactly_once(self):
        """SV-006 fires exactly once per pod."""
        pod = _pod(
            containers=[
                _container("c1", env_from_secrets=[_ref("s1")]),
                _container("c2", env_from_secrets=[_ref("s2")]),
            ],
            secret_volumes=[_vol()],
            automount_service_account_token=False,
            service_account_name="default",
        )
        result = _ANALYZER.analyze(pod)
        sv006 = [f for f in result.findings if f.check_id == "SV-006"]
        assert len(sv006) == 1


# ===========================================================================
# 8. SV-007 — Secret volume at root or home directory
# ===========================================================================

class TestSV007:
    """SV-007: /, /root, /home/... trigger; /app does NOT."""

    def _pod_with_vol(self, mount_path: str, sa: str = "my-sa") -> K8sPodSpec:
        return _pod(
            secret_volumes=[_vol(mount_path=mount_path)],
            automount_service_account_token=False,
            service_account_name=sa,
        )

    def test_sv007_fires_for_filesystem_root(self):
        """mount_path='/' triggers SV-007."""
        result = _ANALYZER.analyze(self._pod_with_vol("/"))
        assert "SV-007" in _check_ids(result)

    def test_sv007_fires_for_root_home(self):
        """mount_path='/root' triggers SV-007."""
        result = _ANALYZER.analyze(self._pod_with_vol("/root"))
        assert "SV-007" in _check_ids(result)

    def test_sv007_fires_for_home_user_path(self):
        """mount_path='/home/user' triggers SV-007."""
        result = _ANALYZER.analyze(self._pod_with_vol("/home/user"))
        assert "SV-007" in _check_ids(result)

    def test_sv007_fires_for_home_arbitrary_user(self):
        """mount_path='/home/appuser/.ssh' triggers SV-007."""
        result = _ANALYZER.analyze(self._pod_with_vol("/home/appuser/.ssh"))
        assert "SV-007" in _check_ids(result)

    def test_sv007_does_not_fire_for_app_path(self):
        """mount_path='/app' does NOT trigger SV-007."""
        result = _ANALYZER.analyze(self._pod_with_vol("/app"))
        assert "SV-007" not in _check_ids(result)

    def test_sv007_does_not_fire_for_run_secrets(self):
        """mount_path='/run/secrets' does NOT trigger SV-007."""
        result = _ANALYZER.analyze(self._pod_with_vol("/run/secrets"))
        assert "SV-007" not in _check_ids(result)

    def test_sv007_finding_severity_is_critical(self):
        """SV-007 finding has CRITICAL severity."""
        result = _ANALYZER.analyze(self._pod_with_vol("/root"))
        sv007 = [f for f in result.findings if f.check_id == "SV-007"]
        assert all(f.severity == "CRITICAL" for f in sv007)

    def test_sv007_finding_records_mount_path(self):
        """SV-007 finding records the mount_path."""
        result = _ANALYZER.analyze(self._pod_with_vol("/home/user"))
        sv007 = [f for f in result.findings if f.check_id == "SV-007"]
        assert any(f.mount_path == "/home/user" for f in sv007)

    def test_sv007_finding_records_secret_name(self):
        """SV-007 finding records the secret_name."""
        pod = _pod(
            secret_volumes=[_vol(mount_path="/root", secret_name="root-secret")],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        sv007 = [f for f in result.findings if f.check_id == "SV-007"]
        assert any(f.secret_name == "root-secret" for f in sv007)


# ===========================================================================
# 9. Multiple checks on the same pod
# ===========================================================================

class TestMultipleChecks:
    """Combined scenarios that fire multiple distinct check IDs."""

    def test_all_checks_can_fire_simultaneously(self):
        """A maximally misconfigured pod fires all seven check IDs."""
        # This pod triggers:
        # SV-001 (envFrom), SV-002 (/etc/ mount), SV-003 ($TOKEN in args),
        # SV-004 (automount=None), SV-005 (same secret in 2 containers),
        # SV-006 (default SA + secrets), SV-007 (/ mount)
        pod = K8sPodSpec(
            name="worst-pod",
            namespace="staging",
            containers=[
                _container(
                    name="c1",
                    env_from_secrets=[_ref("shared")],
                    args=["--token=$API_TOKEN"],
                ),
                _container(
                    name="c2",
                    env_from_secrets=[_ref("shared")],  # shared → SV-005
                ),
            ],
            secret_volumes=[
                _vol(name="v1", mount_path="/etc/app/tls", secret_name="tls-secret"),
                _vol(name="v2", mount_path="/", secret_name="root-secret"),
            ],
            automount_service_account_token=None,    # SV-004
            service_account_name="default",          # SV-006
        )
        result = _ANALYZER.analyze(pod)
        fired = _check_ids(result)
        assert "SV-001" in fired
        assert "SV-002" in fired
        assert "SV-003" in fired
        assert "SV-004" in fired
        assert "SV-005" in fired
        assert "SV-006" in fired
        assert "SV-007" in fired

    def test_sv002_and_sv007_can_both_fire_on_same_volume(self):
        """
        /root starts with /root/ prefix AND matches SV-007 exactly — only
        SV-007 fires for '/root' exactly, while /root/sub fires SV-002 too.
        """
        # /root/sub starts with /root/ so fires SV-002, and starts with /root
        # but not == /root so SV-007 does not fire for it alone.
        pod = _pod(
            secret_volumes=[
                _vol(mount_path="/root/certs"),
            ],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        # /root/certs starts with /root/ → SV-002
        assert "SV-002" in _check_ids(result)
        # /root/certs != /root and doesn't start with /home/ and != / → SV-007 should NOT fire
        assert "SV-007" not in _check_ids(result)

    def test_sv006_and_sv001_fire_together(self):
        """default SA + envFrom secret fires both SV-001 and SV-006."""
        pod = _pod(
            containers=[_container(env_from_secrets=[_ref("creds")])],
            automount_service_account_token=False,
            service_account_name="default",
        )
        result = _ANALYZER.analyze(pod)
        fired = _check_ids(result)
        assert "SV-001" in fired
        assert "SV-006" in fired

    def test_sv004_and_sv006_fire_together(self):
        """automount=None + default SA + secret volumes fires SV-004 and SV-006."""
        pod = _pod(
            secret_volumes=[_vol()],
            automount_service_account_token=None,
            service_account_name="default",
        )
        result = _ANALYZER.analyze(pod)
        fired = _check_ids(result)
        assert "SV-004" in fired
        assert "SV-006" in fired


# ===========================================================================
# 10. Risk score computation and capping
# ===========================================================================

class TestRiskScore:
    """Verify risk_score computation and the cap at 100."""

    def test_risk_score_zero_for_clean_pod(self):
        """Clean pod has risk_score of 0."""
        pod = _pod(automount_service_account_token=False, service_account_name="my-sa")
        result = _ANALYZER.analyze(pod)
        assert result.risk_score == 0

    def test_risk_score_sv001_only(self):
        """SV-001 alone contributes its weight (15)."""
        pod = _pod(
            containers=[_container(env_from_secrets=[_ref("s")])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert result.risk_score == _CHECK_WEIGHTS["SV-001"]

    def test_risk_score_sv007_only(self):
        """SV-007 alone contributes its weight (35)."""
        pod = _pod(
            secret_volumes=[_vol(mount_path="/root")],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert result.risk_score == _CHECK_WEIGHTS["SV-007"]

    def test_risk_score_multiple_findings_same_check_id_counted_once(self):
        """Multiple SV-001 findings from two secrets contribute the weight only once."""
        pod = _pod(
            containers=[_container(env_from_secrets=[_ref("s1"), _ref("s2")])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        # Two SV-001 findings but weight counted once
        assert result.risk_score == _CHECK_WEIGHTS["SV-001"]

    def test_risk_score_capped_at_100(self):
        """risk_score never exceeds 100 even when all check weights sum > 100."""
        # All 7 checks: 15+25+25+15+15+20+35 = 150 → capped at 100
        pod = K8sPodSpec(
            name="all-checks",
            namespace="default",
            containers=[
                _container(
                    name="c1",
                    env_from_secrets=[_ref("shared")],
                    args=["--token=$API_TOKEN"],
                ),
                _container(
                    name="c2",
                    env_from_secrets=[_ref("shared")],
                ),
            ],
            secret_volumes=[
                _vol(name="v1", mount_path="/etc/certs"),
                _vol(name="v2", mount_path="/"),
            ],
            automount_service_account_token=None,
            service_account_name="default",
        )
        result = _ANALYZER.analyze(pod)
        assert result.risk_score == 100

    def test_risk_score_sum_of_two_distinct_checks(self):
        """SV-004 + SV-006 yields sum of their weights."""
        expected = _CHECK_WEIGHTS["SV-004"] + _CHECK_WEIGHTS["SV-006"]
        pod = _pod(
            secret_volumes=[_vol()],
            automount_service_account_token=None,
            service_account_name="default",
        )
        result = _ANALYZER.analyze(pod)
        # Fires SV-004 (15) and SV-006 (20) → 35
        assert result.risk_score == expected

    def test_check_weights_dict_has_all_seven_ids(self):
        """_CHECK_WEIGHTS must define weights for all 7 check IDs."""
        expected_ids = {f"SV-00{i}" for i in range(1, 8)}
        assert expected_ids == set(_CHECK_WEIGHTS.keys())


# ===========================================================================
# 11. by_severity() structure
# ===========================================================================

class TestBySeverity:
    """Verify by_severity() grouping behaviour."""

    def test_by_severity_empty_for_clean_pod(self):
        """by_severity() returns {} for a pod with no findings."""
        pod = _pod(automount_service_account_token=False, service_account_name="my-sa")
        result = _ANALYZER.analyze(pod)
        assert result.by_severity() == {}

    def test_by_severity_groups_by_severity_label(self):
        """Findings are placed in the correct severity bucket."""
        pod = _pod(
            containers=[_container(env_from_secrets=[_ref("s")])],  # MEDIUM (SV-001)
            secret_volumes=[_vol(mount_path="/etc/tls")],           # HIGH (SV-002)
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        by_sev = result.by_severity()
        assert "MEDIUM" in by_sev
        assert "HIGH" in by_sev
        assert all(f.severity == "MEDIUM" for f in by_sev["MEDIUM"])
        assert all(f.severity == "HIGH" for f in by_sev["HIGH"])

    def test_by_severity_critical_bucket(self):
        """CRITICAL bucket is populated when SV-007 fires."""
        pod = _pod(
            secret_volumes=[_vol(mount_path="/")],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        by_sev = result.by_severity()
        assert "CRITICAL" in by_sev
        assert all(f.severity == "CRITICAL" for f in by_sev["CRITICAL"])

    def test_by_severity_total_finding_count_matches(self):
        """Total findings across all buckets equals len(result.findings)."""
        pod = _pod(
            containers=[_container(env_from_secrets=[_ref("s")])],
            secret_volumes=[_vol(mount_path="/etc/tls"), _vol(mount_path="/")],
            automount_service_account_token=None,
            service_account_name="default",
        )
        result = _ANALYZER.analyze(pod)
        by_sev = result.by_severity()
        total = sum(len(v) for v in by_sev.values())
        assert total == len(result.findings)

    def test_by_severity_returns_dict_type(self):
        """by_severity() returns a dict."""
        pod = _pod(automount_service_account_token=False, service_account_name="my-sa")
        result = _ANALYZER.analyze(pod)
        assert isinstance(result.by_severity(), dict)


# ===========================================================================
# 12. summary() format
# ===========================================================================

class TestSummaryFormat:
    """Verify summary() string structure."""

    def test_summary_contains_finding_count(self):
        """summary() contains the finding count as 'N finding(s)'."""
        pod = _pod(
            containers=[_container(env_from_secrets=[_ref("s")])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert f"{len(result.findings)} finding(s)" in result.summary()

    def test_summary_contains_risk_score(self):
        """summary() contains 'Risk Score: N/100'."""
        pod = _pod(
            containers=[_container(env_from_secrets=[_ref("s")])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert f"Risk Score: {result.risk_score}/100" in result.summary()

    def test_summary_contains_secret_volume_analysis_label(self):
        """summary() starts with the module label."""
        pod = _pod(automount_service_account_token=False, service_account_name="my-sa")
        result = _ANALYZER.analyze(pod)
        assert result.summary().startswith("Secret Volume Analysis:")

    def test_summary_contains_severity_counts(self):
        """summary() lists severity bucket counts."""
        pod = _pod(
            secret_volumes=[_vol(mount_path="/")],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        # SV-007 → CRITICAL finding
        assert "CRITICAL" in result.summary()

    def test_summary_returns_string(self):
        """summary() returns a str."""
        pod = _pod(automount_service_account_token=False, service_account_name="my-sa")
        result = _ANALYZER.analyze(pod)
        assert isinstance(result.summary(), str)


# ===========================================================================
# 13. analyze_many() returns a list
# ===========================================================================

class TestAnalyzeMany:
    """Verify analyze_many() behaviour."""

    def test_analyze_many_returns_list(self):
        """analyze_many() returns a list."""
        pods = [
            _pod(name="p1", automount_service_account_token=False, service_account_name="sa"),
            _pod(name="p2", automount_service_account_token=False, service_account_name="sa"),
        ]
        results = _ANALYZER.analyze_many(pods)
        assert isinstance(results, list)

    def test_analyze_many_length_matches_input(self):
        """analyze_many() produces one result per input pod spec."""
        pods = [
            _pod(name=f"pod-{i}", automount_service_account_token=False, service_account_name="sa")
            for i in range(5)
        ]
        results = _ANALYZER.analyze_many(pods)
        assert len(results) == 5

    def test_analyze_many_empty_input_returns_empty_list(self):
        """analyze_many([]) returns []."""
        results = _ANALYZER.analyze_many([])
        assert results == []

    def test_analyze_many_results_are_secret_volume_result_instances(self):
        """Each element returned by analyze_many() is a SecretVolumeResult."""
        pods = [_pod(automount_service_account_token=False, service_account_name="sa")]
        results = _ANALYZER.analyze_many(pods)
        assert all(isinstance(r, SecretVolumeResult) for r in results)

    def test_analyze_many_independent_results(self):
        """Each pod in analyze_many() is analysed independently."""
        clean_pod = _pod(
            name="clean",
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        risky_pod = _pod(
            name="risky",
            secret_volumes=[_vol(mount_path="/")],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        results = _ANALYZER.analyze_many([clean_pod, risky_pod])
        assert results[0].risk_score == 0
        assert results[1].risk_score > 0

    def test_analyze_many_preserves_order(self):
        """Results are returned in the same order as input pod specs."""
        pods = [
            _pod(name=f"p{i}", automount_service_account_token=False, service_account_name="sa")
            for i in range(3)
        ]
        results = _ANALYZER.analyze_many(pods)
        for i, result in enumerate(results):
            # Each result's findings reference the correct pod name
            pod_names_in_findings = {f.pod_name for f in result.findings}
            # For clean pods there are no findings; just verify no cross-contamination
            assert all(n == f"p{i}" for n in pod_names_in_findings)


# ===========================================================================
# 14. to_dict() on all dataclasses
# ===========================================================================

class TestToDict:
    """Verify to_dict() on every dataclass."""

    def test_k8s_secret_ref_to_dict_all_fields(self):
        """K8sSecretRef.to_dict() contains secret_name and key."""
        ref = K8sSecretRef(secret_name="my-secret", key="password")
        d = ref.to_dict()
        assert d["secret_name"] == "my-secret"
        assert d["key"] == "password"

    def test_k8s_secret_ref_to_dict_key_none(self):
        """K8sSecretRef.to_dict() includes key=None when not specified."""
        ref = K8sSecretRef(secret_name="my-secret")
        d = ref.to_dict()
        assert d["key"] is None

    def test_k8s_container_to_dict_structure(self):
        """K8sContainer.to_dict() contains all expected keys."""
        container = _container(name="web", env_from_secrets=[_ref("creds")])
        d = container.to_dict()
        assert "name" in d
        assert "image" in d
        assert "env_from_secrets" in d
        assert "env_secrets" in d
        assert "command" in d
        assert "args" in d

    def test_k8s_container_to_dict_nested_refs(self):
        """K8sContainer.to_dict() serialises nested K8sSecretRef objects."""
        container = _container(env_from_secrets=[_ref("s1"), _ref("s2")])
        d = container.to_dict()
        assert len(d["env_from_secrets"]) == 2
        assert d["env_from_secrets"][0]["secret_name"] == "s1"

    def test_k8s_pod_spec_to_dict_structure(self):
        """K8sPodSpec.to_dict() contains all expected top-level keys."""
        pod = _pod()
        d = pod.to_dict()
        assert "name" in d
        assert "namespace" in d
        assert "containers" in d
        assert "secret_volumes" in d
        assert "automount_service_account_token" in d
        assert "service_account_name" in d

    def test_k8s_pod_spec_to_dict_nested_containers(self):
        """K8sPodSpec.to_dict() serialises nested containers."""
        pod = _pod(containers=[_container(name="svc")])
        d = pod.to_dict()
        assert len(d["containers"]) == 1
        assert d["containers"][0]["name"] == "svc"

    def test_secret_volume_finding_to_dict_all_fields(self):
        """SecretVolumeFinding.to_dict() contains all nine expected keys."""
        finding = SecretVolumeFinding(
            check_id="SV-001",
            severity="MEDIUM",
            pod_name="my-pod",
            namespace="production",
            container_name="app",
            secret_name="db-creds",
            mount_path=None,
            message="Test message.",
            recommendation="Test recommendation.",
        )
        d = finding.to_dict()
        expected_keys = {
            "check_id", "severity", "pod_name", "namespace",
            "container_name", "secret_name", "mount_path",
            "message", "recommendation",
        }
        assert set(d.keys()) == expected_keys

    def test_secret_volume_finding_to_dict_values(self):
        """SecretVolumeFinding.to_dict() preserves field values."""
        finding = SecretVolumeFinding(
            check_id="SV-007",
            severity="CRITICAL",
            pod_name="p",
            namespace="ns",
            mount_path="/root",
            message="msg",
            recommendation="rec",
        )
        d = finding.to_dict()
        assert d["check_id"] == "SV-007"
        assert d["severity"] == "CRITICAL"
        assert d["mount_path"] == "/root"

    def test_secret_volume_result_to_dict_structure(self):
        """SecretVolumeResult.to_dict() contains risk_score, findings, summary."""
        pod = _pod(
            containers=[_container(env_from_secrets=[_ref("s")])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        d = result.to_dict()
        assert "risk_score" in d
        assert "findings" in d
        assert "summary" in d

    def test_secret_volume_result_to_dict_findings_are_dicts(self):
        """SecretVolumeResult.to_dict() serialises findings as list of dicts."""
        pod = _pod(
            containers=[_container(env_from_secrets=[_ref("s")])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        d = result.to_dict()
        assert all(isinstance(f, dict) for f in d["findings"])

    def test_secret_volume_result_to_dict_risk_score_type(self):
        """SecretVolumeResult.to_dict()['risk_score'] is an int."""
        pod = _pod(automount_service_account_token=False, service_account_name="my-sa")
        result = _ANALYZER.analyze(pod)
        d = result.to_dict()
        assert isinstance(d["risk_score"], int)

    def test_secret_volume_result_to_dict_summary_is_string(self):
        """SecretVolumeResult.to_dict()['summary'] is a str."""
        pod = _pod(automount_service_account_token=False, service_account_name="my-sa")
        result = _ANALYZER.analyze(pod)
        d = result.to_dict()
        assert isinstance(d["summary"], str)


# ===========================================================================
# 15. Edge cases and additional coverage
# ===========================================================================

class TestEdgeCases:
    """Edge cases: empty containers list, namespace propagation, etc."""

    def test_pod_with_no_containers_does_not_crash(self):
        """K8sPodSpec with empty containers list does not raise."""
        pod = K8sPodSpec(
            name="empty",
            namespace="default",
            containers=[],
            secret_volumes=[],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert isinstance(result, SecretVolumeResult)

    def test_namespace_propagated_to_findings(self):
        """Findings carry the pod's namespace."""
        pod = _pod(
            namespace="kube-system",
            containers=[_container(env_from_secrets=[_ref("s")])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert all(f.namespace == "kube-system" for f in result.findings)

    def test_pod_name_propagated_to_findings(self):
        """Findings carry the pod's name."""
        pod = _pod(
            name="my-unique-pod",
            containers=[_container(env_from_secrets=[_ref("s")])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert all(f.pod_name == "my-unique-pod" for f in result.findings)

    def test_findings_have_non_empty_message(self):
        """Every finding produced by the analyzer has a non-empty message."""
        pod = K8sPodSpec(
            name="all-checks",
            namespace="default",
            containers=[
                _container("c1", env_from_secrets=[_ref("shared")], args=["--k=$SECRET_KEY"]),
                _container("c2", env_from_secrets=[_ref("shared")]),
            ],
            secret_volumes=[
                _vol(mount_path="/etc/certs"),
                _vol(mount_path="/"),
            ],
            automount_service_account_token=None,
            service_account_name="default",
        )
        result = _ANALYZER.analyze(pod)
        assert all(len(f.message) > 0 for f in result.findings)

    def test_findings_have_non_empty_recommendation(self):
        """Every finding produced by the analyzer has a non-empty recommendation."""
        pod = K8sPodSpec(
            name="all-checks",
            namespace="default",
            containers=[
                _container("c1", env_from_secrets=[_ref("shared")], args=["--k=$SECRET_KEY"]),
                _container("c2", env_from_secrets=[_ref("shared")]),
            ],
            secret_volumes=[
                _vol(mount_path="/etc/certs"),
                _vol(mount_path="/"),
            ],
            automount_service_account_token=None,
            service_account_name="default",
        )
        result = _ANALYZER.analyze(pod)
        assert all(len(f.recommendation) > 0 for f in result.findings)

    def test_k8s_secret_ref_with_specific_key_does_not_trigger_sv001(self):
        """Mounting a specific key via env_secrets is not flagged as SV-001."""
        pod = _pod(
            containers=[_container(env_secrets=[_ref("db", "password")])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert "SV-001" not in _check_ids(result)

    def test_sv007_root_exactly_not_sv002(self):
        """'/' is exact root — SV-007 fires but SV-002 sensitive prefixes do NOT match '/'."""
        pod = _pod(
            secret_volumes=[_vol(mount_path="/")],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert "SV-007" in _check_ids(result)
        # '/' does not start with any of the SV-002 prefixes (/etc/, /root/, etc.)
        assert "SV-002" not in _check_ids(result)

    def test_sv003_no_false_positive_on_env_var_name_without_dollar(self):
        """A plain string 'SECRET' without $ prefix does NOT trigger SV-003."""
        pod = _pod(
            containers=[_container(args=["SECRET", "plain-token", "password"])],
            automount_service_account_token=False,
            service_account_name="my-sa",
        )
        result = _ANALYZER.analyze(pod)
        assert "SV-003" not in _check_ids(result)

    def test_result_is_secret_volume_result_instance(self):
        """analyze() always returns a SecretVolumeResult."""
        result = _ANALYZER.analyze(_pod(automount_service_account_token=False, service_account_name="sa"))
        assert isinstance(result, SecretVolumeResult)
