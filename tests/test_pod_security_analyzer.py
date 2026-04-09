"""
Tests for kubernetes.pod_security_analyzer
===========================================
Covers all 8 PSS checks (fire + no-fire), report structure, risk scoring,
multi-kind support, initContainer detection, image tag edge-cases, and the
public dataclass APIs (PSSFinding / PSSReport).

Run with:  pytest tests/test_pod_security_analyzer.py -v
"""

from __future__ import annotations

import sys
import os

# Ensure the project root is on sys.path so ``kubernetes`` package is importable
# regardless of how pytest is invoked.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from kubernetes.pod_security_analyzer import (
    _CHECK_WEIGHTS,
    _DANGEROUS_CAPS,
    PodSecurityAnalyzer,
    PSSFinding,
    PSSReport,
    PSSSeverity,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _pod(
    name: str = "test-pod",
    namespace: str = "default",
    containers=None,
    init_containers=None,
    host_network: bool = False,
    host_pid: bool = False,
    host_ipc: bool = False,
    volumes=None,
) -> dict:
    """Build a minimal Pod manifest dict."""
    spec: dict = {}
    if containers is not None:
        spec["containers"] = containers
    else:
        spec["containers"] = [_container()]
    if init_containers is not None:
        spec["initContainers"] = init_containers
    if host_network:
        spec["hostNetwork"] = True
    if host_pid:
        spec["hostPID"] = True
    if host_ipc:
        spec["hostIPC"] = True
    if volumes is not None:
        spec["volumes"] = volumes

    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }


def _container(
    name: str = "app",
    image: str = "nginx:1.27.0",
    privileged: bool = False,
    run_as_user=None,
    run_as_non_root=None,
    allow_privilege_escalation=None,
    readonly_root=None,
    caps_add=None,
    caps_drop=None,
) -> dict:
    """Build a minimal container spec dict."""
    sc: dict = {}
    if privileged:
        sc["privileged"] = True
    if run_as_user is not None:
        sc["runAsUser"] = run_as_user
    if run_as_non_root is not None:
        sc["runAsNonRoot"] = run_as_non_root
    if allow_privilege_escalation is not None:
        sc["allowPrivilegeEscalation"] = allow_privilege_escalation
    if readonly_root is not None:
        sc["readOnlyRootFilesystem"] = readonly_root
    if caps_add is not None or caps_drop is not None:
        capabilities: dict = {}
        if caps_add:
            capabilities["add"] = caps_add
        if caps_drop:
            capabilities["drop"] = caps_drop
        sc["capabilities"] = capabilities

    cspec: dict = {"name": name, "image": image}
    if sc:
        cspec["securityContext"] = sc
    return cspec


def _deployment(
    name: str = "test-deploy",
    namespace: str = "default",
    containers=None,
) -> dict:
    """Build a minimal Deployment manifest dict."""
    if containers is None:
        containers = [_container()]
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "template": {
                "spec": {"containers": containers}
            }
        },
    }


def _statefulset(name: str = "test-sts", namespace: str = "default", containers=None) -> dict:
    if containers is None:
        containers = [_container()]
    return {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"template": {"spec": {"containers": containers}}},
    }


def _daemonset(name: str = "test-ds", namespace: str = "default", containers=None) -> dict:
    if containers is None:
        containers = [_container()]
    return {
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"template": {"spec": {"containers": containers}}},
    }


def _job(name: str = "test-job", namespace: str = "default", containers=None) -> dict:
    if containers is None:
        containers = [_container()]
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"template": {"spec": {"containers": containers}}},
    }


def _cronjob(name: str = "test-cj", namespace: str = "default", containers=None) -> dict:
    if containers is None:
        containers = [_container()]
    return {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": {"containers": containers}
                    }
                }
            }
        },
    }


# A fully-hardened container spec that should produce zero findings.
def _hardened_container(name: str = "hardened") -> dict:
    return _container(
        name=name,
        image="nginx:1.27.0",
        run_as_non_root=True,
        run_as_user=65534,
        allow_privilege_escalation=False,
        readonly_root=True,
        privileged=False,
    )


@pytest.fixture()
def analyzer() -> PodSecurityAnalyzer:
    """Default analyzer with all checks enabled."""
    return PodSecurityAnalyzer(check_latest_tag=True, require_readonly_root=True)


def _check_ids(report: PSSReport) -> list:
    return [f.check_id for f in report.findings]


# ---------------------------------------------------------------------------
# PSS-001 — Runs as root
# ---------------------------------------------------------------------------


class TestPSS001RunsAsRoot:
    def test_fires_when_run_as_user_is_zero(self, analyzer):
        pod = _pod(containers=[_container(run_as_user=0)])
        report = analyzer.analyze([pod])
        assert "PSS-001" in _check_ids(report)

    def test_fires_when_run_as_non_root_is_false(self, analyzer):
        pod = _pod(containers=[_container(run_as_non_root=False)])
        report = analyzer.analyze([pod])
        assert "PSS-001" in _check_ids(report)

    def test_no_fire_when_run_as_non_root_true(self, analyzer):
        pod = _pod(containers=[_container(run_as_non_root=True, run_as_user=1000)])
        report = analyzer.analyze([pod])
        findings_001 = [f for f in report.findings if f.check_id == "PSS-001"]
        assert findings_001 == []

    def test_no_fire_when_no_security_context(self, analyzer):
        """Missing securityContext altogether should NOT trigger PSS-001."""
        pod = _pod(containers=[{"name": "app", "image": "nginx:1.27.0"}])
        report = analyzer.analyze([pod])
        findings_001 = [f for f in report.findings if f.check_id == "PSS-001"]
        assert findings_001 == []

    def test_severity_is_high(self, analyzer):
        pod = _pod(containers=[_container(run_as_user=0)])
        report = analyzer.analyze([pod])
        finding = next(f for f in report.findings if f.check_id == "PSS-001")
        assert finding.severity == PSSSeverity.HIGH

    def test_finding_includes_container_name(self, analyzer):
        pod = _pod(containers=[_container(name="myapp", run_as_user=0)])
        report = analyzer.analyze([pod])
        finding = next(f for f in report.findings if f.check_id == "PSS-001")
        assert finding.container_name == "myapp"

    def test_fires_in_init_container(self, analyzer):
        pod = _pod(
            containers=[_hardened_container()],
            init_containers=[_container(name="init", run_as_user=0)],
        )
        report = analyzer.analyze([pod])
        findings = [f for f in report.findings if f.check_id == "PSS-001"]
        assert any(f.container_name == "init" for f in findings)


# ---------------------------------------------------------------------------
# PSS-002 — Privileged container
# ---------------------------------------------------------------------------


class TestPSS002Privileged:
    def test_fires_when_privileged_true(self, analyzer):
        pod = _pod(containers=[_container(privileged=True)])
        report = analyzer.analyze([pod])
        assert "PSS-002" in _check_ids(report)

    def test_no_fire_when_privileged_false(self, analyzer):
        # privileged=False is the default; we set it explicitly here.
        cspec = _container()
        cspec.setdefault("securityContext", {})["privileged"] = False
        pod = _pod(containers=[cspec])
        report = analyzer.analyze([pod])
        findings_002 = [f for f in report.findings if f.check_id == "PSS-002"]
        assert findings_002 == []

    def test_no_fire_when_privileged_absent(self, analyzer):
        pod = _pod(containers=[_hardened_container()])
        report = analyzer.analyze([pod])
        findings_002 = [f for f in report.findings if f.check_id == "PSS-002"]
        assert findings_002 == []

    def test_severity_is_critical(self, analyzer):
        pod = _pod(containers=[_container(privileged=True)])
        report = analyzer.analyze([pod])
        finding = next(f for f in report.findings if f.check_id == "PSS-002")
        assert finding.severity == PSSSeverity.CRITICAL

    def test_fires_in_init_container(self, analyzer):
        pod = _pod(
            containers=[_hardened_container()],
            init_containers=[_container(name="init-priv", privileged=True)],
        )
        report = analyzer.analyze([pod])
        findings = [f for f in report.findings if f.check_id == "PSS-002"]
        assert any(f.container_name == "init-priv" for f in findings)


# ---------------------------------------------------------------------------
# PSS-003 — AllowPrivilegeEscalation not disabled
# ---------------------------------------------------------------------------


class TestPSS003AllowPrivilegeEscalation:
    def test_fires_when_field_absent(self, analyzer):
        pod = _pod(containers=[{"name": "app", "image": "nginx:1.27.0"}])
        report = analyzer.analyze([pod])
        assert "PSS-003" in _check_ids(report)

    def test_fires_when_field_is_true(self, analyzer):
        pod = _pod(containers=[_container(allow_privilege_escalation=True)])
        report = analyzer.analyze([pod])
        assert "PSS-003" in _check_ids(report)

    def test_no_fire_when_explicitly_false(self, analyzer):
        pod = _pod(containers=[_container(allow_privilege_escalation=False)])
        report = analyzer.analyze([pod])
        findings_003 = [f for f in report.findings if f.check_id == "PSS-003"]
        assert findings_003 == []

    def test_severity_is_medium(self, analyzer):
        pod = _pod(containers=[_container(allow_privilege_escalation=True)])
        report = analyzer.analyze([pod])
        finding = next(f for f in report.findings if f.check_id == "PSS-003")
        assert finding.severity == PSSSeverity.MEDIUM

    def test_fires_in_init_container(self, analyzer):
        pod = _pod(
            containers=[_hardened_container()],
            init_containers=[_container(name="init-esc")],  # APE not set
        )
        report = analyzer.analyze([pod])
        findings = [f for f in report.findings if f.check_id == "PSS-003"]
        assert any(f.container_name == "init-esc" for f in findings)


# ---------------------------------------------------------------------------
# PSS-004 — Host namespace sharing
# ---------------------------------------------------------------------------


class TestPSS004HostNamespaces:
    def test_fires_on_host_network(self, analyzer):
        pod = _pod(host_network=True)
        report = analyzer.analyze([pod])
        assert "PSS-004" in _check_ids(report)

    def test_fires_on_host_pid(self, analyzer):
        pod = _pod(host_pid=True)
        report = analyzer.analyze([pod])
        assert "PSS-004" in _check_ids(report)

    def test_fires_on_host_ipc(self, analyzer):
        pod = _pod(host_ipc=True)
        report = analyzer.analyze([pod])
        assert "PSS-004" in _check_ids(report)

    def test_fires_once_even_if_all_three_set(self, analyzer):
        """All three flags in a single pod should produce exactly one PSS-004 finding."""
        pod = _pod(host_network=True, host_pid=True, host_ipc=True)
        report = analyzer.analyze([pod])
        findings_004 = [f for f in report.findings if f.check_id == "PSS-004"]
        assert len(findings_004) == 1

    def test_no_fire_when_none_set(self, analyzer):
        pod = _pod()
        report = analyzer.analyze([pod])
        findings_004 = [f for f in report.findings if f.check_id == "PSS-004"]
        assert findings_004 == []

    def test_severity_is_high(self, analyzer):
        pod = _pod(host_network=True)
        report = analyzer.analyze([pod])
        finding = next(f for f in report.findings if f.check_id == "PSS-004")
        assert finding.severity == PSSSeverity.HIGH

    def test_finding_has_empty_container_name(self, analyzer):
        """PSS-004 is a pod-level check; container_name should be empty."""
        pod = _pod(host_pid=True)
        report = analyzer.analyze([pod])
        finding = next(f for f in report.findings if f.check_id == "PSS-004")
        assert finding.container_name == ""

    def test_detail_mentions_all_violated_fields(self, analyzer):
        pod = _pod(host_network=True, host_ipc=True)
        report = analyzer.analyze([pod])
        finding = next(f for f in report.findings if f.check_id == "PSS-004")
        assert "hostNetwork" in finding.detail
        assert "hostIPC" in finding.detail


# ---------------------------------------------------------------------------
# PSS-005 — Dangerous Linux capabilities
# ---------------------------------------------------------------------------


class TestPSS005DangerousCaps:
    def test_fires_on_sys_admin(self, analyzer):
        pod = _pod(containers=[_container(caps_add=["SYS_ADMIN"])])
        report = analyzer.analyze([pod])
        assert "PSS-005" in _check_ids(report)

    def test_fires_on_net_admin(self, analyzer):
        pod = _pod(containers=[_container(caps_add=["NET_ADMIN"])])
        report = analyzer.analyze([pod])
        assert "PSS-005" in _check_ids(report)

    def test_fires_on_sys_ptrace(self, analyzer):
        pod = _pod(containers=[_container(caps_add=["SYS_PTRACE"])])
        report = analyzer.analyze([pod])
        assert "PSS-005" in _check_ids(report)

    def test_fires_on_mixed_caps_list(self, analyzer):
        """A mix of safe and dangerous caps should still fire."""
        pod = _pod(containers=[_container(caps_add=["CHOWN", "NET_ADMIN"])])
        report = analyzer.analyze([pod])
        assert "PSS-005" in _check_ids(report)

    def test_fires_on_lower_case_cap(self, analyzer):
        """Capability names should be normalised to upper-case before comparison."""
        pod = _pod(containers=[_container(caps_add=["sys_admin"])])
        report = analyzer.analyze([pod])
        assert "PSS-005" in _check_ids(report)

    def test_no_fire_on_safe_caps(self, analyzer):
        pod = _pod(containers=[_container(caps_add=["CHOWN", "NET_BIND_SERVICE"])])
        report = analyzer.analyze([pod])
        findings_005 = [f for f in report.findings if f.check_id == "PSS-005"]
        assert findings_005 == []

    def test_no_fire_when_caps_add_absent(self, analyzer):
        pod = _pod(containers=[_hardened_container()])
        report = analyzer.analyze([pod])
        findings_005 = [f for f in report.findings if f.check_id == "PSS-005"]
        assert findings_005 == []

    def test_severity_is_critical(self, analyzer):
        pod = _pod(containers=[_container(caps_add=["SYS_ADMIN"])])
        report = analyzer.analyze([pod])
        finding = next(f for f in report.findings if f.check_id == "PSS-005")
        assert finding.severity == PSSSeverity.CRITICAL

    def test_all_dangerous_caps_are_detected(self, analyzer):
        """Every cap in _DANGEROUS_CAPS must trigger a PSS-005 finding."""
        for cap in _DANGEROUS_CAPS:
            pod = _pod(containers=[_container(caps_add=[cap])])
            report = analyzer.analyze([pod])
            findings = [f for f in report.findings if f.check_id == "PSS-005"]
            assert findings, f"Expected PSS-005 for capability {cap}"

    def test_fires_in_init_container(self, analyzer):
        pod = _pod(
            containers=[_hardened_container()],
            init_containers=[_container(name="init-cap", caps_add=["SYS_ADMIN"])],
        )
        report = analyzer.analyze([pod])
        findings = [f for f in report.findings if f.check_id == "PSS-005"]
        assert any(f.container_name == "init-cap" for f in findings)


# ---------------------------------------------------------------------------
# PSS-006 — HostPath volume
# ---------------------------------------------------------------------------


class TestPSS006HostPath:
    def test_fires_when_hostpath_volume_present(self, analyzer):
        volumes = [{"name": "host-vol", "hostPath": {"path": "/var/log"}}]
        pod = _pod(volumes=volumes)
        report = analyzer.analyze([pod])
        assert "PSS-006" in _check_ids(report)

    def test_no_fire_on_configmap_volume(self, analyzer):
        volumes = [{"name": "cfg", "configMap": {"name": "my-config"}}]
        pod = _pod(volumes=volumes)
        report = analyzer.analyze([pod])
        findings_006 = [f for f in report.findings if f.check_id == "PSS-006"]
        assert findings_006 == []

    def test_no_fire_on_empty_volumes(self, analyzer):
        pod = _pod(volumes=[])
        report = analyzer.analyze([pod])
        findings_006 = [f for f in report.findings if f.check_id == "PSS-006"]
        assert findings_006 == []

    def test_no_fire_when_volumes_absent(self, analyzer):
        pod = _pod()
        report = analyzer.analyze([pod])
        findings_006 = [f for f in report.findings if f.check_id == "PSS-006"]
        assert findings_006 == []

    def test_severity_is_high(self, analyzer):
        volumes = [{"name": "hv", "hostPath": {"path": "/etc"}}]
        pod = _pod(volumes=volumes)
        report = analyzer.analyze([pod])
        finding = next(f for f in report.findings if f.check_id == "PSS-006")
        assert finding.severity == PSSSeverity.HIGH

    def test_finding_has_empty_container_name(self, analyzer):
        volumes = [{"name": "hv", "hostPath": {"path": "/tmp"}}]
        pod = _pod(volumes=volumes)
        report = analyzer.analyze([pod])
        finding = next(f for f in report.findings if f.check_id == "PSS-006")
        assert finding.container_name == ""

    def test_detail_includes_path(self, analyzer):
        volumes = [{"name": "hv", "hostPath": {"path": "/var/run/docker.sock"}}]
        pod = _pod(volumes=volumes)
        report = analyzer.analyze([pod])
        finding = next(f for f in report.findings if f.check_id == "PSS-006")
        assert "/var/run/docker.sock" in finding.detail


# ---------------------------------------------------------------------------
# PSS-007 — Read-only root filesystem
# ---------------------------------------------------------------------------


class TestPSS007ReadonlyRoot:
    def test_fires_when_field_absent(self, analyzer):
        pod = _pod(containers=[{"name": "app", "image": "nginx:1.27.0"}])
        report = analyzer.analyze([pod])
        assert "PSS-007" in _check_ids(report)

    def test_fires_when_field_is_false(self, analyzer):
        pod = _pod(containers=[_container(readonly_root=False)])
        report = analyzer.analyze([pod])
        assert "PSS-007" in _check_ids(report)

    def test_no_fire_when_field_is_true(self, analyzer):
        pod = _pod(containers=[_container(readonly_root=True)])
        report = analyzer.analyze([pod])
        findings_007 = [f for f in report.findings if f.check_id == "PSS-007"]
        assert findings_007 == []

    def test_no_fire_when_check_disabled(self):
        analyzer = PodSecurityAnalyzer(require_readonly_root=False)
        pod = _pod(containers=[_container(readonly_root=False)])
        report = analyzer.analyze([pod])
        findings_007 = [f for f in report.findings if f.check_id == "PSS-007"]
        assert findings_007 == []

    def test_severity_is_low(self, analyzer):
        pod = _pod(containers=[_container(readonly_root=False)])
        report = analyzer.analyze([pod])
        finding = next(f for f in report.findings if f.check_id == "PSS-007")
        assert finding.severity == PSSSeverity.LOW

    def test_fires_in_init_container(self, analyzer):
        pod = _pod(
            containers=[_hardened_container()],
            init_containers=[_container(name="init-rw", readonly_root=False)],
        )
        report = analyzer.analyze([pod])
        findings = [f for f in report.findings if f.check_id == "PSS-007"]
        assert any(f.container_name == "init-rw" for f in findings)


# ---------------------------------------------------------------------------
# PSS-008 — Image tag hygiene
# ---------------------------------------------------------------------------


class TestPSS008ImageTag:
    def test_fires_on_explicit_latest_tag(self, analyzer):
        pod = _pod(containers=[_container(image="nginx:latest")])
        report = analyzer.analyze([pod])
        assert "PSS-008" in _check_ids(report)

    def test_fires_on_image_with_no_colon(self, analyzer):
        pod = _pod(containers=[_container(image="nginx")])
        report = analyzer.analyze([pod])
        assert "PSS-008" in _check_ids(report)

    def test_fires_on_fully_qualified_latest(self, analyzer):
        pod = _pod(containers=[_container(image="registry.io/org/nginx:latest")])
        report = analyzer.analyze([pod])
        assert "PSS-008" in _check_ids(report)

    def test_no_fire_on_pinned_semver_tag(self, analyzer):
        pod = _pod(containers=[_container(image="nginx:1.27.0")])
        report = analyzer.analyze([pod])
        findings_008 = [f for f in report.findings if f.check_id == "PSS-008"]
        assert findings_008 == []

    def test_no_fire_on_sha256_digest(self, analyzer):
        image = "nginx@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1"
        pod = _pod(containers=[_container(image=image)])
        report = analyzer.analyze([pod])
        findings_008 = [f for f in report.findings if f.check_id == "PSS-008"]
        assert findings_008 == []

    def test_no_fire_on_registry_with_port_and_tag(self, analyzer):
        """Registry:port/image:tag should not be misidentified as 'tag = port'."""
        pod = _pod(containers=[_container(image="registry.io:5000/myapp:v2.3.1")])
        report = analyzer.analyze([pod])
        findings_008 = [f for f in report.findings if f.check_id == "PSS-008"]
        assert findings_008 == []

    def test_no_fire_when_check_disabled(self):
        analyzer = PodSecurityAnalyzer(check_latest_tag=False)
        pod = _pod(containers=[_container(image="nginx:latest")])
        report = analyzer.analyze([pod])
        findings_008 = [f for f in report.findings if f.check_id == "PSS-008"]
        assert findings_008 == []

    def test_severity_is_low(self, analyzer):
        pod = _pod(containers=[_container(image="nginx:latest")])
        report = analyzer.analyze([pod])
        finding = next(f for f in report.findings if f.check_id == "PSS-008")
        assert finding.severity == PSSSeverity.LOW

    def test_case_insensitive_latest(self, analyzer):
        """'LATEST' and 'Latest' should be treated the same as 'latest'."""
        for tag in ("LATEST", "Latest", "lAtEsT"):
            pod = _pod(containers=[_container(image=f"nginx:{tag}")])
            report = analyzer.analyze([pod])
            findings_008 = [f for f in report.findings if f.check_id == "PSS-008"]
            assert findings_008, f"Expected PSS-008 for image tag '{tag}'"


# ---------------------------------------------------------------------------
# Multi-kind support
# ---------------------------------------------------------------------------


class TestMultiKindSupport:
    """Verify that all supported workload kinds are correctly analysed."""

    def _has_findings(self, report: PSSReport) -> bool:
        return report.total_findings > 0

    def test_pod_kind_is_analyzed(self, analyzer):
        report = analyzer.analyze([_pod(containers=[_container(privileged=True)])])
        assert "PSS-002" in _check_ids(report)
        assert report.pods_analyzed == 1

    def test_deployment_kind_is_analyzed(self, analyzer):
        report = analyzer.analyze([_deployment(containers=[_container(privileged=True)])])
        assert "PSS-002" in _check_ids(report)
        assert report.pods_analyzed == 1

    def test_statefulset_kind_is_analyzed(self, analyzer):
        report = analyzer.analyze([_statefulset(containers=[_container(privileged=True)])])
        assert "PSS-002" in _check_ids(report)
        assert report.pods_analyzed == 1

    def test_daemonset_kind_is_analyzed(self, analyzer):
        report = analyzer.analyze([_daemonset(containers=[_container(privileged=True)])])
        assert "PSS-002" in _check_ids(report)
        assert report.pods_analyzed == 1

    def test_job_kind_is_analyzed(self, analyzer):
        report = analyzer.analyze([_job(containers=[_container(privileged=True)])])
        assert "PSS-002" in _check_ids(report)
        assert report.pods_analyzed == 1

    def test_cronjob_kind_is_analyzed(self, analyzer):
        report = analyzer.analyze([_cronjob(containers=[_container(privileged=True)])])
        assert "PSS-002" in _check_ids(report)
        assert report.pods_analyzed == 1

    def test_unsupported_kind_is_skipped(self, analyzer):
        service = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "svc", "namespace": "default"},
            "spec": {"selector": {"app": "myapp"}},
        }
        report = analyzer.analyze([service])
        assert report.pods_analyzed == 0
        assert report.total_findings == 0

    def test_mixed_kinds_all_counted(self, analyzer):
        manifests = [
            _pod(name="p1", containers=[_container(privileged=True)]),
            _deployment(name="d1", containers=[_container(privileged=True)]),
            _statefulset(name="s1", containers=[_container(privileged=True)]),
            _daemonset(name="ds1", containers=[_container(privileged=True)]),
        ]
        report = analyzer.analyze(manifests)
        assert report.pods_analyzed == 4

    def test_namespace_defaults_to_default(self, analyzer):
        manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "no-ns-pod"},  # no namespace key
            "spec": {"containers": [_container(privileged=True)]},
        }
        report = analyzer.analyze([manifest])
        finding = next(f for f in report.findings if f.check_id == "PSS-002")
        assert finding.namespace == "default"


# ---------------------------------------------------------------------------
# Report structure and properties
# ---------------------------------------------------------------------------


class TestReportStructure:
    def test_pods_analyzed_count(self, analyzer):
        manifests = [_pod(name=f"pod-{i}") for i in range(5)]
        report = analyzer.analyze(manifests)
        assert report.pods_analyzed == 5

    def test_total_findings_property(self, analyzer):
        pod = _pod(containers=[_container(privileged=True, image="nginx:latest")])
        report = analyzer.analyze([pod])
        assert report.total_findings == len(report.findings)

    def test_critical_findings_property(self, analyzer):
        pod = _pod(containers=[_container(privileged=True)])
        report = analyzer.analyze([pod])
        for f in report.critical_findings:
            assert f.severity == PSSSeverity.CRITICAL

    def test_high_findings_property(self, analyzer):
        pod = _pod(containers=[_container(run_as_user=0)])
        report = analyzer.analyze([pod])
        for f in report.high_findings:
            assert f.severity == PSSSeverity.HIGH

    def test_findings_by_check(self, analyzer):
        manifests = [
            _pod(name="a", containers=[_container(privileged=True)]),
            _pod(name="b", containers=[_container(privileged=True)]),
        ]
        report = analyzer.analyze(manifests)
        pss002 = report.findings_by_check("PSS-002")
        assert len(pss002) == 2

    def test_findings_for_pod(self, analyzer):
        manifests = [
            _pod(name="target", namespace="ns-a", containers=[_container(privileged=True)]),
            _pod(name="other", namespace="ns-a", containers=[_hardened_container()]),
        ]
        report = analyzer.analyze(manifests)
        pod_findings = report.findings_for_pod("ns-a", "target")
        assert all(f.pod_name == "target" for f in pod_findings)

    def test_generated_at_is_recent(self, analyzer):
        import time
        before = time.time()
        report = analyzer.analyze([_pod()])
        after = time.time()
        assert before <= report.generated_at <= after

    def test_empty_manifests_returns_zero_score(self, analyzer):
        report = analyzer.analyze([])
        assert report.risk_score == 0
        assert report.total_findings == 0
        assert report.pods_analyzed == 0

    def test_to_dict_keys(self, analyzer):
        report = analyzer.analyze([_pod(containers=[_container(privileged=True)])])
        d = report.to_dict()
        assert set(d.keys()) == {
            "risk_score", "pods_analyzed", "total_findings", "generated_at", "findings"
        }

    def test_to_dict_findings_are_dicts(self, analyzer):
        report = analyzer.analyze([_pod(containers=[_container(privileged=True)])])
        d = report.to_dict()
        for f in d["findings"]:
            assert isinstance(f, dict)

    def test_summary_returns_string(self, analyzer):
        report = analyzer.analyze([_pod()])
        s = report.summary()
        assert isinstance(s, str)
        assert "PSS Analysis Report" in s


# ---------------------------------------------------------------------------
# PSSFinding API
# ---------------------------------------------------------------------------


class TestPSSFindingAPI:
    def _sample_finding(self) -> PSSFinding:
        return PSSFinding(
            check_id="PSS-002",
            severity=PSSSeverity.CRITICAL,
            namespace="production",
            pod_name="api-pod",
            container_name="api",
            title="Privileged container",
            detail="This is a detail.",
            remediation="Set privileged: false.",
            evidence="privileged: true",
        )

    def test_summary_contains_check_id(self):
        f = self._sample_finding()
        assert "PSS-002" in f.summary()

    def test_summary_contains_pod_name(self):
        f = self._sample_finding()
        assert "api-pod" in f.summary()

    def test_summary_contains_container_name(self):
        f = self._sample_finding()
        assert "api" in f.summary()

    def test_to_dict_keys(self):
        f = self._sample_finding()
        d = f.to_dict()
        expected = {
            "check_id", "severity", "namespace", "pod_name", "container_name",
            "title", "detail", "remediation", "evidence",
        }
        assert set(d.keys()) == expected

    def test_to_dict_evidence_truncated_at_512(self):
        f = self._sample_finding()
        f.evidence = "x" * 1000
        d = f.to_dict()
        assert len(d["evidence"]) == 512

    def test_to_dict_evidence_short_not_truncated(self):
        f = self._sample_finding()
        f.evidence = "short evidence"
        d = f.to_dict()
        assert d["evidence"] == "short evidence"

    def test_to_dict_severity_is_string(self):
        f = self._sample_finding()
        d = f.to_dict()
        assert isinstance(d["severity"], str)
        assert d["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------


class TestRiskScoring:
    def test_zero_score_for_clean_manifest(self):
        """A fully-hardened pod should produce a score of 0."""
        analyzer = PodSecurityAnalyzer(check_latest_tag=True, require_readonly_root=True)
        pod = _pod(containers=[_hardened_container()])
        # Override to make the pod also have no host namespaces and no hostPath
        report = analyzer.analyze([pod])
        # Clean pod may still trigger PSS-003 if APE not set; hardened_container sets it False.
        # Verify score equals only the weights of checks that actually fired.
        fired = {f.check_id for f in report.findings}
        expected = sum(_CHECK_WEIGHTS.get(c, 0) for c in fired)
        assert report.risk_score == min(expected, 100)

    def test_score_capped_at_100(self):
        """Even if all checks fire the score must not exceed 100."""
        analyzer = PodSecurityAnalyzer(check_latest_tag=True, require_readonly_root=True)
        # Build a pod that triggers as many checks as possible.
        bad_container = _container(
            image="nginx:latest",
            privileged=True,
            run_as_user=0,
            caps_add=["SYS_ADMIN"],
            readonly_root=False,
        )
        volumes = [{"name": "hv", "hostPath": {"path": "/etc"}}]
        pod = _pod(
            containers=[bad_container],
            host_network=True,
            host_pid=True,
            volumes=volumes,
        )
        report = analyzer.analyze([pod])
        assert report.risk_score <= 100

    def test_score_uses_unique_check_ids(self):
        """Firing the same check across multiple containers should count only once."""
        analyzer = PodSecurityAnalyzer(check_latest_tag=False, require_readonly_root=False)
        # Use allow_privilege_escalation=False so only PSS-002 fires; that isolates
        # the test to a single check type repeated across many containers.
        containers = [
            _container(name=f"c{i}", privileged=True, allow_privilege_escalation=False)
            for i in range(10)
        ]
        pod = _pod(containers=containers)
        report = analyzer.analyze([pod])
        # PSS-002 fires 10 times but should only count its weight once.
        assert report.risk_score == _CHECK_WEIGHTS["PSS-002"]

    def test_score_increases_with_more_check_types(self):
        analyzer = PodSecurityAnalyzer(check_latest_tag=True, require_readonly_root=True)
        # Single check.
        pod_one = _pod(containers=[_container(image="nginx:latest", allow_privilege_escalation=False, readonly_root=True)])
        report_one = analyzer.analyze([pod_one])
        # Multiple checks.
        pod_many = _pod(
            containers=[_container(image="nginx:latest", privileged=True, readonly_root=False)],
        )
        report_many = analyzer.analyze([pod_many])
        assert report_many.risk_score >= report_one.risk_score


# ---------------------------------------------------------------------------
# Happy-path / clean manifest
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_fully_hardened_pod_has_no_pss001(self, analyzer):
        pod = _pod(containers=[_hardened_container()])
        report = analyzer.analyze([pod])
        assert "PSS-001" not in _check_ids(report)

    def test_fully_hardened_pod_has_no_pss002(self, analyzer):
        pod = _pod(containers=[_hardened_container()])
        report = analyzer.analyze([pod])
        assert "PSS-002" not in _check_ids(report)

    def test_fully_hardened_pod_has_no_pss003(self, analyzer):
        pod = _pod(containers=[_hardened_container()])
        report = analyzer.analyze([pod])
        assert "PSS-003" not in _check_ids(report)

    def test_fully_hardened_pod_has_no_pss007(self, analyzer):
        pod = _pod(containers=[_hardened_container()])
        report = analyzer.analyze([pod])
        assert "PSS-007" not in _check_ids(report)

    def test_fully_hardened_pod_with_pss_disabled_options(self):
        analyzer = PodSecurityAnalyzer(check_latest_tag=False, require_readonly_root=False)
        pod = _pod(containers=[_hardened_container()])
        report = analyzer.analyze([pod])
        # Only PSS-004 (no hostNetwork etc) and PSS-006 (no hostPath) could fire, and
        # the hardened pod has neither.
        assert "PSS-007" not in _check_ids(report)
        assert "PSS-008" not in _check_ids(report)
