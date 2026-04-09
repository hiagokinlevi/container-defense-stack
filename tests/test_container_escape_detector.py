# CC BY 4.0 — Cyber Port Portfolio
# https://creativecommons.org/licenses/by/4.0/
#
# test_container_escape_detector.py
# pytest suite for container_escape_detector module.
# Run with:  python -m pytest tests/test_container_escape_detector.py -q

import sys
import os

# Allow imports from the kubernetes/ sibling directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "kubernetes"))

from container_escape_detector import (
    CEXFinding,
    CEXResult,
    _CHECK_WEIGHTS,
    _is_sensitive_host_path,
    analyze,
    analyze_many,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _pod(
    name="test-pod",
    namespace="default",
    containers=None,
    init_containers=None,
    volumes=None,
    host_pid=False,
    host_network=False,
    pod_sc=None,
) -> dict:
    """Build a minimal Pod manifest."""
    spec: dict = {}
    if containers is not None:
        spec["containers"] = containers
    if init_containers is not None:
        spec["initContainers"] = init_containers
    if volumes is not None:
        spec["volumes"] = volumes
    if host_pid:
        spec["hostPID"] = True
    if host_network:
        spec["hostNetwork"] = True
    if pod_sc is not None:
        spec["securityContext"] = pod_sc
    return {
        "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }


def _deployment(name="test-deploy", namespace="default", pod_spec=None) -> dict:
    """Build a minimal Deployment manifest wrapping the given pod spec."""
    return {
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "template": {
                "spec": pod_spec or {},
            }
        },
    }


def _statefulset(name="test-sts", namespace="default", pod_spec=None) -> dict:
    return {
        "kind": "StatefulSet",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"template": {"spec": pod_spec or {}}},
    }


def _daemonset(name="test-ds", namespace="default", pod_spec=None) -> dict:
    return {
        "kind": "DaemonSet",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"template": {"spec": pod_spec or {}}},
    }


def _container(name="app", sc=None) -> dict:
    c: dict = {"name": name}
    if sc is not None:
        c["securityContext"] = sc
    return c


def _host_path_vol(vol_name, path) -> dict:
    return {"name": vol_name, "hostPath": {"path": path}}


def _finding_ids(result: CEXResult):
    return [f.check_id for f in result.findings]


def _has_check(result: CEXResult, check_id: str) -> bool:
    return any(f.check_id == check_id for f in result.findings)


# ===========================================================================
# CEX-001: privileged container
# ===========================================================================


def test_cex001_privileged_true_fires():
    manifest = _pod(containers=[_container("app", sc={"privileged": True})])
    result = analyze(manifest)
    assert _has_check(result, "CEX-001")


def test_cex001_privileged_false_no_finding():
    manifest = _pod(containers=[_container("app", sc={"privileged": False})])
    result = analyze(manifest)
    assert not _has_check(result, "CEX-001")


def test_cex001_privileged_missing_no_finding():
    manifest = _pod(containers=[_container("app", sc={"runAsNonRoot": True})])
    result = analyze(manifest)
    assert not _has_check(result, "CEX-001")


def test_cex001_no_security_context_no_finding():
    manifest = _pod(containers=[_container("app")])
    result = analyze(manifest)
    assert not _has_check(result, "CEX-001")


def test_cex001_multiple_containers_one_privileged():
    manifest = _pod(
        containers=[
            _container("safe", sc={"privileged": False}),
            _container("priv", sc={"privileged": True}),
        ]
    )
    result = analyze(manifest)
    cex001 = [f for f in result.findings if f.check_id == "CEX-001"]
    assert len(cex001) == 1
    assert "priv" in cex001[0].detail


def test_cex001_multiple_containers_both_privileged():
    manifest = _pod(
        containers=[
            _container("a", sc={"privileged": True}),
            _container("b", sc={"privileged": True}),
        ]
    )
    result = analyze(manifest)
    cex001 = [f for f in result.findings if f.check_id == "CEX-001"]
    assert len(cex001) == 2


def test_cex001_init_container_privileged():
    manifest = _pod(
        containers=[_container("main")],
        init_containers=[_container("init", sc={"privileged": True})],
    )
    result = analyze(manifest)
    assert _has_check(result, "CEX-001")
    cex001 = [f for f in result.findings if f.check_id == "CEX-001"]
    assert "init" in cex001[0].detail


def test_cex001_severity_is_critical():
    manifest = _pod(containers=[_container("app", sc={"privileged": True})])
    result = analyze(manifest)
    cex001 = [f for f in result.findings if f.check_id == "CEX-001"]
    assert cex001[0].severity == "CRITICAL"


def test_cex001_weight_is_45():
    manifest = _pod(containers=[_container("app", sc={"privileged": True})])
    result = analyze(manifest)
    cex001 = [f for f in result.findings if f.check_id == "CEX-001"]
    assert cex001[0].weight == 45


def test_cex001_security_context_none_no_finding():
    # Explicit None should not trigger CEX-001 (only True does)
    manifest = _pod(containers=[{"name": "app", "securityContext": None}])
    result = analyze(manifest)
    assert not _has_check(result, "CEX-001")


# ===========================================================================
# CEX-002: hostPID
# ===========================================================================


def test_cex002_host_pid_true_fires():
    manifest = _pod(containers=[_container("app")], host_pid=True)
    result = analyze(manifest)
    assert _has_check(result, "CEX-002")


def test_cex002_host_pid_false_no_finding():
    manifest = _pod(containers=[_container("app")])
    result = analyze(manifest)
    assert not _has_check(result, "CEX-002")


def test_cex002_host_pid_explicit_false_no_finding():
    manifest = _pod(containers=[_container("app")])
    manifest["spec"]["hostPID"] = False
    result = analyze(manifest)
    assert not _has_check(result, "CEX-002")


def test_cex002_severity_is_critical():
    manifest = _pod(containers=[_container("app")], host_pid=True)
    result = analyze(manifest)
    cex002 = [f for f in result.findings if f.check_id == "CEX-002"]
    assert cex002[0].severity == "CRITICAL"


def test_cex002_weight_is_40():
    manifest = _pod(containers=[_container("app")], host_pid=True)
    result = analyze(manifest)
    cex002 = [f for f in result.findings if f.check_id == "CEX-002"]
    assert cex002[0].weight == 40


def test_cex002_only_one_finding_regardless_of_containers():
    manifest = _pod(
        containers=[_container("a"), _container("b"), _container("c")],
        host_pid=True,
    )
    result = analyze(manifest)
    cex002 = [f for f in result.findings if f.check_id == "CEX-002"]
    assert len(cex002) == 1


def test_cex002_deployment_wrapper():
    pod_spec = {"hostPID": True, "containers": [{"name": "app"}]}
    manifest = _deployment(pod_spec=pod_spec)
    result = analyze(manifest)
    assert _has_check(result, "CEX-002")


# ===========================================================================
# CEX-003: hostNetwork
# ===========================================================================


def test_cex003_host_network_true_fires():
    manifest = _pod(containers=[_container("app")], host_network=True)
    result = analyze(manifest)
    assert _has_check(result, "CEX-003")


def test_cex003_host_network_false_no_finding():
    manifest = _pod(containers=[_container("app")])
    result = analyze(manifest)
    assert not _has_check(result, "CEX-003")


def test_cex003_host_network_explicit_false_no_finding():
    manifest = _pod(containers=[_container("app")])
    manifest["spec"]["hostNetwork"] = False
    result = analyze(manifest)
    assert not _has_check(result, "CEX-003")


def test_cex003_severity_is_high():
    manifest = _pod(containers=[_container("app")], host_network=True)
    result = analyze(manifest)
    cex003 = [f for f in result.findings if f.check_id == "CEX-003"]
    assert cex003[0].severity == "HIGH"


def test_cex003_weight_is_25():
    manifest = _pod(containers=[_container("app")], host_network=True)
    result = analyze(manifest)
    cex003 = [f for f in result.findings if f.check_id == "CEX-003"]
    assert cex003[0].weight == 25


def test_cex003_only_one_finding():
    manifest = _pod(containers=[_container("a"), _container("b")], host_network=True)
    result = analyze(manifest)
    cex003 = [f for f in result.findings if f.check_id == "CEX-003"]
    assert len(cex003) == 1


def test_cex003_statefulset_wrapper():
    pod_spec = {"hostNetwork": True, "containers": [{"name": "app"}]}
    manifest = _statefulset(pod_spec=pod_spec)
    result = analyze(manifest)
    assert _has_check(result, "CEX-003")


# ===========================================================================
# CEX-004: container runtime socket
# ===========================================================================


def test_cex004_docker_socket_fires():
    vols = [_host_path_vol("docker-sock", "/var/run/docker.sock")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert _has_check(result, "CEX-004")


def test_cex004_containerd_socket_fires():
    vols = [_host_path_vol("containerd-sock", "/run/containerd/containerd.sock")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert _has_check(result, "CEX-004")


def test_cex004_safe_path_no_finding():
    vols = [_host_path_vol("data", "/data")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert not _has_check(result, "CEX-004")


def test_cex004_non_host_path_vol_no_finding():
    # emptyDir volume — no hostPath key
    vols = [{"name": "tmp", "emptyDir": {}}]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert not _has_check(result, "CEX-004")


def test_cex004_severity_is_critical():
    vols = [_host_path_vol("docker-sock", "/var/run/docker.sock")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    cex004 = [f for f in result.findings if f.check_id == "CEX-004"]
    assert cex004[0].severity == "CRITICAL"


def test_cex004_weight_is_45():
    vols = [_host_path_vol("docker-sock", "/var/run/docker.sock")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    cex004 = [f for f in result.findings if f.check_id == "CEX-004"]
    assert cex004[0].weight == 45


def test_cex004_both_sockets_two_findings():
    vols = [
        _host_path_vol("docker-sock", "/var/run/docker.sock"),
        _host_path_vol("containerd-sock", "/run/containerd/containerd.sock"),
    ]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    cex004 = [f for f in result.findings if f.check_id == "CEX-004"]
    assert len(cex004) == 2


def test_cex004_vol_name_in_detail():
    vols = [_host_path_vol("my-sock", "/var/run/docker.sock")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    cex004 = [f for f in result.findings if f.check_id == "CEX-004"]
    assert "my-sock" in cex004[0].detail


def test_cex004_daemonset_wrapper():
    pod_spec = {
        "containers": [{"name": "app"}],
        "volumes": [_host_path_vol("sock", "/var/run/docker.sock")],
    }
    manifest = _daemonset(pod_spec=pod_spec)
    result = analyze(manifest)
    assert _has_check(result, "CEX-004")


# ===========================================================================
# CEX-005: dangerous capabilities
# ===========================================================================


def test_cex005_sys_admin_fires():
    sc = {"capabilities": {"add": ["SYS_ADMIN"]}}
    manifest = _pod(containers=[_container("app", sc=sc)])
    result = analyze(manifest)
    assert _has_check(result, "CEX-005")


def test_cex005_sys_ptrace_fires():
    sc = {"capabilities": {"add": ["SYS_PTRACE"]}}
    manifest = _pod(containers=[_container("app", sc=sc)])
    result = analyze(manifest)
    assert _has_check(result, "CEX-005")


def test_cex005_sys_module_fires():
    sc = {"capabilities": {"add": ["SYS_MODULE"]}}
    manifest = _pod(containers=[_container("app", sc=sc)])
    result = analyze(manifest)
    assert _has_check(result, "CEX-005")


def test_cex005_dac_override_fires():
    sc = {"capabilities": {"add": ["DAC_OVERRIDE"]}}
    manifest = _pod(containers=[_container("app", sc=sc)])
    result = analyze(manifest)
    assert _has_check(result, "CEX-005")


def test_cex005_net_admin_fires():
    sc = {"capabilities": {"add": ["NET_ADMIN"]}}
    manifest = _pod(containers=[_container("app", sc=sc)])
    result = analyze(manifest)
    assert _has_check(result, "CEX-005")


def test_cex005_safe_cap_no_finding():
    sc = {"capabilities": {"add": ["NET_BIND_SERVICE"]}}
    manifest = _pod(containers=[_container("app", sc=sc)])
    result = analyze(manifest)
    assert not _has_check(result, "CEX-005")


def test_cex005_drop_only_no_finding():
    sc = {"capabilities": {"drop": ["ALL"]}}
    manifest = _pod(containers=[_container("app", sc=sc)])
    result = analyze(manifest)
    assert not _has_check(result, "CEX-005")


def test_cex005_no_caps_no_finding():
    manifest = _pod(containers=[_container("app", sc={})])
    result = analyze(manifest)
    assert not _has_check(result, "CEX-005")


def test_cex005_multiple_dangerous_caps_single_finding():
    sc = {"capabilities": {"add": ["SYS_ADMIN", "NET_ADMIN"]}}
    manifest = _pod(containers=[_container("app", sc=sc)])
    result = analyze(manifest)
    cex005 = [f for f in result.findings if f.check_id == "CEX-005"]
    assert len(cex005) == 1
    # Both caps should appear in the detail string
    assert "SYS_ADMIN" in cex005[0].detail
    assert "NET_ADMIN" in cex005[0].detail


def test_cex005_two_containers_both_dangerous_two_findings():
    sc = {"capabilities": {"add": ["SYS_ADMIN"]}}
    manifest = _pod(
        containers=[_container("a", sc=sc), _container("b", sc=sc)]
    )
    result = analyze(manifest)
    cex005 = [f for f in result.findings if f.check_id == "CEX-005"]
    assert len(cex005) == 2


def test_cex005_init_container_dangerous_cap():
    sc = {"capabilities": {"add": ["SYS_MODULE"]}}
    manifest = _pod(
        containers=[_container("main")],
        init_containers=[_container("init", sc=sc)],
    )
    result = analyze(manifest)
    assert _has_check(result, "CEX-005")


def test_cex005_severity_is_high():
    sc = {"capabilities": {"add": ["SYS_ADMIN"]}}
    manifest = _pod(containers=[_container("app", sc=sc)])
    result = analyze(manifest)
    cex005 = [f for f in result.findings if f.check_id == "CEX-005"]
    assert cex005[0].severity == "HIGH"


def test_cex005_weight_is_30():
    sc = {"capabilities": {"add": ["SYS_ADMIN"]}}
    manifest = _pod(containers=[_container("app", sc=sc)])
    result = analyze(manifest)
    cex005 = [f for f in result.findings if f.check_id == "CEX-005"]
    assert cex005[0].weight == 30


def test_cex005_lowercase_cap_is_normalised():
    # Some users write caps in lowercase
    sc = {"capabilities": {"add": ["sys_admin"]}}
    manifest = _pod(containers=[_container("app", sc=sc)])
    result = analyze(manifest)
    assert _has_check(result, "CEX-005")


# ===========================================================================
# CEX-006: sensitive host path
# ===========================================================================


def test_cex006_root_path_fires():
    vols = [_host_path_vol("root", "/")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert _has_check(result, "CEX-006")


def test_cex006_etc_fires():
    vols = [_host_path_vol("etc", "/etc")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert _has_check(result, "CEX-006")


def test_cex006_etc_subpath_fires():
    vols = [_host_path_vol("shadow", "/etc/shadow")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert _has_check(result, "CEX-006")


def test_cex006_proc_fires():
    vols = [_host_path_vol("proc", "/proc")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert _has_check(result, "CEX-006")


def test_cex006_sys_fires():
    vols = [_host_path_vol("sys", "/sys")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert _has_check(result, "CEX-006")


def test_cex006_var_log_fires():
    vols = [_host_path_vol("logs", "/var/log")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert _has_check(result, "CEX-006")


def test_cex006_var_log_subpath_fires():
    vols = [_host_path_vol("syslog", "/var/log/syslog")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert _has_check(result, "CEX-006")


def test_cex006_boot_fires():
    vols = [_host_path_vol("boot", "/boot")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert _has_check(result, "CEX-006")


def test_cex006_usr_fires():
    vols = [_host_path_vol("usr", "/usr")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert _has_check(result, "CEX-006")


def test_cex006_safe_data_path_no_finding():
    vols = [_host_path_vol("data", "/data")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert not _has_check(result, "CEX-006")


def test_cex006_safe_app_path_no_finding():
    vols = [_host_path_vol("app-data", "/app/data")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert not _has_check(result, "CEX-006")


def test_cex006_docker_socket_excluded():
    # /var/run/docker.sock should be caught by CEX-004, NOT CEX-006
    vols = [_host_path_vol("docker-sock", "/var/run/docker.sock")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert not _has_check(result, "CEX-006")
    assert _has_check(result, "CEX-004")


def test_cex006_containerd_socket_excluded():
    vols = [_host_path_vol("ctr-sock", "/run/containerd/containerd.sock")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert not _has_check(result, "CEX-006")
    assert _has_check(result, "CEX-004")


def test_cex006_severity_is_high():
    vols = [_host_path_vol("etc", "/etc")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    cex006 = [f for f in result.findings if f.check_id == "CEX-006"]
    assert cex006[0].severity == "HIGH"


def test_cex006_weight_is_25():
    vols = [_host_path_vol("etc", "/etc")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    cex006 = [f for f in result.findings if f.check_id == "CEX-006"]
    assert cex006[0].weight == 25


def test_cex006_multiple_sensitive_vols_multiple_findings():
    vols = [_host_path_vol("etc", "/etc"), _host_path_vol("proc", "/proc")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    cex006 = [f for f in result.findings if f.check_id == "CEX-006"]
    assert len(cex006) == 2


def test_cex006_var_path_no_false_positive():
    # /var alone is NOT in the sensitive list; /var/log is
    vols = [_host_path_vol("var", "/var")]
    manifest = _pod(containers=[_container("app")], volumes=vols)
    result = analyze(manifest)
    assert not _has_check(result, "CEX-006")


# ===========================================================================
# CEX-007: missing security context
# ===========================================================================


def test_cex007_no_sc_anywhere_fires():
    manifest = _pod(containers=[_container("app")])
    result = analyze(manifest)
    assert _has_check(result, "CEX-007")


def test_cex007_container_sc_present_no_finding():
    manifest = _pod(containers=[_container("app", sc={"runAsNonRoot": True})])
    result = analyze(manifest)
    assert not _has_check(result, "CEX-007")


def test_cex007_pod_sc_suppresses_finding():
    manifest = _pod(
        containers=[_container("app")],
        pod_sc={"runAsNonRoot": True},
    )
    result = analyze(manifest)
    assert not _has_check(result, "CEX-007")


def test_cex007_empty_pod_sc_still_fires():
    # Empty dict pod-level SC should not suppress the check
    manifest = _pod(containers=[_container("app")], pod_sc={})
    result = analyze(manifest)
    assert _has_check(result, "CEX-007")


def test_cex007_explicit_none_container_sc_fires():
    manifest = _pod(containers=[{"name": "app", "securityContext": None}])
    result = analyze(manifest)
    assert _has_check(result, "CEX-007")


def test_cex007_empty_dict_container_sc_fires():
    manifest = _pod(containers=[{"name": "app", "securityContext": {}}])
    result = analyze(manifest)
    assert _has_check(result, "CEX-007")


def test_cex007_two_containers_both_missing_two_findings():
    manifest = _pod(containers=[_container("a"), _container("b")])
    result = analyze(manifest)
    cex007 = [f for f in result.findings if f.check_id == "CEX-007"]
    assert len(cex007) == 2


def test_cex007_init_container_no_sc_fires():
    manifest = _pod(
        containers=[_container("main", sc={"runAsNonRoot": True})],
        init_containers=[_container("init")],
    )
    result = analyze(manifest)
    cex007 = [f for f in result.findings if f.check_id == "CEX-007"]
    assert len(cex007) == 1
    assert "init" in cex007[0].detail


def test_cex007_severity_is_medium():
    manifest = _pod(containers=[_container("app")])
    result = analyze(manifest)
    cex007 = [f for f in result.findings if f.check_id == "CEX-007"]
    assert cex007[0].severity == "MEDIUM"


def test_cex007_weight_is_15():
    manifest = _pod(containers=[_container("app")])
    result = analyze(manifest)
    cex007 = [f for f in result.findings if f.check_id == "CEX-007"]
    assert cex007[0].weight == 15


def test_cex007_partial_sc_present_suppresses():
    # Container has a non-empty SC even without runAsNonRoot — still present
    manifest = _pod(containers=[_container("app", sc={"allowPrivilegeEscalation": False})])
    result = analyze(manifest)
    assert not _has_check(result, "CEX-007")


# ===========================================================================
# Risk score and escape_risk label
# ===========================================================================


def test_risk_score_deduplication():
    # Two privileged containers both fire CEX-001 but weight is counted once
    manifest = _pod(
        containers=[
            _container("a", sc={"privileged": True}),
            _container("b", sc={"privileged": True}),
        ]
    )
    result = analyze(manifest)
    assert result.risk_score == 45  # CEX-001 weight = 45, counted once


def test_risk_score_capped_at_100():
    # Trigger enough checks to exceed 100
    # CEX-001(45) + CEX-002(40) + CEX-004(45) = 130, should be capped at 100
    vols = [_host_path_vol("sock", "/var/run/docker.sock")]
    manifest = _pod(
        containers=[_container("app", sc={"privileged": True})],
        host_pid=True,
        volumes=vols,
    )
    result = analyze(manifest)
    assert result.risk_score == 100


def test_risk_score_multiple_unique_checks():
    # CEX-002(40) + CEX-003(25) = 65
    manifest = _pod(
        containers=[_container("app", sc={"runAsNonRoot": True})],
        host_pid=True,
        host_network=True,
    )
    result = analyze(manifest)
    assert result.risk_score == 65


def test_escape_risk_critical_gte_80():
    # CEX-001(45) + CEX-002(40) = 85 -> CRITICAL
    manifest = _pod(
        containers=[_container("app", sc={"privileged": True})],
        host_pid=True,
    )
    result = analyze(manifest)
    assert result.risk_score == 85
    assert result.escape_risk == "CRITICAL"


def test_escape_risk_high_50_to_79():
    # CEX-002(40) + CEX-003(25) = 65 -> HIGH
    manifest = _pod(
        containers=[_container("app", sc={"runAsNonRoot": True})],
        host_pid=True,
        host_network=True,
    )
    result = analyze(manifest)
    assert result.escape_risk == "HIGH"


def test_escape_risk_medium_20_to_49():
    # CEX-003(25) only -> MEDIUM
    manifest = _pod(
        containers=[_container("app", sc={"runAsNonRoot": True})],
        host_network=True,
    )
    result = analyze(manifest)
    assert result.escape_risk == "MEDIUM"


def test_escape_risk_low_below_20():
    # CEX-007(15) only -> LOW
    manifest = _pod(containers=[_container("app")])
    result = analyze(manifest)
    assert result.risk_score == 15
    assert result.escape_risk == "LOW"


def test_escape_risk_zero_no_findings():
    # Container with explicit safe SC, no host flags
    manifest = _pod(containers=[_container("app", sc={"runAsNonRoot": True})])
    result = analyze(manifest)
    assert result.risk_score == 0
    assert result.escape_risk == "LOW"
    assert len(result.findings) == 0


# ===========================================================================
# Workload kind and metadata parsing
# ===========================================================================


def test_workload_kind_pod():
    manifest = _pod(name="my-pod", namespace="prod", containers=[_container()])
    result = analyze(manifest)
    assert result.workload_kind == "Pod"
    assert result.workload_name == "my-pod"
    assert result.namespace == "prod"


def test_workload_kind_deployment():
    pod_spec = {"containers": [{"name": "app", "securityContext": {"runAsNonRoot": True}}]}
    manifest = _deployment(name="my-deploy", namespace="staging", pod_spec=pod_spec)
    result = analyze(manifest)
    assert result.workload_kind == "Deployment"
    assert result.workload_name == "my-deploy"
    assert result.namespace == "staging"


def test_workload_kind_statefulset():
    pod_spec = {"containers": [{"name": "app", "securityContext": {"runAsNonRoot": True}}]}
    manifest = _statefulset(name="my-sts", namespace="db", pod_spec=pod_spec)
    result = analyze(manifest)
    assert result.workload_kind == "StatefulSet"


def test_workload_kind_daemonset():
    pod_spec = {"containers": [{"name": "app", "securityContext": {"runAsNonRoot": True}}]}
    manifest = _daemonset(name="my-ds", namespace="monitoring", pod_spec=pod_spec)
    result = analyze(manifest)
    assert result.workload_kind == "DaemonSet"


def test_namespace_defaults_to_default():
    manifest = {
        "kind": "Pod",
        "metadata": {"name": "no-ns"},
        "spec": {"containers": [{"name": "app", "securityContext": {"runAsNonRoot": True}}]},
    }
    result = analyze(manifest)
    assert result.namespace == "default"


# ===========================================================================
# CEXResult helper methods
# ===========================================================================


def test_to_dict_structure():
    manifest = _pod(
        containers=[_container("app", sc={"privileged": True})],
        host_pid=True,
    )
    result = analyze(manifest)
    d = result.to_dict()
    assert d["workload_name"] == "test-pod"
    assert d["workload_kind"] == "Pod"
    assert d["namespace"] == "default"
    assert isinstance(d["risk_score"], int)
    assert isinstance(d["escape_risk"], str)
    assert isinstance(d["findings"], list)
    assert len(d["findings"]) >= 1
    first = d["findings"][0]
    assert "check_id" in first
    assert "severity" in first
    assert "title" in first
    assert "detail" in first
    assert "weight" in first


def test_summary_contains_key_fields():
    manifest = _pod(containers=[_container("app", sc={"privileged": True})], host_pid=True)
    result = analyze(manifest)
    s = result.summary()
    assert "Pod" in s
    assert "test-pod" in s
    assert "default" in s
    assert "CRITICAL" in s


def test_by_severity_groups_correctly():
    # CEX-001 (CRITICAL) + CEX-007 (MEDIUM) — container has privileged+no other sc fields
    manifest = _pod(
        containers=[_container("app", sc={"privileged": True})],
        # no pod-level SC, so CEX-007 fires too (container SC is non-empty due to privileged=True,
        # so CEX-007 should NOT fire here — adjust fixture)
    )
    result = analyze(manifest)
    groups = result.by_severity()
    # All findings grouped correctly
    for finding in result.findings:
        assert finding in groups[finding.severity]


def test_by_severity_medium_only():
    manifest = _pod(containers=[_container("app")])  # only CEX-007 fires
    result = analyze(manifest)
    groups = result.by_severity()
    assert "MEDIUM" in groups
    assert all(f.check_id == "CEX-007" for f in groups["MEDIUM"])


# ===========================================================================
# analyze_many
# ===========================================================================


def test_analyze_many_returns_list():
    manifests = [
        _pod(name="pod-1", containers=[_container("app")]),
        _pod(name="pod-2", containers=[_container("app")]),
    ]
    results = analyze_many(manifests)
    assert isinstance(results, list)
    assert len(results) == 2


def test_analyze_many_preserves_order():
    manifests = [
        _pod(name="alpha", containers=[_container("app")]),
        _pod(name="beta", containers=[_container("app")]),
        _pod(name="gamma", containers=[_container("app")]),
    ]
    results = analyze_many(manifests)
    assert [r.workload_name for r in results] == ["alpha", "beta", "gamma"]


def test_analyze_many_empty_list():
    assert analyze_many([]) == []


def test_analyze_many_mixed_kinds():
    manifests = [
        _pod(name="p", containers=[_container("app", sc={"runAsNonRoot": True})]),
        _deployment(
            name="d",
            pod_spec={"containers": [{"name": "app", "securityContext": {"runAsNonRoot": True}}]},
        ),
        _statefulset(
            name="s",
            pod_spec={"containers": [{"name": "app", "securityContext": {"runAsNonRoot": True}}]},
        ),
    ]
    results = analyze_many(manifests)
    kinds = [r.workload_kind for r in results]
    assert kinds == ["Pod", "Deployment", "StatefulSet"]


# ===========================================================================
# _is_sensitive_host_path unit tests
# ===========================================================================


def test_is_sensitive_host_path_root():
    assert _is_sensitive_host_path("/") is True


def test_is_sensitive_host_path_etc():
    assert _is_sensitive_host_path("/etc") is True


def test_is_sensitive_host_path_etc_shadow():
    assert _is_sensitive_host_path("/etc/shadow") is True


def test_is_sensitive_host_path_proc():
    assert _is_sensitive_host_path("/proc") is True


def test_is_sensitive_host_path_sys():
    assert _is_sensitive_host_path("/sys") is True


def test_is_sensitive_host_path_var_log():
    assert _is_sensitive_host_path("/var/log") is True


def test_is_sensitive_host_path_boot():
    assert _is_sensitive_host_path("/boot") is True


def test_is_sensitive_host_path_usr():
    assert _is_sensitive_host_path("/usr") is True


def test_is_sensitive_host_path_data():
    assert _is_sensitive_host_path("/data") is False


def test_is_sensitive_host_path_tmp():
    assert _is_sensitive_host_path("/tmp") is False


def test_is_sensitive_host_path_home():
    assert _is_sensitive_host_path("/home") is False


def test_is_sensitive_host_path_var_only():
    # /var itself is not in the list
    assert _is_sensitive_host_path("/var") is False


def test_is_sensitive_host_path_usr_local():
    assert _is_sensitive_host_path("/usr/local") is True


def test_is_sensitive_host_path_run_other():
    # /run is not in the sensitive list (only specific sockets are)
    assert _is_sensitive_host_path("/run") is False


# ===========================================================================
# _CHECK_WEIGHTS integrity
# ===========================================================================


def test_check_weights_all_ids_present():
    expected = {"CEX-001", "CEX-002", "CEX-003", "CEX-004", "CEX-005", "CEX-006", "CEX-007"}
    assert set(_CHECK_WEIGHTS.keys()) == expected


def test_check_weights_values():
    assert _CHECK_WEIGHTS["CEX-001"] == 45
    assert _CHECK_WEIGHTS["CEX-002"] == 40
    assert _CHECK_WEIGHTS["CEX-003"] == 25
    assert _CHECK_WEIGHTS["CEX-004"] == 45
    assert _CHECK_WEIGHTS["CEX-005"] == 30
    assert _CHECK_WEIGHTS["CEX-006"] == 25
    assert _CHECK_WEIGHTS["CEX-007"] == 15


# ===========================================================================
# Combined / integration scenarios
# ===========================================================================


def test_all_checks_fire_simultaneously():
    # Build a manifest that triggers every check
    vols = [
        _host_path_vol("sock", "/var/run/docker.sock"),
        _host_path_vol("etc", "/etc"),
    ]
    sc = {"privileged": True, "capabilities": {"add": ["SYS_ADMIN"]}}
    manifest = _pod(
        containers=[_container("app", sc=sc)],
        host_pid=True,
        host_network=True,
        volumes=vols,
    )
    result = analyze(manifest)
    fired = {f.check_id for f in result.findings}
    # CEX-007 should NOT fire because sc is non-empty
    assert "CEX-001" in fired
    assert "CEX-002" in fired
    assert "CEX-003" in fired
    assert "CEX-004" in fired
    assert "CEX-005" in fired
    assert "CEX-006" in fired
    # Risk score capped at 100
    assert result.risk_score == 100
    assert result.escape_risk == "CRITICAL"


def test_deployment_with_privileged_container():
    pod_spec = {
        "hostPID": True,
        "containers": [{"name": "app", "securityContext": {"privileged": True}}],
    }
    manifest = _deployment(name="evil-deploy", namespace="kube-system", pod_spec=pod_spec)
    result = analyze(manifest)
    assert result.workload_kind == "Deployment"
    assert _has_check(result, "CEX-001")
    assert _has_check(result, "CEX-002")
    assert result.risk_score == 85  # 45 + 40
    assert result.escape_risk == "CRITICAL"


def test_clean_pod_no_findings():
    sc = {
        "runAsNonRoot": True,
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }
    manifest = _pod(
        containers=[_container("app", sc=sc)],
        pod_sc={"runAsNonRoot": True},
    )
    result = analyze(manifest)
    assert len(result.findings) == 0
    assert result.risk_score == 0
    assert result.escape_risk == "LOW"


def test_init_containers_included_in_all_checks():
    # Init container is privileged, main container is clean
    pod_sc = {"runAsNonRoot": True}
    manifest = _pod(
        containers=[_container("main", sc={"runAsNonRoot": True})],
        init_containers=[_container("init", sc={"privileged": True})],
        pod_sc=pod_sc,
    )
    result = analyze(manifest)
    assert _has_check(result, "CEX-001")
    cex001 = [f for f in result.findings if f.check_id == "CEX-001"]
    assert "init" in cex001[0].detail


def test_result_is_cex_result_instance():
    manifest = _pod(containers=[_container("app")])
    result = analyze(manifest)
    assert isinstance(result, CEXResult)


def test_findings_are_cex_finding_instances():
    manifest = _pod(containers=[_container("app", sc={"privileged": True})])
    result = analyze(manifest)
    for f in result.findings:
        assert isinstance(f, CEXFinding)
