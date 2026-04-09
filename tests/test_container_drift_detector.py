# test_container_drift_detector.py
# Tests for the container_drift_detector module — Cyber Port portfolio.
#
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# Run with:  python -m pytest tests/test_container_drift_detector.py -q
"""
110+ unit tests for container_drift_detector, grouped by check ID.

All tests are pure data-processing — no mocking required.
"""

import sys
import os

# Allow imports from the runtime package without installing the project.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from runtime.container_drift_detector import (
    ContainerBaseline,
    DRIFTFinding,
    DRIFTResult,
    FileEvent,
    NetworkConnection,
    ProcessInfo,
    RuntimeState,
    _calc_drift_level,
    _starts_with_any,
    detect,
    detect_many,
)

# ---------------------------------------------------------------------------
# Shared fixture factories
# ---------------------------------------------------------------------------


def make_baseline(
    container_id: str = "ctr-001",
    expected_processes=None,
    expected_uid: int = 1000,
    expected_connections=None,
    writable_paths=None,
    expected_env_vars=None,
    baseline_cpu_percent: float = 10.0,
    baseline_memory_mb: float = 256.0,
) -> ContainerBaseline:
    return ContainerBaseline(
        container_id=container_id,
        expected_processes=expected_processes if expected_processes is not None else ["nginx", "sh"],
        expected_uid=expected_uid,
        expected_connections=expected_connections if expected_connections is not None else [],
        writable_paths=writable_paths if writable_paths is not None else ["/tmp", "/var/log"],
        expected_env_vars=expected_env_vars if expected_env_vars is not None else {"HOME": "/root", "PATH": "/usr/bin"},
        baseline_cpu_percent=baseline_cpu_percent,
        baseline_memory_mb=baseline_memory_mb,
    )


def make_state(
    container_id: str = "ctr-001",
    processes=None,
    network_connections=None,
    file_events=None,
    env_vars=None,
    cpu_usage_percent: float = 5.0,
    memory_usage_mb: float = 128.0,
) -> RuntimeState:
    return RuntimeState(
        container_id=container_id,
        processes=processes if processes is not None else [],
        network_connections=network_connections if network_connections is not None else [],
        file_events=file_events if file_events is not None else [],
        env_vars=env_vars if env_vars is not None else {"HOME": "/root", "PATH": "/usr/bin"},
        cpu_usage_percent=cpu_usage_percent,
        memory_usage_mb=memory_usage_mb,
    )


def make_process(pid=1, name="nginx", cmdline="nginx -g", uid=1000) -> ProcessInfo:
    return ProcessInfo(pid=pid, name=name, cmdline=cmdline, uid=uid)


def make_conn(remote_ip="1.2.3.4", remote_port=80, protocol="tcp") -> NetworkConnection:
    return NetworkConnection(remote_ip=remote_ip, remote_port=remote_port, protocol=protocol)


def make_file_event(path="/tmp/file.txt", event_type="write", executable=False) -> FileEvent:
    return FileEvent(path=path, event_type=event_type, executable=executable)


# ---------------------------------------------------------------------------
# Helper — run detect and assert a single finding exists for a check
# ---------------------------------------------------------------------------

def get_finding(result: DRIFTResult, check_id: str) -> DRIFTFinding:
    matches = [f for f in result.findings if f.check_id == check_id]
    assert matches, f"Expected finding {check_id} not present. Findings: {[f.check_id for f in result.findings]}"
    return matches[0]


def no_finding(result: DRIFTResult, check_id: str) -> None:
    matches = [f for f in result.findings if f.check_id == check_id]
    assert not matches, f"Unexpected finding {check_id} present."


# ===========================================================================
# Internal utility tests
# ===========================================================================

class TestStartsWithAny:
    def test_exact_match(self):
        assert _starts_with_any("/etc", ["/etc"]) is True

    def test_subpath_match(self):
        assert _starts_with_any("/etc/passwd", ["/etc"]) is True

    def test_no_match(self):
        assert _starts_with_any("/home/user", ["/etc", "/usr"]) is False

    def test_partial_name_not_matched(self):
        # /etcfoo should NOT match /etc prefix
        assert _starts_with_any("/etcfoo/bar", ["/etc"]) is False

    def test_multiple_prefixes_second_matches(self):
        assert _starts_with_any("/usr/bin/python", ["/tmp", "/usr"]) is True

    def test_empty_prefixes(self):
        assert _starts_with_any("/etc/passwd", []) is False

    def test_deep_nested_path_match(self):
        # A deeply nested path must still match the top-level prefix.
        assert _starts_with_any("/usr/local/bin/python3", ["/usr"]) is True


class TestCalcDriftLevel:
    def test_none(self):
        assert _calc_drift_level(0) == "NONE"

    def test_low_boundary(self):
        assert _calc_drift_level(1) == "LOW"
        assert _calc_drift_level(20) == "LOW"

    def test_medium_boundary(self):
        assert _calc_drift_level(21) == "MEDIUM"
        assert _calc_drift_level(45) == "MEDIUM"

    def test_high_boundary(self):
        assert _calc_drift_level(46) == "HIGH"
        assert _calc_drift_level(70) == "HIGH"

    def test_critical_boundary(self):
        assert _calc_drift_level(71) == "CRITICAL"
        assert _calc_drift_level(100) == "CRITICAL"


# ===========================================================================
# DRIFT-001 — Unexpected process
# ===========================================================================

class TestDrift001:
    def test_001_no_processes_no_finding(self):
        state = make_state(processes=[])
        result = detect(state, make_baseline())
        no_finding(result, "DRIFT-001")

    def test_001_all_expected_processes_no_finding(self):
        state = make_state(processes=[make_process(name="nginx"), make_process(name="sh")])
        result = detect(state, make_baseline(expected_processes=["nginx", "sh"]))
        no_finding(result, "DRIFT-001")

    def test_001_single_unknown_process_fires(self):
        state = make_state(processes=[make_process(name="cryptominer")])
        result = detect(state, make_baseline(expected_processes=["nginx"]))
        f = get_finding(result, "DRIFT-001")
        assert "cryptominer" in f.detail
        assert f.severity == "HIGH"
        assert f.weight == 25

    def test_001_multiple_unknown_processes_one_finding(self):
        procs = [make_process(name="evil1"), make_process(name="evil2")]
        state = make_state(processes=procs)
        result = detect(state, make_baseline(expected_processes=["nginx"]))
        findings_001 = [f for f in result.findings if f.check_id == "DRIFT-001"]
        assert len(findings_001) == 1, "Weight counted once even with multiple unknown processes"

    def test_001_detail_lists_all_unique_names(self):
        procs = [
            make_process(pid=1, name="nc"),
            make_process(pid=2, name="bash"),
            make_process(pid=3, name="nc"),   # duplicate name, deduped in detail
        ]
        state = make_state(processes=procs)
        result = detect(state, make_baseline(expected_processes=["nginx"]))
        f = get_finding(result, "DRIFT-001")
        assert "nc" in f.detail
        assert "bash" in f.detail

    def test_001_mix_expected_and_unexpected(self):
        procs = [make_process(name="nginx"), make_process(name="evil")]
        state = make_state(processes=procs)
        result = detect(state, make_baseline(expected_processes=["nginx"]))
        f = get_finding(result, "DRIFT-001")
        assert "evil" in f.detail
        assert "nginx" not in f.detail

    def test_001_weight_counted_once(self):
        procs = [make_process(name="a"), make_process(name="b"), make_process(name="c")]
        state = make_state(processes=procs)
        result = detect(state, make_baseline(expected_processes=[]))
        assert result.risk_score == 25  # only DRIFT-001 fires, weight=25

    def test_001_empty_expected_list_all_fire(self):
        state = make_state(processes=[make_process(name="sh")])
        result = detect(state, make_baseline(expected_processes=[]))
        get_finding(result, "DRIFT-001")

    def test_001_case_sensitive_name_match(self):
        # "Nginx" != "nginx" — should fire
        state = make_state(processes=[make_process(name="Nginx")])
        result = detect(state, make_baseline(expected_processes=["nginx"]))
        get_finding(result, "DRIFT-001")


# ===========================================================================
# DRIFT-002 — File write to protected path
# ===========================================================================

class TestDrift002:
    def test_002_no_file_events_no_finding(self):
        state = make_state(file_events=[])
        result = detect(state, make_baseline())
        no_finding(result, "DRIFT-002")

    def test_002_write_to_writable_path_no_finding(self):
        event = make_file_event(path="/tmp/output.log", event_type="write")
        state = make_state(file_events=[event])
        result = detect(state, make_baseline(writable_paths=["/tmp"]))
        no_finding(result, "DRIFT-002")

    def test_002_write_to_etc_fires(self):
        event = make_file_event(path="/etc/passwd", event_type="write")
        state = make_state(file_events=[event])
        result = detect(state, make_baseline())
        f = get_finding(result, "DRIFT-002")
        assert "/etc/passwd" in f.detail
        assert f.severity == "CRITICAL"
        assert f.weight == 45

    def test_002_write_to_usr_fires(self):
        event = make_file_event(path="/usr/bin/evil", event_type="write")
        state = make_state(file_events=[event])
        result = detect(state, make_baseline())
        get_finding(result, "DRIFT-002")

    def test_002_write_to_bin_fires(self):
        event = make_file_event(path="/bin/sh", event_type="write")
        state = make_state(file_events=[event])
        result = detect(state, make_baseline())
        get_finding(result, "DRIFT-002")

    def test_002_write_to_sbin_fires(self):
        event = make_file_event(path="/sbin/init", event_type="write")
        state = make_state(file_events=[event])
        result = detect(state, make_baseline())
        get_finding(result, "DRIFT-002")

    def test_002_write_to_lib_fires(self):
        event = make_file_event(path="/lib/x86_64-linux-gnu/libc.so.6", event_type="write")
        state = make_state(file_events=[event])
        result = detect(state, make_baseline())
        get_finding(result, "DRIFT-002")

    def test_002_write_to_boot_fires(self):
        event = make_file_event(path="/boot/vmlinuz", event_type="write")
        state = make_state(file_events=[event])
        result = detect(state, make_baseline())
        get_finding(result, "DRIFT-002")

    def test_002_create_to_protected_fires(self):
        event = make_file_event(path="/etc/cron.d/evil", event_type="create")
        state = make_state(file_events=[event])
        result = detect(state, make_baseline())
        get_finding(result, "DRIFT-002")

    def test_002_delete_event_no_finding(self):
        # delete is not write or create — should not fire DRIFT-002
        event = make_file_event(path="/etc/passwd", event_type="delete")
        state = make_state(file_events=[event])
        result = detect(state, make_baseline())
        no_finding(result, "DRIFT-002")

    def test_002_chmod_event_no_finding(self):
        event = make_file_event(path="/etc/passwd", event_type="chmod")
        state = make_state(file_events=[event])
        result = detect(state, make_baseline())
        no_finding(result, "DRIFT-002")

    def test_002_writable_path_overrides_protected(self):
        # If /etc/myapp is in writable_paths, writes there are allowed.
        event = make_file_event(path="/etc/myapp/config", event_type="write")
        state = make_state(file_events=[event])
        result = detect(state, make_baseline(writable_paths=["/etc/myapp", "/tmp"]))
        no_finding(result, "DRIFT-002")

    def test_002_write_outside_protected_no_finding(self):
        event = make_file_event(path="/home/user/data.txt", event_type="write")
        state = make_state(file_events=[event])
        result = detect(state, make_baseline())
        no_finding(result, "DRIFT-002")

    def test_002_multiple_violations_one_finding(self):
        events = [
            make_file_event(path="/etc/hosts", event_type="write"),
            make_file_event(path="/usr/local/evil", event_type="write"),
        ]
        state = make_state(file_events=events)
        result = detect(state, make_baseline())
        findings_002 = [f for f in result.findings if f.check_id == "DRIFT-002"]
        assert len(findings_002) == 1

    def test_002_detail_contains_all_violating_paths(self):
        events = [
            make_file_event(path="/etc/hosts", event_type="write"),
            make_file_event(path="/bin/evil", event_type="create"),
        ]
        state = make_state(file_events=events)
        result = detect(state, make_baseline())
        f = get_finding(result, "DRIFT-002")
        assert "/etc/hosts" in f.detail
        assert "/bin/evil" in f.detail

    def test_002_exact_protected_path_fires(self):
        # Exactly /etc (edge: path == prefix exactly)
        event = make_file_event(path="/etc", event_type="write")
        state = make_state(file_events=[event])
        result = detect(state, make_baseline())
        get_finding(result, "DRIFT-002")

    def test_002_etcfoo_does_not_fire(self):
        # /etcfoo should NOT match /etc protected prefix
        event = make_file_event(path="/etcfoo/bar", event_type="write")
        state = make_state(file_events=[event])
        result = detect(state, make_baseline())
        no_finding(result, "DRIFT-002")


# ===========================================================================
# DRIFT-003 — Unexpected network connection
# ===========================================================================

class TestDrift003:
    def test_003_no_connections_no_finding(self):
        state = make_state(network_connections=[])
        result = detect(state, make_baseline())
        no_finding(result, "DRIFT-003")

    def test_003_expected_connection_no_finding(self):
        conn = make_conn("10.0.0.1", 443, "tcp")
        state = make_state(network_connections=[conn])
        result = detect(state, make_baseline(expected_connections=[conn]))
        no_finding(result, "DRIFT-003")

    def test_003_unexpected_ip_fires(self):
        expected = make_conn("10.0.0.1", 443, "tcp")
        observed = make_conn("8.8.8.8", 443, "tcp")
        state = make_state(network_connections=[observed])
        result = detect(state, make_baseline(expected_connections=[expected]))
        get_finding(result, "DRIFT-003")

    def test_003_unexpected_port_fires(self):
        expected = make_conn("10.0.0.1", 443, "tcp")
        observed = make_conn("10.0.0.1", 4444, "tcp")
        state = make_state(network_connections=[observed])
        result = detect(state, make_baseline(expected_connections=[expected]))
        get_finding(result, "DRIFT-003")

    def test_003_unexpected_protocol_fires(self):
        expected = make_conn("10.0.0.1", 53, "tcp")
        observed = make_conn("10.0.0.1", 53, "udp")
        state = make_state(network_connections=[observed])
        result = detect(state, make_baseline(expected_connections=[expected]))
        get_finding(result, "DRIFT-003")

    def test_003_all_fields_must_match(self):
        # All three fields (ip, port, protocol) must match — if any differ, fires.
        expected = make_conn("10.0.0.1", 80, "tcp")
        observed = make_conn("10.0.0.1", 80, "udp")
        state = make_state(network_connections=[observed])
        result = detect(state, make_baseline(expected_connections=[expected]))
        get_finding(result, "DRIFT-003")

    def test_003_multiple_unexpected_one_finding(self):
        conns = [make_conn("1.1.1.1", 80, "tcp"), make_conn("2.2.2.2", 443, "tcp")]
        state = make_state(network_connections=conns)
        result = detect(state, make_baseline(expected_connections=[]))
        findings_003 = [f for f in result.findings if f.check_id == "DRIFT-003"]
        assert len(findings_003) == 1

    def test_003_detail_lists_all_unexpected(self):
        conns = [make_conn("1.1.1.1", 80, "tcp"), make_conn("2.2.2.2", 443, "tcp")]
        state = make_state(network_connections=conns)
        result = detect(state, make_baseline(expected_connections=[]))
        f = get_finding(result, "DRIFT-003")
        assert "1.1.1.1" in f.detail
        assert "2.2.2.2" in f.detail

    def test_003_mix_expected_and_unexpected(self):
        expected = make_conn("10.0.0.1", 443, "tcp")
        unexpected = make_conn("8.8.8.8", 53, "udp")
        state = make_state(network_connections=[expected, unexpected])
        result = detect(state, make_baseline(expected_connections=[expected]))
        f = get_finding(result, "DRIFT-003")
        assert "8.8.8.8" in f.detail

    def test_003_severity_and_weight(self):
        observed = make_conn("8.8.8.8", 443, "tcp")
        state = make_state(network_connections=[observed])
        result = detect(state, make_baseline(expected_connections=[]))
        f = get_finding(result, "DRIFT-003")
        assert f.severity == "HIGH"
        assert f.weight == 25

    def test_003_empty_baseline_all_fire(self):
        conns = [make_conn("1.1.1.1", 80, "tcp")]
        state = make_state(network_connections=conns)
        result = detect(state, make_baseline(expected_connections=[]))
        get_finding(result, "DRIFT-003")


# ===========================================================================
# DRIFT-004 — Privilege escalation (root process when non-root expected)
# ===========================================================================

class TestDrift004:
    def test_004_expected_uid_matches_no_finding(self):
        proc = make_process(uid=1000)
        state = make_state(processes=[proc])
        result = detect(state, make_baseline(expected_uid=1000))
        no_finding(result, "DRIFT-004")

    def test_004_root_process_when_uid_expected_fires(self):
        proc = make_process(uid=0)
        state = make_state(processes=[proc])
        result = detect(state, make_baseline(expected_uid=1000))
        f = get_finding(result, "DRIFT-004")
        assert f.severity == "CRITICAL"
        assert f.weight == 40

    def test_004_baseline_uid_zero_root_allowed(self):
        # baseline expects uid=0, so a root process is fine
        proc = make_process(uid=0)
        state = make_state(processes=[proc])
        result = detect(state, make_baseline(expected_uid=0))
        no_finding(result, "DRIFT-004")

    def test_004_no_root_processes_no_finding(self):
        procs = [make_process(uid=1000), make_process(uid=999)]
        state = make_state(processes=procs)
        result = detect(state, make_baseline(expected_uid=1000))
        no_finding(result, "DRIFT-004")

    def test_004_multiple_root_procs_one_finding(self):
        procs = [make_process(pid=1, uid=0), make_process(pid=2, uid=0)]
        state = make_state(processes=procs)
        result = detect(state, make_baseline(expected_uid=1000))
        findings_004 = [f for f in result.findings if f.check_id == "DRIFT-004"]
        assert len(findings_004) == 1

    def test_004_detail_lists_root_procs(self):
        procs = [make_process(pid=42, name="evil", uid=0)]
        state = make_state(processes=procs)
        result = detect(state, make_baseline(expected_uid=1000))
        f = get_finding(result, "DRIFT-004")
        assert "evil" in f.detail
        assert "42" in f.detail

    def test_004_non_root_uid_mismatch_no_firing(self):
        # Process runs as uid=500 but baseline expects uid=1000
        # DRIFT-004 only checks uid==0, not general UID mismatches
        proc = make_process(uid=500)
        state = make_state(processes=[proc])
        result = detect(state, make_baseline(expected_uid=1000))
        no_finding(result, "DRIFT-004")

    def test_004_mix_root_and_expected_uid(self):
        procs = [make_process(pid=1, uid=1000), make_process(pid=2, uid=0)]
        state = make_state(processes=procs)
        result = detect(state, make_baseline(expected_uid=1000))
        get_finding(result, "DRIFT-004")

    def test_004_weight_counted_once(self):
        procs = [make_process(pid=1, uid=0), make_process(pid=2, uid=0)]
        state = make_state(processes=procs)
        result = detect(state, make_baseline(expected_uid=999))
        # Only DRIFT-004 fires
        assert result.risk_score == 40


# ===========================================================================
# DRIFT-005 — New executable file outside writable paths
# ===========================================================================

class TestDrift005:
    def test_005_no_file_events_no_finding(self):
        state = make_state(file_events=[])
        result = detect(state, make_baseline())
        no_finding(result, "DRIFT-005")

    def test_005_create_non_executable_no_finding(self):
        event = make_file_event(path="/opt/app/data.txt", event_type="create", executable=False)
        state = make_state(file_events=[event])
        result = detect(state, make_baseline())
        no_finding(result, "DRIFT-005")

    def test_005_create_executable_in_writable_no_finding(self):
        event = make_file_event(path="/tmp/install.sh", event_type="create", executable=True)
        state = make_state(file_events=[event])
        result = detect(state, make_baseline(writable_paths=["/tmp"]))
        no_finding(result, "DRIFT-005")

    def test_005_create_executable_outside_writable_fires(self):
        event = make_file_event(path="/opt/evil.sh", event_type="create", executable=True)
        state = make_state(file_events=[event])
        result = detect(state, make_baseline(writable_paths=["/tmp"]))
        f = get_finding(result, "DRIFT-005")
        assert f.severity == "HIGH"
        assert f.weight == 25

    def test_005_write_event_not_checked(self):
        # event_type="write" — DRIFT-005 only applies to "create"
        event = make_file_event(path="/opt/evil.sh", event_type="write", executable=True)
        state = make_state(file_events=[event])
        result = detect(state, make_baseline(writable_paths=["/tmp"]))
        no_finding(result, "DRIFT-005")

    def test_005_multiple_suspect_files_one_finding(self):
        events = [
            make_file_event(path="/opt/a.sh", event_type="create", executable=True),
            make_file_event(path="/opt/b.sh", event_type="create", executable=True),
        ]
        state = make_state(file_events=events)
        result = detect(state, make_baseline())
        findings_005 = [f for f in result.findings if f.check_id == "DRIFT-005"]
        assert len(findings_005) == 1

    def test_005_detail_contains_path(self):
        event = make_file_event(path="/opt/sneaky.sh", event_type="create", executable=True)
        state = make_state(file_events=[event])
        result = detect(state, make_baseline())
        f = get_finding(result, "DRIFT-005")
        assert "/opt/sneaky.sh" in f.detail

    def test_005_writable_subpath_overrides(self):
        event = make_file_event(path="/var/log/app.sh", event_type="create", executable=True)
        state = make_state(file_events=[event])
        result = detect(state, make_baseline(writable_paths=["/var/log"]))
        no_finding(result, "DRIFT-005")

    def test_005_delete_event_not_checked(self):
        event = make_file_event(path="/opt/evil.sh", event_type="delete", executable=True)
        state = make_state(file_events=[event])
        result = detect(state, make_baseline())
        no_finding(result, "DRIFT-005")


# ===========================================================================
# DRIFT-006 — Unexpected / changed environment variable
# ===========================================================================

class TestDrift006:
    def test_006_same_env_vars_no_finding(self):
        env = {"HOME": "/root", "PATH": "/usr/bin"}
        state = make_state(env_vars=env)
        result = detect(state, make_baseline(expected_env_vars=env))
        no_finding(result, "DRIFT-006")

    def test_006_new_var_fires(self):
        state = make_state(env_vars={"HOME": "/root", "PATH": "/usr/bin", "SECRET": "abc"})
        result = detect(state, make_baseline(expected_env_vars={"HOME": "/root", "PATH": "/usr/bin"}))
        f = get_finding(result, "DRIFT-006")
        assert "SECRET" in f.detail
        assert f.severity == "MEDIUM"
        assert f.weight == 15

    def test_006_changed_value_fires(self):
        state = make_state(env_vars={"HOME": "/evil"})
        result = detect(state, make_baseline(expected_env_vars={"HOME": "/root"}))
        f = get_finding(result, "DRIFT-006")
        assert "HOME" in f.detail

    def test_006_value_is_redacted(self):
        state = make_state(env_vars={"HOME": "/root", "DB_PASS": "supersecret"})
        result = detect(state, make_baseline(expected_env_vars={"HOME": "/root"}))
        f = get_finding(result, "DRIFT-006")
        # The actual value must NOT appear in the finding detail
        assert "supersecret" not in f.detail

    def test_006_removed_var_no_finding(self):
        # A var present in baseline but absent at runtime is not covered by DRIFT-006
        state = make_state(env_vars={})  # HOME and PATH removed
        result = detect(state, make_baseline(expected_env_vars={"HOME": "/root", "PATH": "/usr/bin"}))
        no_finding(result, "DRIFT-006")

    def test_006_multiple_changes_one_finding(self):
        state = make_state(env_vars={"NEW1": "x", "NEW2": "y"})
        result = detect(state, make_baseline(expected_env_vars={}))
        findings_006 = [f for f in result.findings if f.check_id == "DRIFT-006"]
        assert len(findings_006) == 1

    def test_006_detail_lists_added_vars(self):
        state = make_state(env_vars={"A": "1", "B": "2"})
        result = detect(state, make_baseline(expected_env_vars={}))
        f = get_finding(result, "DRIFT-006")
        assert "A" in f.detail
        assert "B" in f.detail

    def test_006_empty_state_and_empty_baseline_no_finding(self):
        state = make_state(env_vars={})
        result = detect(state, make_baseline(expected_env_vars={}))
        no_finding(result, "DRIFT-006")

    def test_006_only_extra_vars_matter(self):
        # State has only the baseline vars — no drift
        state = make_state(env_vars={"HOME": "/root"})
        result = detect(state, make_baseline(expected_env_vars={"HOME": "/root", "PATH": "/usr/bin"}))
        no_finding(result, "DRIFT-006")


# ===========================================================================
# DRIFT-007 — Resource usage > 2× baseline
# ===========================================================================

class TestDrift007:
    def test_007_normal_usage_no_finding(self):
        state = make_state(cpu_usage_percent=10.0, memory_usage_mb=200.0)
        result = detect(state, make_baseline(baseline_cpu_percent=10.0, baseline_memory_mb=256.0))
        no_finding(result, "DRIFT-007")

    def test_007_cpu_exactly_double_no_finding(self):
        # Strictly GREATER THAN 2× — exactly equal must not fire.
        state = make_state(cpu_usage_percent=20.0, memory_usage_mb=100.0)
        result = detect(state, make_baseline(baseline_cpu_percent=10.0, baseline_memory_mb=256.0))
        no_finding(result, "DRIFT-007")

    def test_007_cpu_just_over_double_fires(self):
        state = make_state(cpu_usage_percent=20.01, memory_usage_mb=100.0)
        result = detect(state, make_baseline(baseline_cpu_percent=10.0, baseline_memory_mb=256.0))
        f = get_finding(result, "DRIFT-007")
        assert f.severity == "MEDIUM"
        assert f.weight == 15

    def test_007_memory_exactly_double_no_finding(self):
        state = make_state(cpu_usage_percent=5.0, memory_usage_mb=512.0)
        result = detect(state, make_baseline(baseline_cpu_percent=10.0, baseline_memory_mb=256.0))
        no_finding(result, "DRIFT-007")

    def test_007_memory_just_over_double_fires(self):
        state = make_state(cpu_usage_percent=5.0, memory_usage_mb=512.01)
        result = detect(state, make_baseline(baseline_cpu_percent=10.0, baseline_memory_mb=256.0))
        get_finding(result, "DRIFT-007")

    def test_007_both_exceeded_one_finding(self):
        state = make_state(cpu_usage_percent=100.0, memory_usage_mb=1024.0)
        result = detect(state, make_baseline(baseline_cpu_percent=10.0, baseline_memory_mb=256.0))
        findings_007 = [f for f in result.findings if f.check_id == "DRIFT-007"]
        assert len(findings_007) == 1

    def test_007_detail_shows_current_and_threshold(self):
        state = make_state(cpu_usage_percent=25.0, memory_usage_mb=100.0)
        result = detect(state, make_baseline(baseline_cpu_percent=10.0, baseline_memory_mb=256.0))
        f = get_finding(result, "DRIFT-007")
        assert "25" in f.detail or "25.00" in f.detail

    def test_007_zero_baseline_zero_usage_no_finding(self):
        state = make_state(cpu_usage_percent=0.0, memory_usage_mb=0.0)
        result = detect(state, make_baseline(baseline_cpu_percent=0.0, baseline_memory_mb=0.0))
        no_finding(result, "DRIFT-007")

    def test_007_zero_baseline_any_usage_fires(self):
        # 0.0 * 2 = 0.0 threshold; any positive usage > 0.0 fires
        state = make_state(cpu_usage_percent=0.01, memory_usage_mb=0.0)
        result = detect(state, make_baseline(baseline_cpu_percent=0.0, baseline_memory_mb=0.0))
        get_finding(result, "DRIFT-007")

    def test_007_only_memory_exceeds(self):
        state = make_state(cpu_usage_percent=5.0, memory_usage_mb=600.0)
        result = detect(state, make_baseline(baseline_cpu_percent=10.0, baseline_memory_mb=256.0))
        f = get_finding(result, "DRIFT-007")
        assert "memory" in f.detail.lower()


# ===========================================================================
# Risk score and drift level integration tests
# ===========================================================================

class TestRiskScore:
    def test_clean_state_zero_score(self):
        state = make_state()
        result = detect(state, make_baseline())
        assert result.risk_score == 0
        assert result.drift_level == "NONE"

    def test_single_check_score_matches_weight(self):
        # Only DRIFT-003 fires (weight=25)
        observed = make_conn("8.8.8.8", 53, "udp")
        state = make_state(network_connections=[observed])
        result = detect(state, make_baseline(expected_connections=[]))
        assert result.risk_score == 25

    def test_two_checks_additive(self):
        # DRIFT-001 (25) + DRIFT-003 (25) = 50
        procs = [make_process(name="evil")]
        conn = make_conn("8.8.8.8", 53, "udp")
        state = make_state(processes=procs, network_connections=[conn])
        baseline = make_baseline(expected_processes=[], expected_connections=[])
        result = detect(state, baseline)
        assert result.risk_score == 50

    def test_score_capped_at_100(self):
        # Fire all 7 checks: 25+45+25+40+25+15+15 = 190 -> capped at 100
        procs = [make_process(name="evil", uid=0)]
        conn = make_conn("8.8.8.8", 53, "udp")
        file_events = [
            make_file_event(path="/etc/passwd", event_type="write"),
            make_file_event(path="/opt/evil.sh", event_type="create", executable=True),
        ]
        env = {"HOME": "/root", "MALICIOUS": "yes"}
        state = RuntimeState(
            container_id="ctr-001",
            processes=procs,
            network_connections=[conn],
            file_events=file_events,
            env_vars=env,
            cpu_usage_percent=999.0,
            memory_usage_mb=999999.0,
        )
        baseline = make_baseline(
            expected_processes=[],
            expected_uid=1000,
            expected_connections=[],
            writable_paths=["/tmp"],
            expected_env_vars={"HOME": "/root"},
        )
        result = detect(state, baseline)
        assert result.risk_score == 100

    def test_drift_level_none(self):
        state = make_state()
        result = detect(state, make_baseline())
        assert result.drift_level == "NONE"

    def test_drift_level_low(self):
        # DRIFT-006 fires (weight=15) -> score=15 -> LOW
        state = make_state(env_vars={"HOME": "/root", "NEW": "val"})
        result = detect(state, make_baseline(expected_env_vars={"HOME": "/root"}))
        assert result.risk_score == 15
        assert result.drift_level == "LOW"

    def test_drift_level_medium(self):
        # DRIFT-006 (15) + DRIFT-007 (15) = 30 -> MEDIUM
        state = make_state(
            env_vars={"NEW": "val"},
            cpu_usage_percent=999.0,
        )
        result = detect(state, make_baseline(expected_env_vars={}, baseline_cpu_percent=10.0))
        assert result.drift_level == "MEDIUM"

    def test_drift_level_high(self):
        # DRIFT-001 (25) + DRIFT-003 (25) = 50 -> HIGH
        state = make_state(
            processes=[make_process(name="evil")],
            network_connections=[make_conn("8.8.8.8", 53, "udp")],
        )
        baseline = make_baseline(expected_processes=[], expected_connections=[])
        result = detect(state, baseline)
        assert result.risk_score == 50
        assert result.drift_level == "HIGH"

    def test_drift_level_critical(self):
        # DRIFT-004 (40) + DRIFT-002 (45) = 85 -> capped? No: 85 <= 100, CRITICAL
        procs = [make_process(uid=0)]
        file_events = [make_file_event(path="/etc/passwd", event_type="write")]
        state = make_state(processes=procs, file_events=file_events)
        result = detect(state, make_baseline(expected_uid=1000))
        assert result.risk_score == 85
        assert result.drift_level == "CRITICAL"

    def test_unique_check_ids_in_score(self):
        # Firing the same logical check multiple times still counts only once
        # (our architecture guarantees this — each check_id appears at most once)
        procs = [make_process(pid=i, name="evil", uid=0) for i in range(5)]
        state = make_state(processes=procs)
        result = detect(state, make_baseline(expected_uid=1000, expected_processes=[]))
        # DRIFT-001 (25) + DRIFT-004 (40) = 65
        assert result.risk_score == 65


# ===========================================================================
# DRIFTResult helper method tests
# ===========================================================================

class TestDriftResultHelpers:
    def _result_with_all_sevs(self) -> DRIFTResult:
        """Build a DRIFTResult that has one finding of each severity."""
        findings = [
            DRIFTFinding("DRIFT-002", "CRITICAL", "t", "d", 45),
            DRIFTFinding("DRIFT-001", "HIGH", "t", "d", 25),
            DRIFTFinding("DRIFT-006", "MEDIUM", "t", "d", 15),
        ]
        return DRIFTResult(
            container_id="ctr-001",
            findings=findings,
            risk_score=85,
            drift_level="CRITICAL",
        )

    def test_to_dict_keys(self):
        result = self._result_with_all_sevs()
        d = result.to_dict()
        assert set(d.keys()) == {"container_id", "risk_score", "drift_level", "findings"}

    def test_to_dict_findings_list(self):
        result = self._result_with_all_sevs()
        d = result.to_dict()
        assert isinstance(d["findings"], list)
        assert len(d["findings"]) == 3

    def test_to_dict_finding_keys(self):
        result = self._result_with_all_sevs()
        d = result.to_dict()
        finding_keys = set(d["findings"][0].keys())
        assert finding_keys == {"check_id", "severity", "title", "detail", "weight"}

    def test_to_dict_values_correct(self):
        result = self._result_with_all_sevs()
        d = result.to_dict()
        assert d["container_id"] == "ctr-001"
        assert d["risk_score"] == 85
        assert d["drift_level"] == "CRITICAL"

    def test_summary_contains_container_id(self):
        result = self._result_with_all_sevs()
        assert "ctr-001" in result.summary()

    def test_summary_contains_risk_score(self):
        result = self._result_with_all_sevs()
        assert "85" in result.summary()

    def test_summary_contains_drift_level(self):
        result = self._result_with_all_sevs()
        assert "CRITICAL" in result.summary()

    def test_summary_no_findings(self):
        result = DRIFTResult("ctr-x", [], 0, "NONE")
        s = result.summary()
        assert "NONE" in s
        assert "ctr-x" in s

    def test_by_severity_groups_correctly(self):
        result = self._result_with_all_sevs()
        grouped = result.by_severity()
        assert "CRITICAL" in grouped
        assert "HIGH" in grouped
        assert "MEDIUM" in grouped
        assert len(grouped["CRITICAL"]) == 1
        assert len(grouped["HIGH"]) == 1
        assert len(grouped["MEDIUM"]) == 1

    def test_by_severity_empty(self):
        result = DRIFTResult("ctr-x", [], 0, "NONE")
        assert result.by_severity() == {}

    def test_by_severity_multiple_same_severity(self):
        findings = [
            DRIFTFinding("DRIFT-001", "HIGH", "t", "d", 25),
            DRIFTFinding("DRIFT-003", "HIGH", "t", "d", 25),
        ]
        result = DRIFTResult("ctr-x", findings, 50, "HIGH")
        grouped = result.by_severity()
        assert len(grouped["HIGH"]) == 2


# ===========================================================================
# detect_many tests
# ===========================================================================

class TestDetectMany:
    def test_empty_states_returns_empty(self):
        results = detect_many([], [make_baseline()])
        assert results == []

    def test_empty_baselines_returns_empty(self):
        results = detect_many([make_state()], [])
        assert results == []

    def test_matched_pair_returns_result(self):
        results = detect_many([make_state("ctr-A")], [make_baseline("ctr-A")])
        assert len(results) == 1
        assert results[0].container_id == "ctr-A"

    def test_unmatched_state_skipped(self):
        results = detect_many(
            [make_state("ctr-UNKNOWN")],
            [make_baseline("ctr-001")],
        )
        assert results == []

    def test_unmatched_baseline_ignored(self):
        results = detect_many(
            [make_state("ctr-001")],
            [make_baseline("ctr-001"), make_baseline("ctr-002")],
        )
        assert len(results) == 1

    def test_multiple_pairs_all_matched(self):
        states = [make_state(f"ctr-{i}") for i in range(3)]
        baselines = [make_baseline(f"ctr-{i}") for i in range(3)]
        results = detect_many(states, baselines)
        assert len(results) == 3

    def test_order_follows_states(self):
        states = [make_state("ctr-B"), make_state("ctr-A")]
        baselines = [make_baseline("ctr-A"), make_baseline("ctr-B")]
        results = detect_many(states, baselines)
        assert results[0].container_id == "ctr-B"
        assert results[1].container_id == "ctr-A"

    def test_findings_propagate_correctly(self):
        state = make_state("ctr-X", processes=[make_process(name="evil")])
        baseline = make_baseline("ctr-X", expected_processes=[])
        results = detect_many([state], [baseline])
        assert len(results) == 1
        assert any(f.check_id == "DRIFT-001" for f in results[0].findings)

    def test_duplicate_container_id_in_baselines(self):
        # Second baseline with same container_id wins (last-write in dict)
        b1 = make_baseline("ctr-001", expected_processes=["nginx"])
        b2 = make_baseline("ctr-001", expected_processes=[])
        state = make_state("ctr-001", processes=[make_process(name="nginx")])
        results = detect_many([state], [b1, b2])
        # With b2 (empty expected_processes), nginx is unexpected
        assert len(results) == 1

    def test_no_findings_for_clean_container(self):
        state = make_state("ctr-clean")
        baseline = make_baseline("ctr-clean")
        results = detect_many([state], [baseline])
        assert results[0].risk_score == 0
        assert results[0].drift_level == "NONE"


# ===========================================================================
# Cross-check / combined scenario tests
# ===========================================================================

class TestCombinedScenarios:
    def test_all_seven_checks_fire(self):
        procs = [make_process(name="evil", uid=0)]
        conn = make_conn("8.8.8.8", 53, "udp")
        file_events = [
            make_file_event(path="/etc/passwd", event_type="write"),
            make_file_event(path="/opt/evil.sh", event_type="create", executable=True),
        ]
        state = RuntimeState(
            container_id="ctr-001",
            processes=procs,
            network_connections=[conn],
            file_events=file_events,
            env_vars={"HOME": "/root", "MALICIOUS": "yes"},
            cpu_usage_percent=999.0,
            memory_usage_mb=999999.0,
        )
        baseline = make_baseline(
            expected_processes=[],
            expected_uid=1000,
            expected_connections=[],
            writable_paths=["/tmp"],
            expected_env_vars={"HOME": "/root"},
        )
        result = detect(state, baseline)
        fired_ids = {f.check_id for f in result.findings}
        for cid in ["DRIFT-001", "DRIFT-002", "DRIFT-003", "DRIFT-004", "DRIFT-005", "DRIFT-006", "DRIFT-007"]:
            assert cid in fired_ids, f"{cid} did not fire"

    def test_clean_container_no_drift(self):
        proc = make_process(name="nginx", uid=1000)
        conn = make_conn("10.0.0.1", 443, "tcp")
        file_event = make_file_event(path="/tmp/access.log", event_type="write")
        env = {"HOME": "/root", "PATH": "/usr/bin"}
        state = RuntimeState(
            container_id="ctr-001",
            processes=[proc],
            network_connections=[conn],
            file_events=[file_event],
            env_vars=env,
            cpu_usage_percent=10.0,
            memory_usage_mb=200.0,
        )
        baseline = make_baseline(
            expected_processes=["nginx"],
            expected_uid=1000,
            expected_connections=[conn],
            writable_paths=["/tmp"],
            expected_env_vars=env,
        )
        result = detect(state, baseline)
        assert result.findings == []
        assert result.risk_score == 0
        assert result.drift_level == "NONE"

    def test_container_id_preserved_in_result(self):
        state = make_state(container_id="my-special-container")
        result = detect(state, make_baseline(container_id="my-special-container"))
        assert result.container_id == "my-special-container"

    def test_findings_list_type(self):
        result = detect(make_state(), make_baseline())
        assert isinstance(result.findings, list)

    def test_risk_score_int_type(self):
        result = detect(make_state(), make_baseline())
        assert isinstance(result.risk_score, int)
