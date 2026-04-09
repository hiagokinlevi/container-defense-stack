# container_drift_detector.py
# Part of the Cyber Port portfolio — container-defense-stack repo.
#
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# You are free to share and adapt this material for any purpose, even
# commercially, under the following terms:
#   Attribution — You must give appropriate credit, provide a link to
#   the licence, and indicate if changes were made.
#
# Author: hiagokinlevi  |  Cyber Port — github.com/hiagokinlevi
"""
container_drift_detector
========================
Detect runtime container drift by comparing an observed RuntimeState against
an expected ContainerBaseline.

Seven checks are performed:

    DRIFT-001  New process not present in the expected process baseline       HIGH      w=25
    DRIFT-002  File write/create to a read-only system path                  CRITICAL  w=45
    DRIFT-003  Unexpected outbound network connection                         HIGH      w=25
    DRIFT-004  Process running as root when baseline specifies non-root UID   CRITICAL  w=40
    DRIFT-005  New executable file created outside writable paths             HIGH      w=25
    DRIFT-006  Environment variable added or changed at runtime               MEDIUM    w=15
    DRIFT-007  CPU or memory usage exceeds 2× the baseline average            MEDIUM    w=15

Usage::

    result = detect(runtime_state, baseline)
    print(result.summary())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Read-only system path prefixes that are always protected regardless of the
# writable_paths list in the baseline.
_PROTECTED_PATH_PREFIXES: List[str] = [
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/boot",
]

# Weight assigned to each check when it fires (contributes once to risk_score).
_CHECK_WEIGHTS: Dict[str, int] = {
    "DRIFT-001": 25,  # new process — HIGH
    "DRIFT-002": 45,  # write to protected path — CRITICAL
    "DRIFT-003": 25,  # unexpected network connection — HIGH
    "DRIFT-004": 40,  # root process when non-root expected — CRITICAL
    "DRIFT-005": 25,  # new executable outside writable paths — HIGH
    "DRIFT-006": 15,  # unexpected / changed env var — MEDIUM
    "DRIFT-007": 15,  # resource usage > 2× baseline — MEDIUM
}

# Severity label for each check ID.
_CHECK_SEVERITY: Dict[str, str] = {
    "DRIFT-001": "HIGH",
    "DRIFT-002": "CRITICAL",
    "DRIFT-003": "HIGH",
    "DRIFT-004": "CRITICAL",
    "DRIFT-005": "HIGH",
    "DRIFT-006": "MEDIUM",
    "DRIFT-007": "MEDIUM",
}

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ProcessInfo:
    """Snapshot of a single process observed inside the container."""

    pid: int
    name: str
    cmdline: str
    uid: int  # effective UID of the process


@dataclass
class NetworkConnection:
    """A single outbound network connection observed inside the container."""

    remote_ip: str
    remote_port: int
    protocol: str  # "tcp" or "udp"


@dataclass
class FileEvent:
    """A filesystem event observed at runtime."""

    path: str
    event_type: str   # "write", "create", "delete", "chmod"
    executable: bool  # True when the file's executable bit is set (relevant for "create")


@dataclass
class RuntimeState:
    """Complete observed runtime snapshot of one container."""

    container_id: str
    processes: List[ProcessInfo]
    network_connections: List[NetworkConnection]
    file_events: List[FileEvent]
    env_vars: Dict[str, str]
    cpu_usage_percent: float
    memory_usage_mb: float


@dataclass
class ContainerBaseline:
    """Expected (trusted) configuration for one container."""

    container_id: str
    expected_processes: List[str]           # allowlisted process names
    expected_uid: int                       # all processes must run as this UID
    expected_connections: List[NetworkConnection]
    writable_paths: List[str]               # paths where writes are explicitly allowed
    expected_env_vars: Dict[str, str]
    baseline_cpu_percent: float
    baseline_memory_mb: float


@dataclass
class DRIFTFinding:
    """A single drift finding produced by one of the seven checks."""

    check_id: str
    severity: str   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int


@dataclass
class DRIFTResult:
    """Aggregated drift analysis result for one container."""

    container_id: str
    findings: List[DRIFTFinding]
    risk_score: int   # min(100, sum of weights for unique fired check IDs)
    drift_level: str  # "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a plain-dict representation suitable for JSON serialisation."""
        return {
            "container_id": self.container_id,
            "risk_score": self.risk_score,
            "drift_level": self.drift_level,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                }
                for f in self.findings
            ],
        }

    def summary(self) -> str:
        """One-line human-readable summary of the drift result."""
        count = len(self.findings)
        noun = "finding" if count == 1 else "findings"
        return (
            f"[{self.drift_level}] container={self.container_id} "
            f"risk_score={self.risk_score} findings={count} {noun}"
        )

    def by_severity(self) -> Dict[str, List[DRIFTFinding]]:
        """Group findings by severity label (CRITICAL, HIGH, MEDIUM, …)."""
        grouped: Dict[str, List[DRIFTFinding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.severity, []).append(finding)
        return grouped


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _starts_with_any(path: str, prefixes: List[str]) -> bool:
    """Return True if *path* starts with any of the given *prefixes*."""
    for prefix in prefixes:
        # Ensure we match on a path boundary (e.g. /etc matches /etc/passwd
        # but must not match /etcfoo).
        if path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def _calc_drift_level(risk_score: int) -> str:
    """Map a numeric risk_score to a categorical drift level."""
    if risk_score == 0:
        return "NONE"
    if risk_score <= 20:
        return "LOW"
    if risk_score <= 45:
        return "MEDIUM"
    if risk_score <= 70:
        return "HIGH"
    return "CRITICAL"


def _build_finding(check_id: str, title: str, detail: str) -> DRIFTFinding:
    """Construct a DRIFTFinding using the central weight/severity tables."""
    return DRIFTFinding(
        check_id=check_id,
        severity=_CHECK_SEVERITY[check_id],
        title=title,
        detail=detail,
        weight=_CHECK_WEIGHTS[check_id],
    )


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------


def _check_drift_001(state: RuntimeState, baseline: ContainerBaseline) -> Optional[DRIFTFinding]:
    """DRIFT-001 — new process not in the expected process baseline."""
    unknown_names: List[str] = [
        p.name
        for p in state.processes
        if p.name not in baseline.expected_processes
    ]
    if not unknown_names:
        return None
    # De-duplicate while preserving order for a stable detail string.
    seen: List[str] = []
    for name in unknown_names:
        if name not in seen:
            seen.append(name)
    detail = (
        f"Processes not in expected baseline: {', '.join(seen)}. "
        f"Total unexpected process instances: {len(unknown_names)}."
    )
    return _build_finding(
        "DRIFT-001",
        "Unexpected process detected at runtime",
        detail,
    )


def _check_drift_002(state: RuntimeState, baseline: ContainerBaseline) -> Optional[DRIFTFinding]:
    """DRIFT-002 — file write/create to a protected read-only system path."""
    violating_paths: List[str] = []
    for event in state.file_events:
        if event.event_type not in ("write", "create"):
            continue
        # Write is allowed if the path is covered by a baseline writable prefix.
        if _starts_with_any(event.path, baseline.writable_paths):
            continue
        # Write is a violation only when the path falls under a protected prefix.
        if _starts_with_any(event.path, _PROTECTED_PATH_PREFIXES):
            violating_paths.append(event.path)
    if not violating_paths:
        return None
    detail = (
        f"Write/create events to protected system paths: "
        f"{', '.join(violating_paths)}."
    )
    return _build_finding(
        "DRIFT-002",
        "File modification detected on read-only system path",
        detail,
    )


def _check_drift_003(state: RuntimeState, baseline: ContainerBaseline) -> Optional[DRIFTFinding]:
    """DRIFT-003 — unexpected outbound network connection."""
    # Build a set of (ip, port, protocol) tuples for O(1) lookup.
    allowed: set = {
        (c.remote_ip, c.remote_port, c.protocol)
        for c in baseline.expected_connections
    }
    unexpected: List[NetworkConnection] = [
        c
        for c in state.network_connections
        if (c.remote_ip, c.remote_port, c.protocol) not in allowed
    ]
    if not unexpected:
        return None
    conn_strs = [
        f"{c.protocol}://{c.remote_ip}:{c.remote_port}" for c in unexpected
    ]
    detail = f"Unexpected outbound connections: {', '.join(conn_strs)}."
    return _build_finding(
        "DRIFT-003",
        "Unexpected outbound network connection detected",
        detail,
    )


def _check_drift_004(state: RuntimeState, baseline: ContainerBaseline) -> Optional[DRIFTFinding]:
    """DRIFT-004 — process running as root when baseline specifies non-root UID."""
    # Only applies when the baseline explicitly expects a non-root UID.
    if baseline.expected_uid == 0:
        return None
    root_procs: List[ProcessInfo] = [
        p for p in state.processes if p.uid == 0
    ]
    if not root_procs:
        return None
    proc_descs = [f"{p.name}(pid={p.pid})" for p in root_procs]
    detail = (
        f"Processes running as root (uid=0) while baseline expects uid={baseline.expected_uid}: "
        f"{', '.join(proc_descs)}."
    )
    return _build_finding(
        "DRIFT-004",
        "Privilege escalation detected — process running as root",
        detail,
    )


def _check_drift_005(state: RuntimeState, baseline: ContainerBaseline) -> Optional[DRIFTFinding]:
    """DRIFT-005 — new executable file created outside of expected writable paths."""
    suspect_paths: List[str] = []
    for event in state.file_events:
        if event.event_type != "create":
            continue
        if not event.executable:
            continue
        # Allow executables dropped into explicitly writable paths.
        if _starts_with_any(event.path, baseline.writable_paths):
            continue
        suspect_paths.append(event.path)
    if not suspect_paths:
        return None
    detail = (
        f"Executable files created outside of writable paths: "
        f"{', '.join(suspect_paths)}."
    )
    return _build_finding(
        "DRIFT-005",
        "New executable file created outside expected writable paths",
        detail,
    )


def _check_drift_006(state: RuntimeState, baseline: ContainerBaseline) -> Optional[DRIFTFinding]:
    """DRIFT-006 — environment variable added or changed at runtime."""
    added: List[str] = []
    changed: List[str] = []
    for key, _value in state.env_vars.items():
        if key not in baseline.expected_env_vars:
            added.append(key)
        elif state.env_vars[key] != baseline.expected_env_vars[key]:
            changed.append(key)
    if not added and not changed:
        return None
    parts: List[str] = []
    if added:
        parts.append(f"added=[{', '.join(sorted(added))}]")
    if changed:
        parts.append(f"changed=[{', '.join(sorted(changed))}]")
    # Values are intentionally redacted to avoid leaking secrets in findings.
    detail = (
        f"Environment variable drift detected (values redacted): "
        f"{'; '.join(parts)}."
    )
    return _build_finding(
        "DRIFT-006",
        "Unexpected environment variable change detected",
        detail,
    )


def _check_drift_007(state: RuntimeState, baseline: ContainerBaseline) -> Optional[DRIFTFinding]:
    """DRIFT-007 — CPU or memory usage exceeds 2× the baseline average."""
    cpu_threshold = baseline.baseline_cpu_percent * 2
    mem_threshold = baseline.baseline_memory_mb * 2

    cpu_exceeded = state.cpu_usage_percent > cpu_threshold
    mem_exceeded = state.memory_usage_mb > mem_threshold

    if not cpu_exceeded and not mem_exceeded:
        return None

    metrics: List[str] = []
    if cpu_exceeded:
        metrics.append(
            f"CPU {state.cpu_usage_percent:.2f}% > threshold {cpu_threshold:.2f}% "
            f"(baseline {baseline.baseline_cpu_percent:.2f}%)"
        )
    if mem_exceeded:
        metrics.append(
            f"memory {state.memory_usage_mb:.2f} MB > threshold {mem_threshold:.2f} MB "
            f"(baseline {baseline.baseline_memory_mb:.2f} MB)"
        )
    detail = (
        "Resource usage exceeds 2× baseline — possible crypto-mining or resource abuse. "
        + "; ".join(metrics) + "."
    )
    return _build_finding(
        "DRIFT-007",
        "Abnormal resource usage detected (>2× baseline)",
        detail,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect(state: RuntimeState, baseline: ContainerBaseline) -> DRIFTResult:
    """Detect drift between *state* and the trusted *baseline*.

    Each of the seven checks fires at most once; its weight is added once to
    the cumulative risk_score (capped at 100).

    Parameters
    ----------
    state:
        Observed runtime snapshot of the container.
    baseline:
        Trusted reference configuration for the same container.

    Returns
    -------
    DRIFTResult
        Aggregated findings, numeric risk score, and categorical drift level.
    """
    # Run all checks in order and collect non-None findings.
    check_fns = [
        _check_drift_001,
        _check_drift_002,
        _check_drift_003,
        _check_drift_004,
        _check_drift_005,
        _check_drift_006,
        _check_drift_007,
    ]

    findings: List[DRIFTFinding] = []
    for fn in check_fns:
        result = fn(state, baseline)
        if result is not None:
            findings.append(result)

    # risk_score: sum of weights for unique check IDs that fired, capped at 100.
    fired_ids = {f.check_id for f in findings}
    raw_score = sum(_CHECK_WEIGHTS[cid] for cid in fired_ids)
    risk_score = min(100, raw_score)
    drift_level = _calc_drift_level(risk_score)

    return DRIFTResult(
        container_id=state.container_id,
        findings=findings,
        risk_score=risk_score,
        drift_level=drift_level,
    )


def detect_many(
    states: List[RuntimeState],
    baselines: List[ContainerBaseline],
) -> List[DRIFTResult]:
    """Detect drift for multiple containers in one call.

    Each RuntimeState is matched to a ContainerBaseline by ``container_id``.
    States without a matching baseline are silently skipped; baselines without
    a matching state are also ignored.

    Parameters
    ----------
    states:
        List of observed runtime snapshots.
    baselines:
        List of trusted baseline configurations.

    Returns
    -------
    List[DRIFTResult]
        One DRIFTResult per matched (state, baseline) pair, in the order the
        matching states appear in *states*.
    """
    # Index baselines by container_id for O(1) lookup.
    baseline_index: Dict[str, ContainerBaseline] = {
        b.container_id: b for b in baselines
    }

    results: List[DRIFTResult] = []
    for state in states:
        matched_baseline = baseline_index.get(state.container_id)
        if matched_baseline is None:
            # No baseline available for this container — skip silently.
            continue
        results.append(detect(state, matched_baseline))

    return results
