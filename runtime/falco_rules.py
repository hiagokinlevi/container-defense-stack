"""
Falco-Style Container Runtime Threat Detection Rules
======================================================
A Falco-inspired rule engine for detecting suspicious activity in Kubernetes
container workloads.  Rules are evaluated against structured event dicts that
represent syscall events, process activity, file accesses, and network connections.

Event structure (all fields optional — missing fields are treated as absent):
{
    "container": {
        "id":           str,   # Container ID
        "name":         str,   # Container name
        "image":        str,   # Docker image (name:tag)
        "privileged":   bool,  # Running with --privileged
        "uid":          int,   # Process UID inside container
        "namespace":    str,   # Kubernetes namespace
        "pod_name":     str,   # Kubernetes pod name
    },
    "process": {
        "name":   str,   # Process name (basename of exe)
        "exe":    str,   # Full path to executable
        "args":   list,  # argv list
        "uid":    int,   # Process UID
        "ppid":   int,   # Parent process PID
        "cmdline": str,  # Full command line string
    },
    "fd": {
        "filename": str,  # File path being accessed
        "typechar": str,  # "f" file / "d" dir / "p" pipe
        "openflags": int, # open(2) flags (O_WRONLY = 1, O_RDWR = 2)
    },
    "network": {
        "direction": str,  # "inbound" | "outbound"
        "dest_ip":   str,  # Destination IP address
        "dest_port": int,  # Destination port
        "proto":     str,  # "tcp" | "udp"
    },
    "syscall": {
        "name": str,   # Syscall name (e.g. "execve", "mount", "ptrace")
        "args": dict,  # Syscall arguments
    },
}

Usage:
    from runtime.falco_rules import (
        evaluate_rule,
        evaluate_all,
        BUILTIN_RULES,
        RuleEngine,
        RuleMatch,
    )

    # Evaluate a single event
    matches = evaluate_all(event)
    for m in matches:
        print(f"[{m.rule.priority}] {m.rule.name}: {m.output}")

    # Use the RuleEngine
    engine = RuleEngine()
    engine.load_defaults()
    matches = engine.evaluate(event)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FalcoRule:
    """
    A single Falco-style runtime detection rule.

    The condition is a Python callable that receives an event dict and
    returns True when the rule should fire.  The output_template is a
    string that may reference event fields via {key.subkey} placeholders.
    """

    name: str
    description: str
    condition: Callable[[dict[str, Any]], bool]
    output_template: str
    priority: str     # "CRITICAL", "WARNING", "ERROR", "NOTICE", "INFO"
    tags: frozenset[str] = field(default_factory=frozenset)

    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, FalcoRule):
            return self.name == other.name
        return NotImplemented


@dataclass
class RuleMatch:
    """Result of a rule firing against an event."""

    rule: FalcoRule
    output: str               # Rendered output with event context
    event_summary: str = ""   # Short human-readable event description


@dataclass
class EvaluationReport:
    """Summary of evaluating all rules against a batch of events."""

    total_events: int = 0
    total_matches: int = 0
    matches_by_priority: dict[str, int] = field(default_factory=dict)
    matches_by_rule: dict[str, int] = field(default_factory=dict)
    all_matches: list[RuleMatch] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"Events: {self.total_events} | "
            f"Matches: {self.total_matches} | "
            f"CRITICAL={self.matches_by_priority.get('CRITICAL', 0)} "
            f"WARNING={self.matches_by_priority.get('WARNING', 0)} "
            f"NOTICE={self.matches_by_priority.get('NOTICE', 0)}"
        )


# ---------------------------------------------------------------------------
# Event helper accessors
# ---------------------------------------------------------------------------

def _get(event: dict, *path: str, default=None):
    """Safely traverse nested dict path, returning default if any key missing."""
    obj = event
    for key in path:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(key, default)
        if obj is None:
            return default
    return obj


def _proc_name(event: dict) -> str:
    return str(_get(event, "process", "name") or "").lower()


def _proc_exe(event: dict) -> str:
    return str(_get(event, "process", "exe") or "").lower()


def _proc_cmdline(event: dict) -> str:
    name = _get(event, "process", "name") or ""
    args = _get(event, "process", "args") or []
    cmdline = _get(event, "process", "cmdline") or ""
    if cmdline:
        return cmdline.lower()
    return " ".join([str(name)] + [str(a) for a in args]).lower()


def _proc_uid(event: dict) -> Optional[int]:
    uid = _get(event, "process", "uid")
    if uid is None:
        uid = _get(event, "container", "uid")
    return uid


def _fd_filename(event: dict) -> str:
    return str(_get(event, "fd", "filename") or "")


def _fd_writable(event: dict) -> bool:
    flags = _get(event, "fd", "openflags", default=0)
    return bool(flags & 3)   # O_WRONLY(1) | O_RDWR(2)


def _syscall_name(event: dict) -> str:
    return str(_get(event, "syscall", "name") or "").lower()


def _in_container(event: dict) -> bool:
    """Return True if the event has a container context."""
    return bool(_get(event, "container", "id"))


# ---------------------------------------------------------------------------
# Rule conditions
# ---------------------------------------------------------------------------

# Shell process names that indicate interactive or script-spawned shells
_SHELL_NAMES = {"bash", "sh", "dash", "zsh", "ksh", "fish", "tcsh", "csh"}

# Crypto-mining process names and patterns
_MINER_NAMES = {
    "xmrig", "minerd", "cpuminer", "ethminer", "claymore", "t-rex",
    "nbminer", "lolminer", "gminer", "bzminer",
}
_MINER_PATTERN = re.compile(r"xmr|miner|stratum|monero|cryptonight", re.IGNORECASE)

# Paths indicating sensitive files
_SENSITIVE_PATHS = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.ssh/",
    "/etc/kubernetes/",
    "/.kube/config",
    "/var/run/secrets/kubernetes.io/",
    "/proc/self/mem",
    "/dev/mem",
)

# Paths that should not be written to from inside a container
_BINARY_DIRS = ("/usr/bin/", "/usr/local/bin/", "/bin/", "/sbin/", "/usr/sbin/")

# kubectl arguments indicating enumeration/exfiltration
_K8S_ENUM_PATTERNS = re.compile(
    r"kubectl\s+(?:get|describe|list)\s+(?:secrets|clusterroles|rolebindings|serviceaccounts)",
    re.IGNORECASE,
)


def _cond_shell_spawned(event: dict) -> bool:
    """Container shell spawned via execve."""
    return (
        _in_container(event)
        and _syscall_name(event) in ("execve", "execveat", "")
        and _proc_name(event) in _SHELL_NAMES
    )


def _cond_privileged_container(event: dict) -> bool:
    """Process running inside a privileged container."""
    return bool(_get(event, "container", "privileged"))


def _cond_sensitive_file_access(event: dict) -> bool:
    """Sensitive system or Kubernetes credential file accessed."""
    fname = _fd_filename(event)
    return any(fname.startswith(p) for p in _SENSITIVE_PATHS)


def _cond_write_to_binary_dir(event: dict) -> bool:
    """Write to system binary directories inside container."""
    return (
        _in_container(event)
        and _fd_writable(event)
        and any(_fd_filename(event).startswith(d) for d in _BINARY_DIRS)
    )


def _cond_root_in_container(event: dict) -> bool:
    """Process running as UID 0 inside a container."""
    return _in_container(event) and _proc_uid(event) == 0


def _cond_kubectl_in_container(event: dict) -> bool:
    """kubectl binary executed inside a container."""
    return _in_container(event) and (
        "kubectl" in _proc_name(event) or "kubectl" in _proc_exe(event)
    )


def _cond_crypto_mining(event: dict) -> bool:
    """Known crypto-mining process started."""
    name = _proc_name(event)
    cmdline = _proc_cmdline(event)
    return name in _MINER_NAMES or bool(_MINER_PATTERN.search(cmdline))


def _cond_container_escape_mount(event: dict) -> bool:
    """mount syscall invoked from inside a container (potential escape)."""
    return _in_container(event) and _syscall_name(event) == "mount"


def _cond_container_escape_ptrace(event: dict) -> bool:
    """ptrace syscall against an external process (potential breakout)."""
    return (
        _in_container(event)
        and _syscall_name(event) == "ptrace"
    )


def _cond_outbound_unusual_port(event: dict) -> bool:
    """Outbound network connection to a non-standard port from a container."""
    return (
        _in_container(event)
        and _get(event, "network", "direction") == "outbound"
        and _get(event, "network", "proto", default="tcp") == "tcp"
        and _get(event, "network", "dest_port", default=0) not in (
            80, 443, 8080, 8443, 53,   # common legitimate ports
        )
    )


def _cond_k8s_api_enumeration(event: dict) -> bool:
    """kubectl command enumerating secrets, roles, or service accounts."""
    return bool(_K8S_ENUM_PATTERNS.search(_proc_cmdline(event)))


def _cond_nsenter_executed(event: dict) -> bool:
    """nsenter executed — commonly used for namespace escape."""
    name = _proc_name(event)
    return "nsenter" in name or "nsenter" in _proc_exe(event)


def _cond_setuid_binary_exec(event: dict) -> bool:
    """Known setuid-capable binary executed inside container."""
    _SETUID_BINS = {"sudo", "su", "newgrp", "chsh", "passwd", "gpasswd"}
    return _in_container(event) and _proc_name(event) in _SETUID_BINS


def _cond_docker_socket_access(event: dict) -> bool:
    """Docker or containerd socket file accessed from container."""
    fname = _fd_filename(event)
    return any(sock in fname for sock in (
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/var/run/containerd/containerd.sock",
        "/run/containerd/containerd.sock",
    ))


# ---------------------------------------------------------------------------
# Output renderer
# ---------------------------------------------------------------------------

def _render_output(template: str, event: dict[str, Any]) -> str:
    """
    Render an output template with values from the event dict.

    Supported placeholders: {container.name}, {process.name}, {fd.filename},
    {syscall.name}, {network.dest_port}, etc.
    """
    replacements = {
        "container.name":   _get(event, "container", "name") or "<unknown>",
        "container.id":     _get(event, "container", "id") or "<unknown>",
        "container.image":  _get(event, "container", "image") or "<unknown>",
        "process.name":     _get(event, "process", "name") or "<unknown>",
        "process.exe":      _get(event, "process", "exe") or "<unknown>",
        "process.uid":      str(_proc_uid(event) or "<unknown>"),
        "fd.filename":      _get(event, "fd", "filename") or "<unknown>",
        "syscall.name":     _get(event, "syscall", "name") or "<unknown>",
        "network.dest_ip":  _get(event, "network", "dest_ip") or "<unknown>",
        "network.dest_port": str(_get(event, "network", "dest_port") or ""),
        "pod.name":         _get(event, "container", "pod_name") or "<unknown>",
        "namespace":        _get(event, "container", "namespace") or "<unknown>",
    }
    result = template
    for key, value in replacements.items():
        result = result.replace("{" + key + "}", value)
    return result


# ---------------------------------------------------------------------------
# Built-in rules
# ---------------------------------------------------------------------------

BUILTIN_RULES: list[FalcoRule] = [
    FalcoRule(
        name="CONTAINER_SHELL_SPAWNED",
        description=(
            "A shell was spawned inside a container. Interactive shells in "
            "production containers often indicate an attacker exploring the environment."
        ),
        condition=_cond_shell_spawned,
        output_template=(
            "Shell spawned in container {container.name} (image: {container.image}): "
            "process={process.name} uid={process.uid} pod={pod.name} ns={namespace}"
        ),
        priority="WARNING",
        tags=frozenset(["container", "shell", "execution"]),
    ),
    FalcoRule(
        name="PRIVILEGED_CONTAINER_STARTED",
        description=(
            "A privileged container is running. Privileged containers have full "
            "host access and can be used to escape to the host node."
        ),
        condition=_cond_privileged_container,
        output_template=(
            "Privileged container running: {container.name} (image: {container.image}) "
            "pod={pod.name} ns={namespace}"
        ),
        priority="CRITICAL",
        tags=frozenset(["container", "privilege-escalation"]),
    ),
    FalcoRule(
        name="SENSITIVE_FILE_ACCESSED",
        description=(
            "A sensitive system or Kubernetes credential file was accessed. "
            "This may indicate credential harvesting or privilege escalation."
        ),
        condition=_cond_sensitive_file_access,
        output_template=(
            "Sensitive file accessed: {fd.filename} by process {process.name} "
            "in container {container.name} uid={process.uid}"
        ),
        priority="WARNING",
        tags=frozenset(["file-access", "credential-access", "container"]),
    ),
    FalcoRule(
        name="WRITE_TO_BINARY_DIR",
        description=(
            "A process wrote to a system binary directory inside a container. "
            "This may indicate a backdoor or binary replacement attack."
        ),
        condition=_cond_write_to_binary_dir,
        output_template=(
            "Binary directory write: {fd.filename} by {process.name} "
            "in container {container.name} pod={pod.name}"
        ),
        priority="ERROR",
        tags=frozenset(["container", "defense-evasion", "file-integrity"]),
    ),
    FalcoRule(
        name="ROOT_PROCESS_IN_CONTAINER",
        description=(
            "A process is running as UID 0 (root) inside a container. "
            "Root processes can escape container boundaries more easily."
        ),
        condition=_cond_root_in_container,
        output_template=(
            "Root process in container: {process.name} (uid=0) "
            "in {container.name} pod={pod.name} ns={namespace}"
        ),
        priority="NOTICE",
        tags=frozenset(["container", "privilege-escalation"]),
    ),
    FalcoRule(
        name="KUBECTL_EXEC_IN_CONTAINER",
        description=(
            "kubectl was executed inside a container. Attackers use kubectl "
            "to enumerate cluster resources, escalate privileges, or pivot "
            "to other pods and namespaces."
        ),
        condition=_cond_kubectl_in_container,
        output_template=(
            "kubectl executed in container {container.name}: "
            "cmd={process.name} pod={pod.name} ns={namespace}"
        ),
        priority="WARNING",
        tags=frozenset(["container", "discovery", "lateral-movement"]),
    ),
    FalcoRule(
        name="CRYPTO_MINING_PROCESS_DETECTED",
        description=(
            "A known crypto-mining binary or process with mining-related "
            "name patterns was started."
        ),
        condition=_cond_crypto_mining,
        output_template=(
            "Crypto-mining process: {process.name} (exe={process.exe}) "
            "in container {container.name} pod={pod.name}"
        ),
        priority="CRITICAL",
        tags=frozenset(["container", "cryptomining", "impact"]),
    ),
    FalcoRule(
        name="CONTAINER_ESCAPE_VIA_MOUNT",
        description=(
            "A mount syscall was invoked from inside a container. This is "
            "a common technique to break out of container isolation."
        ),
        condition=_cond_container_escape_mount,
        output_template=(
            "Container escape attempt (mount): process={process.name} "
            "in {container.name} uid={process.uid} pod={pod.name}"
        ),
        priority="CRITICAL",
        tags=frozenset(["container-escape", "privilege-escalation"]),
    ),
    FalcoRule(
        name="CONTAINER_ESCAPE_VIA_PTRACE",
        description=(
            "A ptrace syscall was invoked from inside a container, which can be "
            "used to attach to host processes and escape container isolation."
        ),
        condition=_cond_container_escape_ptrace,
        output_template=(
            "Container escape attempt (ptrace): process={process.name} "
            "in {container.name} uid={process.uid}"
        ),
        priority="CRITICAL",
        tags=frozenset(["container-escape", "privilege-escalation"]),
    ),
    FalcoRule(
        name="OUTBOUND_UNUSUAL_PORT",
        description=(
            "A container initiated an outbound TCP connection to a non-standard port. "
            "This may indicate command-and-control (C2) activity or data exfiltration."
        ),
        condition=_cond_outbound_unusual_port,
        output_template=(
            "Unusual outbound connection from {container.name}: "
            "dest={network.dest_ip}:{network.dest_port} pod={pod.name} ns={namespace}"
        ),
        priority="WARNING",
        tags=frozenset(["network", "c2", "exfiltration", "container"]),
    ),
    FalcoRule(
        name="K8S_API_ENUMERATION",
        description=(
            "A kubectl command enumerating sensitive cluster resources (secrets, "
            "roles, service accounts) was detected."
        ),
        condition=_cond_k8s_api_enumeration,
        output_template=(
            "K8s API enumeration: cmd={process.name} in {container.name} "
            "uid={process.uid} pod={pod.name}"
        ),
        priority="WARNING",
        tags=frozenset(["discovery", "credential-access", "container"]),
    ),
    FalcoRule(
        name="NSENTER_EXECUTED",
        description=(
            "nsenter was executed, which is used to enter Linux namespaces and "
            "is a common container escape technique."
        ),
        condition=_cond_nsenter_executed,
        output_template=(
            "nsenter executed: process={process.name} in {container.name} "
            "uid={process.uid} pod={pod.name}"
        ),
        priority="CRITICAL",
        tags=frozenset(["container-escape", "privilege-escalation", "defense-evasion"]),
    ),
    FalcoRule(
        name="SETUID_BINARY_EXECUTED_IN_CONTAINER",
        description=(
            "A setuid-capable binary (sudo, su, passwd, etc.) was executed inside "
            "a container. These binaries can be used for privilege escalation."
        ),
        condition=_cond_setuid_binary_exec,
        output_template=(
            "Setuid binary in container: {process.name} in {container.name} "
            "uid={process.uid} pod={pod.name} ns={namespace}"
        ),
        priority="WARNING",
        tags=frozenset(["container", "privilege-escalation"]),
    ),
    FalcoRule(
        name="DOCKER_SOCKET_ACCESSED",
        description=(
            "The Docker or containerd socket was accessed from inside a container. "
            "Socket access grants full container runtime control, equivalent to root "
            "on the host."
        ),
        condition=_cond_docker_socket_access,
        output_template=(
            "Container runtime socket accessed: {fd.filename} by {process.name} "
            "in {container.name} uid={process.uid} pod={pod.name}"
        ),
        priority="CRITICAL",
        tags=frozenset(["container-escape", "privilege-escalation", "lateral-movement"]),
    ),
]


# ---------------------------------------------------------------------------
# Evaluation functions
# ---------------------------------------------------------------------------

def evaluate_rule(rule: FalcoRule, event: dict[str, Any]) -> Optional[RuleMatch]:
    """
    Evaluate a single rule against an event.

    Returns a RuleMatch if the rule fires, None otherwise.
    """
    try:
        fired = rule.condition(event)
    except Exception:
        fired = False

    if not fired:
        return None

    output = _render_output(rule.output_template, event)
    return RuleMatch(rule=rule, output=output)


def evaluate_all(
    event: dict[str, Any],
    rules: Optional[list[FalcoRule]] = None,
) -> list[RuleMatch]:
    """
    Evaluate all rules (or a provided subset) against a single event.

    Args:
        event:  The event dict to evaluate.
        rules:  Rules to evaluate. Defaults to BUILTIN_RULES.

    Returns:
        List of RuleMatch objects for all rules that fired.
    """
    if rules is None:
        rules = BUILTIN_RULES
    matches: list[RuleMatch] = []
    for rule in rules:
        match = evaluate_rule(rule, event)
        if match:
            matches.append(match)
    return matches


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

class RuleEngine:
    """
    Stateful rule engine that can load rules and evaluate batches of events.

    Usage:
        engine = RuleEngine()
        engine.load_defaults()
        engine.add_rule(custom_rule)

        report = engine.evaluate_batch(events)
        print(report.summary())
    """

    def __init__(self) -> None:
        self._rules: list[FalcoRule] = []

    def load_defaults(self) -> "RuleEngine":
        """Load all built-in rules into the engine."""
        self._rules = list(BUILTIN_RULES)
        return self

    def add_rule(self, rule: FalcoRule) -> "RuleEngine":
        """Add a custom rule to the engine."""
        self._rules.append(rule)
        return self

    def remove_rule(self, rule_name: str) -> "RuleEngine":
        """Remove a rule by name."""
        self._rules = [r for r in self._rules if r.name != rule_name]
        return self

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def get_rule(self, name: str) -> Optional[FalcoRule]:
        """Return a rule by name, or None if not found."""
        return next((r for r in self._rules if r.name == name), None)

    def rules_by_priority(self, priority: str) -> list[FalcoRule]:
        """Return all rules with the given priority."""
        return [r for r in self._rules if r.priority == priority]

    def rules_by_tag(self, tag: str) -> list[FalcoRule]:
        """Return all rules that include the given tag."""
        return [r for r in self._rules if tag in r.tags]

    def evaluate(self, event: dict[str, Any]) -> list[RuleMatch]:
        """Evaluate all loaded rules against a single event."""
        return evaluate_all(event, self._rules)

    def evaluate_batch(self, events: list[dict[str, Any]]) -> EvaluationReport:
        """
        Evaluate all rules against a batch of events.

        Returns an EvaluationReport with aggregate statistics.
        """
        report = EvaluationReport(total_events=len(events))

        for event in events:
            for match in self.evaluate(event):
                report.total_matches += 1
                p = match.rule.priority
                report.matches_by_priority[p] = report.matches_by_priority.get(p, 0) + 1
                n = match.rule.name
                report.matches_by_rule[n] = report.matches_by_rule.get(n, 0) + 1
                report.all_matches.append(match)

        return report
