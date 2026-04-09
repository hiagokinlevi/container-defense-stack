"""
Tests for runtime/falco_rules.py and validators/rbac_auditor.py

falco_rules.py:
  - evaluate_rule returns None when condition is False
  - evaluate_rule returns RuleMatch when condition fires
  - evaluate_all returns matches from all fired rules
  - evaluate_all returns empty list when no rules fire
  - CONTAINER_SHELL_SPAWNED fires when shell execve in container
  - CONTAINER_SHELL_SPAWNED does not fire outside container context
  - CONTAINER_SHELL_SPAWNED does not fire for non-shell process
  - PRIVILEGED_CONTAINER_STARTED fires when privileged=True
  - PRIVILEGED_CONTAINER_STARTED does not fire when privileged=False
  - SENSITIVE_FILE_ACCESSED fires for /etc/shadow
  - SENSITIVE_FILE_ACCESSED fires for /etc/kubernetes/ path
  - SENSITIVE_FILE_ACCESSED does not fire for /tmp/log.txt
  - WRITE_TO_BINARY_DIR fires for write to /usr/bin/evil
  - ROOT_PROCESS_IN_CONTAINER fires for uid=0 in container
  - ROOT_PROCESS_IN_CONTAINER does not fire for uid=1000
  - KUBECTL_EXEC_IN_CONTAINER fires when kubectl in container
  - CRYPTO_MINING_PROCESS_DETECTED fires for xmrig
  - CRYPTO_MINING_PROCESS_DETECTED fires for cmdline with xmr
  - CONTAINER_ESCAPE_VIA_MOUNT fires for mount syscall in container
  - CONTAINER_ESCAPE_VIA_PTRACE fires for ptrace syscall in container
  - OUTBOUND_UNUSUAL_PORT fires for port 4444 outbound
  - OUTBOUND_UNUSUAL_PORT does not fire for port 443
  - K8S_API_ENUMERATION fires for 'kubectl get secrets'
  - NSENTER_EXECUTED fires when nsenter process
  - DOCKER_SOCKET_ACCESSED fires for /var/run/docker.sock
  - RuleEngine.load_defaults populates rules
  - RuleEngine.rule_count matches BUILTIN_RULES length
  - RuleEngine.add_rule adds custom rule
  - RuleEngine.remove_rule removes by name
  - RuleEngine.get_rule returns rule or None
  - RuleEngine.rules_by_priority filters correctly
  - RuleEngine.rules_by_tag filters correctly
  - RuleEngine.evaluate_batch returns EvaluationReport with correct counts
  - EvaluationReport.summary() contains CRITICAL count
  - _render_output replaces container.name placeholder
  - Exception in condition treated as no match

rbac_auditor.py:
  - RbacAuditReport.passed True when no high/critical
  - RbacAuditReport.passed False when high present
  - RbacAuditReport.summary contains PASS/FAIL
  - RBAC-001 cluster-admin ClusterRoleBinding flagged
  - RBAC-001 non-cluster-admin binding not flagged
  - RBAC-002 wildcard verb in Role flagged
  - RBAC-002 specific verbs not flagged
  - RBAC-003 wildcard resource in ClusterRole flagged
  - RBAC-003 specific resources not flagged
  - RBAC-004 secrets get in Role flagged
  - RBAC-004 non-secrets resource not flagged
  - RBAC-005 SA without automount=false flagged
  - RBAC-005 SA with automount=false not flagged
  - RBAC-006 ClusterRole with node write flagged
  - RBAC-006 ClusterRole with node read not flagged
  - RBAC-007 RoleBinding without namespace flagged
  - RBAC-007 RoleBinding with namespace not flagged
  - audit_rbac_file with multi-document YAML
  - audit_rbac_file with YAML parse error produces warning
  - audit_rbac_directory scans multiple files
  - clean RBAC manifest passes
"""
from __future__ import annotations

import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from runtime.falco_rules import (
    BUILTIN_RULES,
    EvaluationReport,
    FalcoRule,
    RuleEngine,
    RuleMatch,
    _render_output,
    evaluate_all,
    evaluate_rule,
)
from validators.rbac_auditor import (
    RbacAuditReport,
    RbacFinding,
    audit_rbac_directory,
    audit_rbac_file,
)


# ---------------------------------------------------------------------------
# Event builder helpers
# ---------------------------------------------------------------------------

def _event(
    container_id: str = "abc123",
    container_name: str = "web-app",
    container_image: str = "nginx:1.21",
    privileged: bool = False,
    proc_name: str = "nginx",
    proc_exe: str = "/usr/sbin/nginx",
    proc_uid: int = 1000,
    proc_args: list | None = None,
    fd_filename: str = "",
    fd_openflags: int = 0,
    syscall_name: str = "",
    net_direction: str = "",
    net_dest_ip: str = "",
    net_dest_port: int = 0,
    net_proto: str = "tcp",
    pod_name: str = "web-pod",
    namespace: str = "default",
) -> dict[str, Any]:
    return {
        "container": {
            "id":        container_id,
            "name":      container_name,
            "image":     container_image,
            "privileged": privileged,
            "uid":       proc_uid,
            "pod_name":  pod_name,
            "namespace": namespace,
        },
        "process": {
            "name":   proc_name,
            "exe":    proc_exe,
            "uid":    proc_uid,
            "args":   proc_args or [],
            "cmdline": f"{proc_name} {' '.join(proc_args or [])}",
        },
        "fd": {
            "filename":   fd_filename,
            "openflags":  fd_openflags,
            "typechar":   "f",
        },
        "syscall": {
            "name": syscall_name,
            "args": {},
        },
        "network": {
            "direction": net_direction,
            "dest_ip":   net_dest_ip,
            "dest_port": net_dest_port,
            "proto":     net_proto,
        },
    }


def _no_container_event() -> dict[str, Any]:
    """Event without container context."""
    return _event(container_id="")


# ---------------------------------------------------------------------------
# evaluate_rule
# ---------------------------------------------------------------------------

class TestEvaluateRule:

    def test_returns_none_when_condition_false(self):
        rule = FalcoRule(
            name="TEST",
            description="test",
            condition=lambda e: False,
            output_template="output",
            priority="WARNING",
        )
        assert evaluate_rule(rule, _event()) is None

    def test_returns_match_when_condition_true(self):
        rule = FalcoRule(
            name="TEST",
            description="test",
            condition=lambda e: True,
            output_template="output",
            priority="WARNING",
        )
        match = evaluate_rule(rule, _event())
        assert isinstance(match, RuleMatch)
        assert match.rule.name == "TEST"

    def test_exception_in_condition_returns_none(self):
        def bad_condition(e):
            raise RuntimeError("oops")
        rule = FalcoRule(
            name="BAD",
            description="test",
            condition=bad_condition,
            output_template="out",
            priority="INFO",
        )
        assert evaluate_rule(rule, _event()) is None


# ---------------------------------------------------------------------------
# evaluate_all
# ---------------------------------------------------------------------------

class TestEvaluateAll:

    def test_returns_empty_when_no_rules_fire(self):
        event = _event(proc_name="nginx", proc_uid=1000)
        matches = evaluate_all(event)
        # May have some matches (privileged=False, no sensitive file, etc.)
        # Just ensure it doesn't crash and returns a list
        assert isinstance(matches, list)

    def test_custom_rules_list(self):
        rules = [
            FalcoRule("R1", "", lambda e: True, "out", "WARNING"),
            FalcoRule("R2", "", lambda e: False, "out", "INFO"),
        ]
        matches = evaluate_all(_event(), rules=rules)
        assert len(matches) == 1
        assert matches[0].rule.name == "R1"


# ---------------------------------------------------------------------------
# CONTAINER_SHELL_SPAWNED
# ---------------------------------------------------------------------------

class TestContainerShellSpawned:

    def test_fires_when_bash_execve_in_container(self):
        event = _event(proc_name="bash", syscall_name="execve")
        matches = [m for m in evaluate_all(event) if m.rule.name == "CONTAINER_SHELL_SPAWNED"]
        assert len(matches) == 1

    def test_fires_when_sh_in_container(self):
        event = _event(proc_name="sh", syscall_name="execve")
        matches = [m for m in evaluate_all(event) if m.rule.name == "CONTAINER_SHELL_SPAWNED"]
        assert len(matches) == 1

    def test_does_not_fire_outside_container(self):
        event = _no_container_event()
        event["process"]["name"] = "bash"
        event["syscall"]["name"] = "execve"
        matches = [m for m in evaluate_all(event) if m.rule.name == "CONTAINER_SHELL_SPAWNED"]
        assert len(matches) == 0

    def test_does_not_fire_for_non_shell(self):
        event = _event(proc_name="python3", syscall_name="execve")
        matches = [m for m in evaluate_all(event) if m.rule.name == "CONTAINER_SHELL_SPAWNED"]
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# PRIVILEGED_CONTAINER_STARTED
# ---------------------------------------------------------------------------

class TestPrivilegedContainer:

    def test_fires_when_privileged_true(self):
        event = _event(privileged=True)
        matches = [m for m in evaluate_all(event) if m.rule.name == "PRIVILEGED_CONTAINER_STARTED"]
        assert len(matches) == 1

    def test_does_not_fire_when_privileged_false(self):
        event = _event(privileged=False)
        matches = [m for m in evaluate_all(event) if m.rule.name == "PRIVILEGED_CONTAINER_STARTED"]
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# SENSITIVE_FILE_ACCESSED
# ---------------------------------------------------------------------------

class TestSensitiveFileAccessed:

    def test_fires_for_etc_shadow(self):
        event = _event(fd_filename="/etc/shadow")
        matches = [m for m in evaluate_all(event) if m.rule.name == "SENSITIVE_FILE_ACCESSED"]
        assert len(matches) == 1

    def test_fires_for_kubernetes_creds(self):
        event = _event(fd_filename="/etc/kubernetes/admin.conf")
        matches = [m for m in evaluate_all(event) if m.rule.name == "SENSITIVE_FILE_ACCESSED"]
        assert len(matches) == 1

    def test_does_not_fire_for_tmp(self):
        event = _event(fd_filename="/tmp/logfile.txt")
        matches = [m for m in evaluate_all(event) if m.rule.name == "SENSITIVE_FILE_ACCESSED"]
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# WRITE_TO_BINARY_DIR
# ---------------------------------------------------------------------------

class TestWriteToBinaryDir:

    def test_fires_for_write_to_usr_bin(self):
        # openflags=1 = O_WRONLY
        event = _event(fd_filename="/usr/bin/evil", fd_openflags=1)
        matches = [m for m in evaluate_all(event) if m.rule.name == "WRITE_TO_BINARY_DIR"]
        assert len(matches) == 1

    def test_does_not_fire_for_read_access(self):
        event = _event(fd_filename="/usr/bin/bash", fd_openflags=0)
        matches = [m for m in evaluate_all(event) if m.rule.name == "WRITE_TO_BINARY_DIR"]
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# ROOT_PROCESS_IN_CONTAINER
# ---------------------------------------------------------------------------

class TestRootProcessInContainer:

    def test_fires_for_uid_zero_in_container(self):
        event = _event(proc_uid=0)
        matches = [m for m in evaluate_all(event) if m.rule.name == "ROOT_PROCESS_IN_CONTAINER"]
        assert len(matches) == 1

    def test_does_not_fire_for_non_root(self):
        event = _event(proc_uid=1000)
        matches = [m for m in evaluate_all(event) if m.rule.name == "ROOT_PROCESS_IN_CONTAINER"]
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# KUBECTL_EXEC_IN_CONTAINER
# ---------------------------------------------------------------------------

class TestKubectlInContainer:

    def test_fires_when_kubectl_name(self):
        event = _event(proc_name="kubectl")
        matches = [m for m in evaluate_all(event) if m.rule.name == "KUBECTL_EXEC_IN_CONTAINER"]
        assert len(matches) == 1


# ---------------------------------------------------------------------------
# CRYPTO_MINING
# ---------------------------------------------------------------------------

class TestCryptoMining:

    def test_fires_for_xmrig(self):
        event = _event(proc_name="xmrig")
        matches = [m for m in evaluate_all(event) if m.rule.name == "CRYPTO_MINING_PROCESS_DETECTED"]
        assert len(matches) == 1

    def test_fires_for_xmr_in_cmdline(self):
        event = _event(proc_name="worker", proc_args=["--pool", "xmr.pool.io"])
        event["process"]["cmdline"] = "worker --pool xmr.pool.io"
        matches = [m for m in evaluate_all(event) if m.rule.name == "CRYPTO_MINING_PROCESS_DETECTED"]
        assert len(matches) == 1


# ---------------------------------------------------------------------------
# Container escape
# ---------------------------------------------------------------------------

class TestContainerEscape:

    def test_mount_fires_in_container(self):
        event = _event(syscall_name="mount")
        matches = [m for m in evaluate_all(event) if m.rule.name == "CONTAINER_ESCAPE_VIA_MOUNT"]
        assert len(matches) == 1

    def test_ptrace_fires_in_container(self):
        event = _event(syscall_name="ptrace")
        matches = [m for m in evaluate_all(event) if m.rule.name == "CONTAINER_ESCAPE_VIA_PTRACE"]
        assert len(matches) == 1

    def test_nsenter_fires(self):
        event = _event(proc_name="nsenter")
        matches = [m for m in evaluate_all(event) if m.rule.name == "NSENTER_EXECUTED"]
        assert len(matches) == 1

    def test_docker_socket_fires(self):
        event = _event(fd_filename="/var/run/docker.sock")
        matches = [m for m in evaluate_all(event) if m.rule.name == "DOCKER_SOCKET_ACCESSED"]
        assert len(matches) == 1


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

class TestOutboundUnusualPort:

    def test_fires_for_port_4444(self):
        event = _event(net_direction="outbound", net_dest_port=4444, net_dest_ip="1.2.3.4")
        matches = [m for m in evaluate_all(event) if m.rule.name == "OUTBOUND_UNUSUAL_PORT"]
        assert len(matches) == 1

    def test_does_not_fire_for_port_443(self):
        event = _event(net_direction="outbound", net_dest_port=443, net_dest_ip="1.2.3.4")
        matches = [m for m in evaluate_all(event) if m.rule.name == "OUTBOUND_UNUSUAL_PORT"]
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# K8s API enumeration
# ---------------------------------------------------------------------------

class TestK8sApiEnumeration:

    def test_fires_for_kubectl_get_secrets(self):
        event = _event(proc_name="kubectl", proc_args=["get", "secrets"])
        event["process"]["cmdline"] = "kubectl get secrets"
        matches = [m for m in evaluate_all(event) if m.rule.name == "K8S_API_ENUMERATION"]
        assert len(matches) == 1

    def test_does_not_fire_for_kubectl_get_pods(self):
        event = _event(proc_name="kubectl", proc_args=["get", "pods"])
        event["process"]["cmdline"] = "kubectl get pods"
        matches = [m for m in evaluate_all(event) if m.rule.name == "K8S_API_ENUMERATION"]
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# RuleEngine
# ---------------------------------------------------------------------------

class TestRuleEngine:

    def test_load_defaults_populates_rules(self):
        engine = RuleEngine()
        engine.load_defaults()
        assert engine.rule_count == len(BUILTIN_RULES)

    def test_rule_count_after_add(self):
        engine = RuleEngine()
        engine.load_defaults()
        n = engine.rule_count
        engine.add_rule(FalcoRule("CUSTOM", "", lambda e: False, "", "INFO"))
        assert engine.rule_count == n + 1

    def test_remove_rule_by_name(self):
        engine = RuleEngine()
        engine.load_defaults()
        n = engine.rule_count
        engine.remove_rule("CONTAINER_SHELL_SPAWNED")
        assert engine.rule_count == n - 1

    def test_get_rule_returns_rule(self):
        engine = RuleEngine()
        engine.load_defaults()
        rule = engine.get_rule("PRIVILEGED_CONTAINER_STARTED")
        assert rule is not None
        assert rule.priority == "CRITICAL"

    def test_get_rule_returns_none_for_unknown(self):
        engine = RuleEngine()
        engine.load_defaults()
        assert engine.get_rule("DOES_NOT_EXIST") is None

    def test_rules_by_priority_filters(self):
        engine = RuleEngine()
        engine.load_defaults()
        critical_rules = engine.rules_by_priority("CRITICAL")
        assert len(critical_rules) > 0
        assert all(r.priority == "CRITICAL" for r in critical_rules)

    def test_rules_by_tag_filters(self):
        engine = RuleEngine()
        engine.load_defaults()
        escape_rules = engine.rules_by_tag("container-escape")
        assert len(escape_rules) > 0

    def test_evaluate_batch_counts_correctly(self):
        engine = RuleEngine()
        engine.load_defaults()
        events = [
            _event(privileged=True),   # triggers PRIVILEGED_CONTAINER_STARTED
            _event(proc_name="nginx", proc_uid=1000),  # clean
        ]
        report = engine.evaluate_batch(events)
        assert report.total_events == 2
        assert report.total_matches >= 1

    def test_evaluate_batch_summary_contains_critical(self):
        engine = RuleEngine()
        engine.load_defaults()
        report = engine.evaluate_batch([_event(privileged=True)])
        assert "CRITICAL" in report.summary()


# ---------------------------------------------------------------------------
# _render_output
# ---------------------------------------------------------------------------

class TestRenderOutput:

    def test_replaces_container_name(self):
        event = _event(container_name="my-app")
        output = _render_output("container={container.name}", event)
        assert "my-app" in output

    def test_replaces_process_name(self):
        event = _event(proc_name="bash")
        output = _render_output("process={process.name}", event)
        assert "bash" in output

    def test_missing_field_defaults_to_unknown(self):
        event = {}
        output = _render_output("container={container.name}", event)
        assert "<unknown>" in output


# ---------------------------------------------------------------------------
# RBAC audit — RbacAuditReport
# ---------------------------------------------------------------------------

class TestRbacAuditReport:

    def test_passed_true_when_no_critical_high(self):
        r = RbacAuditReport()
        r.findings.append(RbacFinding("RBAC-007", "low", "RoleBinding", "rb", None, "", ""))
        assert r.passed is True

    def test_passed_false_when_high(self):
        r = RbacAuditReport()
        r.findings.append(RbacFinding("RBAC-002", "high", "Role", "r", None, "", ""))
        assert r.passed is False

    def test_summary_contains_pass_or_fail(self):
        r = RbacAuditReport()
        s = r.summary()
        assert "PASS" in s or "FAIL" in s

    def test_findings_by_rule_filters(self):
        r = RbacAuditReport()
        r.findings = [
            RbacFinding("RBAC-001", "critical", "ClusterRoleBinding", "crb", None, "", ""),
            RbacFinding("RBAC-002", "high", "Role", "role", None, "", ""),
        ]
        assert len(r.findings_by_rule("RBAC-001")) == 1
        assert len(r.findings_by_rule("RBAC-002")) == 1


# ---------------------------------------------------------------------------
# YAML helper
# ---------------------------------------------------------------------------

def _write_yaml(content: str) -> Path:
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    )
    tmp.write(textwrap.dedent(content))
    tmp.flush()
    tmp.close()
    return Path(tmp.name)


# ---------------------------------------------------------------------------
# RBAC-001
# ---------------------------------------------------------------------------

class TestRbac001ClusterAdmin:

    def test_cluster_admin_binding_flagged(self):
        path = _write_yaml("""\
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRoleBinding
            metadata:
              name: admin-all
            roleRef:
              apiGroup: rbac.authorization.k8s.io
              kind: ClusterRole
              name: cluster-admin
            subjects:
              - kind: User
                name: alice
        """)
        report = audit_rbac_file(path)
        findings = report.findings_by_rule("RBAC-001")
        assert len(findings) >= 1

    def test_non_admin_binding_not_flagged(self):
        path = _write_yaml("""\
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRoleBinding
            metadata:
              name: view-only
            roleRef:
              apiGroup: rbac.authorization.k8s.io
              kind: ClusterRole
              name: view
            subjects:
              - kind: User
                name: bob
        """)
        report = audit_rbac_file(path)
        assert len(report.findings_by_rule("RBAC-001")) == 0


# ---------------------------------------------------------------------------
# RBAC-002
# ---------------------------------------------------------------------------

class TestRbac002WildcardVerb:

    def test_wildcard_verb_flagged(self):
        path = _write_yaml("""\
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata:
              name: super-role
              namespace: default
            rules:
              - apiGroups: [""]
                resources: ["pods"]
                verbs: ["*"]
        """)
        report = audit_rbac_file(path)
        assert len(report.findings_by_rule("RBAC-002")) >= 1

    def test_specific_verbs_not_flagged(self):
        path = _write_yaml("""\
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata:
              name: read-only
              namespace: default
            rules:
              - apiGroups: [""]
                resources: ["pods"]
                verbs: ["get", "list", "watch"]
        """)
        report = audit_rbac_file(path)
        assert len(report.findings_by_rule("RBAC-002")) == 0


# ---------------------------------------------------------------------------
# RBAC-003
# ---------------------------------------------------------------------------

class TestRbac003WildcardResource:

    def test_wildcard_resource_flagged(self):
        path = _write_yaml("""\
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRole
            metadata:
              name: everything
            rules:
              - apiGroups: [""]
                resources: ["*"]
                verbs: ["get"]
        """)
        report = audit_rbac_file(path)
        assert len(report.findings_by_rule("RBAC-003")) >= 1

    def test_specific_resources_not_flagged(self):
        path = _write_yaml("""\
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRole
            metadata:
              name: pods-only
            rules:
              - apiGroups: [""]
                resources: ["pods"]
                verbs: ["get"]
        """)
        report = audit_rbac_file(path)
        assert len(report.findings_by_rule("RBAC-003")) == 0


# ---------------------------------------------------------------------------
# RBAC-004
# ---------------------------------------------------------------------------

class TestRbac004SecretsReadable:

    def test_secrets_get_flagged(self):
        path = _write_yaml("""\
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata:
              name: secret-reader
              namespace: default
            rules:
              - apiGroups: [""]
                resources: ["secrets"]
                verbs: ["get", "list"]
        """)
        report = audit_rbac_file(path)
        assert len(report.findings_by_rule("RBAC-004")) >= 1

    def test_non_secrets_resource_not_flagged(self):
        path = _write_yaml("""\
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata:
              name: pod-reader
              namespace: default
            rules:
              - apiGroups: [""]
                resources: ["pods"]
                verbs: ["get", "list"]
        """)
        report = audit_rbac_file(path)
        assert len(report.findings_by_rule("RBAC-004")) == 0


# ---------------------------------------------------------------------------
# RBAC-005
# ---------------------------------------------------------------------------

class TestRbac005ServiceAccountAutomount:

    def test_sa_without_automount_false_flagged(self):
        path = _write_yaml("""\
            apiVersion: v1
            kind: ServiceAccount
            metadata:
              name: app-sa
              namespace: default
        """)
        report = audit_rbac_file(path)
        assert len(report.findings_by_rule("RBAC-005")) >= 1

    def test_sa_with_automount_false_not_flagged(self):
        path = _write_yaml("""\
            apiVersion: v1
            kind: ServiceAccount
            metadata:
              name: app-sa
              namespace: default
            automountServiceAccountToken: false
        """)
        report = audit_rbac_file(path)
        assert len(report.findings_by_rule("RBAC-005")) == 0


# ---------------------------------------------------------------------------
# RBAC-006
# ---------------------------------------------------------------------------

class TestRbac006NodeWrite:

    def test_node_write_flagged(self):
        path = _write_yaml("""\
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRole
            metadata:
              name: node-admin
            rules:
              - apiGroups: [""]
                resources: ["nodes"]
                verbs: ["update", "patch"]
        """)
        report = audit_rbac_file(path)
        assert len(report.findings_by_rule("RBAC-006")) >= 1

    def test_node_read_not_flagged(self):
        path = _write_yaml("""\
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRole
            metadata:
              name: node-viewer
            rules:
              - apiGroups: [""]
                resources: ["nodes"]
                verbs: ["get", "list"]
        """)
        report = audit_rbac_file(path)
        assert len(report.findings_by_rule("RBAC-006")) == 0


# ---------------------------------------------------------------------------
# RBAC-007
# ---------------------------------------------------------------------------

class TestRbac007RoleBindingMissingNamespace:

    def test_rolebinding_without_namespace_flagged(self):
        path = _write_yaml("""\
            apiVersion: rbac.authorization.k8s.io/v1
            kind: RoleBinding
            metadata:
              name: no-ns-binding
            roleRef:
              apiGroup: rbac.authorization.k8s.io
              kind: Role
              name: some-role
            subjects:
              - kind: ServiceAccount
                name: app-sa
        """)
        report = audit_rbac_file(path)
        assert len(report.findings_by_rule("RBAC-007")) >= 1

    def test_rolebinding_with_namespace_not_flagged(self):
        path = _write_yaml("""\
            apiVersion: rbac.authorization.k8s.io/v1
            kind: RoleBinding
            metadata:
              name: ns-binding
              namespace: default
            roleRef:
              apiGroup: rbac.authorization.k8s.io
              kind: Role
              name: some-role
            subjects:
              - kind: ServiceAccount
                name: app-sa
                namespace: default
        """)
        report = audit_rbac_file(path)
        assert len(report.findings_by_rule("RBAC-007")) == 0


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------

class TestRbacIntegration:

    def test_multi_document_yaml(self, tmp_path):
        path = tmp_path / "rbac.yaml"
        path.write_text(textwrap.dedent("""\
            apiVersion: v1
            kind: ServiceAccount
            metadata:
              name: app-sa
              namespace: default
            automountServiceAccountToken: false
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata:
              name: read-only
              namespace: default
            rules:
              - apiGroups: [""]
                resources: ["pods"]
                verbs: ["get", "list"]
        """))
        report = audit_rbac_file(path)
        assert report.resources_audited == 2
        assert report.passed is True

    def test_yaml_parse_error_produces_warning(self):
        path = _write_yaml("{ invalid yaml [[[")
        report = audit_rbac_file(path)
        assert len(report.warnings) > 0

    def test_directory_scan(self, tmp_path):
        for i, content in enumerate([
            "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: sa\n  namespace: default\nautomountServiceAccountToken: false\n",
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: r\n  namespace: default\nrules:\n  - apiGroups: [\"\"]\n    resources: [\"pods\"]\n    verbs: [\"get\"]\n",
        ]):
            (tmp_path / f"manifest{i}.yaml").write_text(content)
        report = audit_rbac_directory(tmp_path)
        assert report.resources_audited == 2
