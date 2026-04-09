"""
Kubernetes RBAC Audit Analyzer
================================
Audits Kubernetes RBAC manifests (.yaml files containing Role, ClusterRole,
RoleBinding, ClusterRoleBinding, and ServiceAccount resources) for overly
permissive configurations and security misconfigurations.

Checks performed:
  - RBAC-001 CRITICAL: ClusterRoleBinding grants cluster-admin
  - RBAC-002 HIGH:     Wildcard verb ('*') in any Role or ClusterRole rule
  - RBAC-003 HIGH:     Wildcard resource ('*') in any Role or ClusterRole rule
  - RBAC-004 HIGH:     Secrets resource readable (get/list/watch on secrets)
  - RBAC-005 MEDIUM:   ServiceAccount with automountServiceAccountToken not
                       explicitly set to false
  - RBAC-006 MEDIUM:   ClusterRole with write access to nodes resource
  - RBAC-007 LOW:      RoleBinding or ClusterRoleBinding missing a namespace
                       (potential misconfiguration indicator)

Usage:
    from validators.rbac_auditor import audit_rbac_file, RbacAuditReport

    report = audit_rbac_file(Path("kubernetes/rbac/my-roles.yaml"))
    for f in report.findings:
        print(f"[{f.severity.upper()}] {f.rule_id}: {f.message}")

    if not report.passed:
        print("RBAC audit FAILED — review HIGH/CRITICAL findings.")
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RbacFinding:
    """A single RBAC security finding."""

    rule_id: str
    severity: str          # "critical", "high", "medium", "low"
    resource_kind: str     # "ClusterRole", "RoleBinding", etc.
    resource_name: str
    namespace: Optional[str]
    message: str
    remediation: str
    evidence: str = ""     # Specific YAML snippet or field that triggered the finding


@dataclass
class RbacAuditReport:
    """Results of auditing RBAC manifests from one or more YAML files."""

    file_paths: list[Path] = field(default_factory=list)
    findings: list[RbacFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    resources_audited: int = 0

    @property
    def passed(self) -> bool:
        """True if no critical or high findings are present."""
        return not any(f.severity in ("critical", "high") for f in self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "low")

    def findings_by_rule(self, rule_id: str) -> list[RbacFinding]:
        return [f for f in self.findings if f.rule_id == rule_id]

    def summary(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return (
            f"[{status}] RBAC audit — {self.resources_audited} resources | "
            f"CRITICAL={self.critical_count} "
            f"HIGH={self.high_count} "
            f"MEDIUM={self.medium_count} "
            f"LOW={self.low_count}"
        )


# ---------------------------------------------------------------------------
# YAML parsing helpers
# ---------------------------------------------------------------------------

def _load_all_docs(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """
    Load all YAML documents from a file.

    Returns a tuple of (documents, warnings).
    """
    if yaml is None:
        return [], ["pyyaml not installed — cannot parse YAML"]

    try:
        raw = path.read_text(encoding="utf-8")
        docs = [d for d in yaml.safe_load_all(raw) if isinstance(d, dict)]
        return docs, []
    except yaml.YAMLError as exc:
        return [], [f"YAML parse error in {path.name}: {exc}"]
    except OSError as exc:
        return [], [f"Cannot read {path.name}: {exc}"]


def _kind(doc: dict) -> str:
    return str(doc.get("kind", "")).strip()


def _name(doc: dict) -> str:
    return str(doc.get("metadata", {}).get("name", "<unnamed>"))


def _namespace(doc: dict) -> Optional[str]:
    return doc.get("metadata", {}).get("namespace")


def _rules(doc: dict) -> list[dict]:
    return doc.get("rules", []) or []


# ---------------------------------------------------------------------------
# Rule checks
# ---------------------------------------------------------------------------

def _check_rbac001_cluster_admin_binding(
    doc: dict,
    report: RbacAuditReport,
) -> None:
    """RBAC-001: ClusterRoleBinding that grants cluster-admin."""
    kind = _kind(doc)
    if kind not in ("ClusterRoleBinding", "RoleBinding"):
        return

    role_ref = doc.get("roleRef", {})
    if role_ref.get("name") == "cluster-admin":
        report.findings.append(
            RbacFinding(
                rule_id="RBAC-001",
                severity="critical",
                resource_kind=kind,
                resource_name=_name(doc),
                namespace=_namespace(doc),
                message=(
                    f"{kind} '{_name(doc)}' grants the 'cluster-admin' ClusterRole. "
                    "cluster-admin has unrestricted access to all resources in all "
                    "namespaces — this is equivalent to giving a subject root on the cluster."
                ),
                remediation=(
                    "Replace the cluster-admin binding with a least-privilege Role "
                    "or ClusterRole that grants only the specific verbs and resources "
                    "the subject requires."
                ),
                evidence=f"roleRef.name: cluster-admin",
            )
        )


def _check_rbac002_wildcard_verb(
    doc: dict,
    report: RbacAuditReport,
) -> None:
    """RBAC-002: Wildcard verb in Role or ClusterRole."""
    kind = _kind(doc)
    if kind not in ("Role", "ClusterRole"):
        return

    for rule in _rules(doc):
        verbs = rule.get("verbs", [])
        if "*" in verbs:
            resources = rule.get("resources", ["<unknown>"])
            report.findings.append(
                RbacFinding(
                    rule_id="RBAC-002",
                    severity="high",
                    resource_kind=kind,
                    resource_name=_name(doc),
                    namespace=_namespace(doc),
                    message=(
                        f"{kind} '{_name(doc)}' has wildcard verb ('*') on "
                        f"resource(s): {resources}. Wildcard verbs grant all "
                        "operations (get, list, create, update, delete, patch, watch, etc.)."
                    ),
                    remediation=(
                        "Replace the wildcard verb with the specific verbs the workload "
                        "actually needs (e.g. [get, list, watch] for read-only access)."
                    ),
                    evidence=f"verbs: ['*'] on resources: {resources}",
                )
            )


def _check_rbac003_wildcard_resource(
    doc: dict,
    report: RbacAuditReport,
) -> None:
    """RBAC-003: Wildcard resource in Role or ClusterRole."""
    kind = _kind(doc)
    if kind not in ("Role", "ClusterRole"):
        return

    for rule in _rules(doc):
        resources = rule.get("resources", [])
        if "*" in resources:
            verbs = rule.get("verbs", ["<unknown>"])
            report.findings.append(
                RbacFinding(
                    rule_id="RBAC-003",
                    severity="high",
                    resource_kind=kind,
                    resource_name=_name(doc),
                    namespace=_namespace(doc),
                    message=(
                        f"{kind} '{_name(doc)}' grants {verbs} on wildcard "
                        "resource ('*'). This allows access to every resource "
                        "type in the target scope."
                    ),
                    remediation=(
                        "Enumerate the specific resource types the workload needs "
                        "and list them explicitly instead of using '*'."
                    ),
                    evidence=f"resources: ['*'] verbs: {verbs}",
                )
            )


def _check_rbac004_secrets_readable(
    doc: dict,
    report: RbacAuditReport,
) -> None:
    """RBAC-004: Secrets resource with read access (get/list/watch)."""
    kind = _kind(doc)
    if kind not in ("Role", "ClusterRole"):
        return

    _READ_VERBS = {"get", "list", "watch", "*"}
    for rule in _rules(doc):
        resources = rule.get("resources", [])
        if "secrets" in resources or "*" in resources:
            verbs = set(rule.get("verbs", []))
            if verbs & _READ_VERBS:
                report.findings.append(
                    RbacFinding(
                        rule_id="RBAC-004",
                        severity="high",
                        resource_kind=kind,
                        resource_name=_name(doc),
                        namespace=_namespace(doc),
                        message=(
                            f"{kind} '{_name(doc)}' grants read access to Secrets "
                            f"(verbs: {sorted(verbs & _READ_VERBS)}). Secrets contain "
                            "API keys, passwords, and TLS certificates. Broad secret "
                            "read access enables credential harvesting."
                        ),
                        remediation=(
                            "Restrict secret access to only the specific secrets the "
                            "workload needs using resourceNames, or eliminate it entirely "
                            "and use a secrets manager instead."
                        ),
                        evidence=f"resources: secrets, verbs: {sorted(verbs)}",
                    )
                )


def _check_rbac005_sa_automount(
    doc: dict,
    report: RbacAuditReport,
) -> None:
    """RBAC-005: ServiceAccount without automountServiceAccountToken: false."""
    if _kind(doc) != "ServiceAccount":
        return

    automount = doc.get("automountServiceAccountToken")
    if automount is not False:
        report.findings.append(
            RbacFinding(
                rule_id="RBAC-005",
                severity="medium",
                resource_kind="ServiceAccount",
                resource_name=_name(doc),
                namespace=_namespace(doc),
                message=(
                    f"ServiceAccount '{_name(doc)}' does not set "
                    "'automountServiceAccountToken: false'. "
                    "The token will be mounted into every pod using this SA, "
                    "providing API server access even when not needed."
                ),
                remediation=(
                    "Add 'automountServiceAccountToken: false' to the ServiceAccount. "
                    "For pods that genuinely need the token, set "
                    "'automountServiceAccountToken: true' explicitly on the Pod spec."
                ),
                evidence=f"automountServiceAccountToken: {automount!r}",
            )
        )


def _check_rbac006_node_write(
    doc: dict,
    report: RbacAuditReport,
) -> None:
    """RBAC-006: ClusterRole with write access to nodes."""
    if _kind(doc) != "ClusterRole":
        return

    _WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection", "*"}
    for rule in _rules(doc):
        resources = rule.get("resources", [])
        if "nodes" in resources or "*" in resources:
            verbs = set(rule.get("verbs", []))
            if verbs & _WRITE_VERBS:
                report.findings.append(
                    RbacFinding(
                        rule_id="RBAC-006",
                        severity="medium",
                        resource_kind="ClusterRole",
                        resource_name=_name(doc),
                        namespace=_namespace(doc),
                        message=(
                            f"ClusterRole '{_name(doc)}' has write access to nodes "
                            f"(verbs: {sorted(verbs & _WRITE_VERBS)}). "
                            "Node write access can be used to tamper with node configuration, "
                            "taint nodes, or trigger workload rescheduling."
                        ),
                        remediation=(
                            "Grant only the specific read operations needed (e.g. [get, list]) "
                            "and remove write verbs (create, update, patch, delete) on nodes. "
                            "Node management should be restricted to cluster infrastructure "
                            "components only."
                        ),
                        evidence=f"resources: nodes, verbs: {sorted(verbs)}",
                    )
                )


def _check_rbac007_missing_namespace(
    doc: dict,
    report: RbacAuditReport,
) -> None:
    """RBAC-007: RoleBinding without a namespace in metadata."""
    if _kind(doc) != "RoleBinding":
        return

    ns = _namespace(doc)
    if not ns:
        report.findings.append(
            RbacFinding(
                rule_id="RBAC-007",
                severity="low",
                resource_kind="RoleBinding",
                resource_name=_name(doc),
                namespace=None,
                message=(
                    f"RoleBinding '{_name(doc)}' has no namespace in its metadata. "
                    "RoleBindings are namespace-scoped; a missing namespace may cause "
                    "unexpected behavior or indicate a copy-paste error."
                ),
                remediation=(
                    "Add 'namespace: <target-namespace>' to the metadata block. "
                    "If cluster-wide access is intended, use ClusterRoleBinding instead."
                ),
                evidence="metadata.namespace: <missing>",
            )
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_CHECKS = [
    _check_rbac001_cluster_admin_binding,
    _check_rbac002_wildcard_verb,
    _check_rbac003_wildcard_resource,
    _check_rbac004_secrets_readable,
    _check_rbac005_sa_automount,
    _check_rbac006_node_write,
    _check_rbac007_missing_namespace,
]


def audit_rbac_file(path: Path) -> RbacAuditReport:
    """
    Audit a single YAML file containing Kubernetes RBAC resources.

    The file may contain multiple documents separated by '---'.  Each
    document is audited independently.

    Args:
        path:  Path to the YAML file to audit.

    Returns:
        RbacAuditReport containing all findings and warnings.
    """
    report = RbacAuditReport(file_paths=[path])
    docs, warnings = _load_all_docs(path)
    report.warnings.extend(warnings)
    report.resources_audited = len(docs)

    for doc in docs:
        for check in _CHECKS:
            check(doc, report)

    return report


def audit_rbac_directory(
    directory: Path,
    pattern: str = "**/*.yaml",
) -> RbacAuditReport:
    """
    Audit all YAML files matching pattern in a directory tree.

    Args:
        directory: Root directory to search.
        pattern:   Glob pattern relative to directory (default "**/*.yaml").

    Returns:
        Consolidated RbacAuditReport across all matched files.
    """
    combined = RbacAuditReport()
    for path in sorted(directory.glob(pattern)):
        file_report = audit_rbac_file(path)
        combined.file_paths.extend(file_report.file_paths)
        combined.findings.extend(file_report.findings)
        combined.warnings.extend(file_report.warnings)
        combined.resources_audited += file_report.resources_audited
    return combined
