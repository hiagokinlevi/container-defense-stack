# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International License.
# https://creativecommons.org/licenses/by/4.0/
"""
Kubernetes RBAC Privilege Gap Analyzer
=======================================
Analyzes Kubernetes RBAC objects (Roles, ClusterRoles, RoleBindings,
ClusterRoleBindings) for privilege escalation paths, over-permissive rules,
and common misconfigurations.

Operates entirely offline on Python dicts — no live cluster API calls required.

Check IDs
----------
RBAC-GAP-001  Binding to cluster-admin ClusterRole              (CRITICAL, w=40)
RBAC-GAP-002  Wildcard verbs in role rules                      (HIGH,     w=25)
RBAC-GAP-003  Wildcard resources in role rules                  (HIGH,     w=25)
RBAC-GAP-004  Secrets read access (get/list/watch on secrets)   (HIGH,     w=20)
RBAC-GAP-005  Default service account with bindings             (MEDIUM,   w=15)
RBAC-GAP-006  Privilege escalation verbs (bind/escalate/imp.)   (CRITICAL, w=35)
RBAC-GAP-007  system:masters group binding                      (CRITICAL, w=40)

Usage::

    from kubernetes.rbac_gap_analyzer import (
        RBACGapAnalyzer, RBACRole, RBACBinding, PolicyRule
    )

    role = RBACRole(
        name="dangerous-role",
        namespace="default",
        rules=[PolicyRule(api_groups=["*"], resources=["secrets"], verbs=["get", "list"])],
    )
    binding = RBACBinding(
        name="dangerous-binding",
        namespace="default",
        role_ref_name="dangerous-role",
        role_ref_kind="Role",
        subjects=[{"kind": "ServiceAccount", "name": "default", "namespace": "default"}],
    )
    analyzer = RBACGapAnalyzer()
    result = analyzer.analyze([role], [binding])
    print(result.summary())
    for finding in result.findings:
        print(finding.to_dict())
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Weight table — each check ID maps to its integer contribution to risk_score.
# risk_score = min(100, sum of weights for each *unique* fired check ID).
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "RBAC-GAP-001": 40,  # cluster-admin binding
    "RBAC-GAP-002": 25,  # wildcard verbs
    "RBAC-GAP-003": 25,  # wildcard resources
    "RBAC-GAP-004": 20,  # secrets read access
    "RBAC-GAP-005": 15,  # default service account bound
    "RBAC-GAP-006": 35,  # privilege escalation verbs
    "RBAC-GAP-007": 40,  # system:masters group binding
}

# Verbs that enable privilege escalation at the Kubernetes RBAC layer.
_ESCALATION_VERBS = {"bind", "escalate", "impersonate"}

# Read-like verbs that expose secret material when combined with the secrets resource.
_READ_VERBS = {"get", "list", "watch", "*"}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PolicyRule:
    """
    A single Kubernetes RBAC policy rule.

    Attributes:
        api_groups:      API groups the rule applies to, e.g. ["*"] or [""].
        resources:       Resource types, e.g. ["*"] or ["secrets", "pods"].
        verbs:           Allowed verbs, e.g. ["*"] or ["get", "list"].
        resource_names:  Optional list restricting scope to named resources.
    """
    api_groups:     List[str]
    resources:      List[str]
    verbs:          List[str]
    resource_names: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        d: Dict[str, Any] = {
            "api_groups": self.api_groups,
            "resources":  self.resources,
            "verbs":      self.verbs,
        }
        if self.resource_names is not None:
            d["resource_names"] = self.resource_names
        return d


@dataclass
class RBACRole:
    """
    Represents a Kubernetes Role or ClusterRole.

    A Role has a namespace; a ClusterRole has namespace=None and
    is_cluster_role=True (computed automatically from the namespace value).

    Attributes:
        name:            Role name.
        namespace:       Namespace for namespaced Roles; None for ClusterRoles.
        rules:           List of PolicyRule objects that compose this role.
        is_cluster_role: True when namespace is None (computed property).
    """
    name:      str
    namespace: Optional[str]
    rules:     List[PolicyRule] = field(default_factory=list)

    @property
    def is_cluster_role(self) -> bool:
        """True if this role is a ClusterRole (no namespace)."""
        return self.namespace is None

    @property
    def kind(self) -> str:
        """Kubernetes kind string: 'ClusterRole' or 'Role'."""
        return "ClusterRole" if self.is_cluster_role else "Role"

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "name":            self.name,
            "namespace":       self.namespace,
            "is_cluster_role": self.is_cluster_role,
            "rules":           [r.to_dict() for r in self.rules],
        }


@dataclass
class RBACBinding:
    """
    Represents a Kubernetes RoleBinding or ClusterRoleBinding.

    A RoleBinding has a namespace; a ClusterRoleBinding has namespace=None.

    Attributes:
        name:           Binding name.
        namespace:      Namespace for RoleBindings; None for ClusterRoleBindings.
        role_ref_name:  Name of the bound Role or ClusterRole.
        role_ref_kind:  "Role" or "ClusterRole".
        subjects:       List of subject dicts, each with keys:
                        kind (User/Group/ServiceAccount), name,
                        and optionally namespace.
    """
    name:           str
    namespace:      Optional[str]
    role_ref_name:  str
    role_ref_kind:  str
    subjects:       List[Dict[str, Any]] = field(default_factory=list)

    @property
    def is_cluster_binding(self) -> bool:
        """True if this is a ClusterRoleBinding (no namespace)."""
        return self.namespace is None

    @property
    def kind(self) -> str:
        """Kubernetes kind string: 'ClusterRoleBinding' or 'RoleBinding'."""
        return "ClusterRoleBinding" if self.is_cluster_binding else "RoleBinding"

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "name":           self.name,
            "namespace":      self.namespace,
            "role_ref_name":  self.role_ref_name,
            "role_ref_kind":  self.role_ref_kind,
            "subjects":       list(self.subjects),
        }


@dataclass
class RBACFinding:
    """
    A single RBAC privilege-gap finding.

    Attributes:
        check_id:        RBAC-GAP-XXX identifier.
        severity:        "CRITICAL", "HIGH", or "MEDIUM".
        resource_name:   Name of the offending Role/Binding.
        resource_kind:   "Role", "ClusterRole", "RoleBinding", or
                         "ClusterRoleBinding".
        namespace:       Namespace of the resource; None for cluster-scoped.
        message:         Human-readable description of the gap.
        recommendation:  Actionable remediation guidance.
    """
    check_id:       str
    severity:       str
    resource_name:  str
    resource_kind:  str
    namespace:      Optional[str]
    message:        str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "check_id":       self.check_id,
            "severity":       self.severity,
            "resource_name":  self.resource_name,
            "resource_kind":  self.resource_kind,
            "namespace":      self.namespace,
            "message":        self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class RBACGapResult:
    """
    Aggregated result of a single RBAC gap analysis run.

    Attributes:
        findings:    All RBACFinding objects produced by the analysis.
        risk_score:  Integer 0–100 computed from unique fired check IDs.
    """
    findings:   List[RBACFinding] = field(default_factory=list)
    risk_score: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """
        Return a one-line human-readable summary.

        Example::
            "RBAC Gap Analysis: 3 finding(s) | Risk Score: 65/100 | CRITICAL: 1, HIGH: 2, MEDIUM: 0"
        """
        by_sev = self.by_severity()
        parts = ", ".join(
            f"{sev}: {len(findings)}"
            for sev, findings in sorted(by_sev.items())
        )
        total = len(self.findings)
        return (
            f"RBAC Gap Analysis: {total} finding(s) | "
            f"Risk Score: {self.risk_score}/100 | {parts}"
        )

    def by_severity(self) -> Dict[str, List[RBACFinding]]:
        """
        Return findings grouped by severity string.

        Returns a dict where keys are severity labels present in findings;
        an empty analysis returns an empty dict.
        """
        result: Dict[str, List[RBACFinding]] = {}
        for finding in self.findings:
            result.setdefault(finding.severity, []).append(finding)
        return result

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "risk_score": self.risk_score,
            "findings":   [f.to_dict() for f in self.findings],
            "summary":    self.summary(),
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class RBACGapAnalyzer:
    """
    Offline Kubernetes RBAC privilege gap analyzer.

    Instantiate once and call :meth:`analyze` (or :meth:`analyze_many`) to
    evaluate one or more sets of Roles + Bindings.  No Kubernetes API
    connectivity is required.
    """

    # Individual check helpers — each returns a (possibly empty) list of
    # RBACFinding objects.  They are called in order by :meth:`_run_checks`.

    # ------------------------------------------------------------------
    # RBAC-GAP-001: Binding to cluster-admin ClusterRole
    # ------------------------------------------------------------------

    def _check_001(self, bindings: List[RBACBinding]) -> List[RBACFinding]:
        """
        Flag any binding that references the built-in cluster-admin ClusterRole.
        cluster-admin grants unrestricted access to the entire cluster.
        """
        findings: List[RBACFinding] = []
        for binding in bindings:
            if (
                binding.role_ref_name == "cluster-admin"
                and binding.role_ref_kind == "ClusterRole"
            ):
                findings.append(RBACFinding(
                    check_id="RBAC-GAP-001",
                    severity="CRITICAL",
                    resource_name=binding.name,
                    resource_kind=binding.kind,
                    namespace=binding.namespace,
                    message=(
                        f"{binding.kind} '{binding.name}' binds to the built-in "
                        "cluster-admin ClusterRole, granting unrestricted cluster-wide "
                        "access to all bound subjects."
                    ),
                    recommendation=(
                        "Remove or replace this binding with one referencing a "
                        "least-privilege custom ClusterRole scoped to the minimum "
                        "required permissions."
                    ),
                ))
        return findings

    # ------------------------------------------------------------------
    # RBAC-GAP-002: Wildcard verbs in rules
    # ------------------------------------------------------------------

    def _check_002(self, roles: List[RBACRole]) -> List[RBACFinding]:
        """
        Flag roles that allow all verbs ("*") in at least one rule.
        One finding is emitted per affected role (deduplicated by role name).
        """
        findings: List[RBACFinding] = []
        seen: set = set()  # deduplicate by role name
        for role in roles:
            if role.name in seen:
                continue
            for rule in role.rules:
                if "*" in rule.verbs:
                    seen.add(role.name)
                    findings.append(RBACFinding(
                        check_id="RBAC-GAP-002",
                        severity="HIGH",
                        resource_name=role.name,
                        resource_kind=role.kind,
                        namespace=role.namespace,
                        message=(
                            f"{role.kind} '{role.name}' contains a rule with wildcard "
                            "verbs (\"*\"), permitting every HTTP verb on the targeted "
                            "resources."
                        ),
                        recommendation=(
                            "Replace wildcard verbs with an explicit allowlist of "
                            "only the verbs required by the workload (e.g., "
                            "[\"get\", \"list\"])."
                        ),
                    ))
                    break  # one finding per role
        return findings

    # ------------------------------------------------------------------
    # RBAC-GAP-003: Wildcard resources in rules
    # ------------------------------------------------------------------

    def _check_003(self, roles: List[RBACRole]) -> List[RBACFinding]:
        """
        Flag roles that target all resources ("*") in at least one rule.
        One finding is emitted per affected role (deduplicated by role name).
        """
        findings: List[RBACFinding] = []
        seen: set = set()
        for role in roles:
            if role.name in seen:
                continue
            for rule in role.rules:
                if "*" in rule.resources:
                    seen.add(role.name)
                    findings.append(RBACFinding(
                        check_id="RBAC-GAP-003",
                        severity="HIGH",
                        resource_name=role.name,
                        resource_kind=role.kind,
                        namespace=role.namespace,
                        message=(
                            f"{role.kind} '{role.name}' contains a rule with wildcard "
                            "resources (\"*\"), granting access to every resource type "
                            "in the targeted API groups."
                        ),
                        recommendation=(
                            "Replace wildcard resources with an explicit allowlist of "
                            "only the resource types required by the workload."
                        ),
                    ))
                    break
        return findings

    # ------------------------------------------------------------------
    # RBAC-GAP-004: Secrets read access
    # ------------------------------------------------------------------

    def _check_004(self, roles: List[RBACRole]) -> List[RBACFinding]:
        """
        Flag roles that allow reading secrets (get/list/watch on the
        'secrets' resource or via wildcard resources/verbs).
        One finding is emitted per affected role.
        """
        findings: List[RBACFinding] = []
        seen: set = set()
        for role in roles:
            if role.name in seen:
                continue
            for rule in role.rules:
                # Resource must cover secrets explicitly or via wildcard
                covers_secrets = (
                    "secrets" in rule.resources or "*" in rule.resources
                )
                # Verbs must include at least one read-like verb
                covers_read = bool(_READ_VERBS.intersection(set(rule.verbs)))
                if covers_secrets and covers_read:
                    seen.add(role.name)
                    findings.append(RBACFinding(
                        check_id="RBAC-GAP-004",
                        severity="HIGH",
                        resource_name=role.name,
                        resource_kind=role.kind,
                        namespace=role.namespace,
                        message=(
                            f"{role.kind} '{role.name}' grants read access (get/list/"
                            "watch) to Secrets, which may expose credentials, tokens, "
                            "or TLS private keys."
                        ),
                        recommendation=(
                            "Restrict access to Secrets to only the specific named "
                            "resources required, or remove Secret access entirely. "
                            "Use resourceNames to limit scope where possible."
                        ),
                    ))
                    break
        return findings

    # ------------------------------------------------------------------
    # RBAC-GAP-005: Default service account with bindings
    # ------------------------------------------------------------------

    def _check_005(self, bindings: List[RBACBinding]) -> List[RBACFinding]:
        """
        Flag bindings that include the 'default' ServiceAccount as a subject.
        The default SA is automatically mounted into all pods in the namespace,
        so granting it any RBAC permission is high-risk.
        """
        findings: List[RBACFinding] = []
        for binding in bindings:
            for subject in binding.subjects:
                if (
                    subject.get("kind") == "ServiceAccount"
                    and subject.get("name") == "default"
                ):
                    findings.append(RBACFinding(
                        check_id="RBAC-GAP-005",
                        severity="MEDIUM",
                        resource_name=binding.name,
                        resource_kind=binding.kind,
                        namespace=binding.namespace,
                        message=(
                            f"{binding.kind} '{binding.name}' binds the 'default' "
                            "ServiceAccount, which is auto-mounted into every Pod in "
                            "the namespace, inadvertently granting those Pods elevated "
                            "RBAC permissions."
                        ),
                        recommendation=(
                            "Create a dedicated ServiceAccount for each workload with "
                            "only the required permissions. Set "
                            "automountServiceAccountToken: false on the default SA."
                        ),
                    ))
                    break  # one finding per binding
        return findings

    # ------------------------------------------------------------------
    # RBAC-GAP-006: Privilege escalation verbs
    # ------------------------------------------------------------------

    def _check_006(self, roles: List[RBACRole]) -> List[RBACFinding]:
        """
        Flag roles that grant the 'bind', 'escalate', or 'impersonate' verbs.
        These verbs allow a subject to gain permissions beyond their own,
        effectively bypassing RBAC controls.
        """
        findings: List[RBACFinding] = []
        seen: set = set()
        for role in roles:
            if role.name in seen:
                continue
            for rule in role.rules:
                found_escalation = _ESCALATION_VERBS.intersection(set(rule.verbs))
                if found_escalation:
                    seen.add(role.name)
                    verbs_str = ", ".join(sorted(found_escalation))
                    findings.append(RBACFinding(
                        check_id="RBAC-GAP-006",
                        severity="CRITICAL",
                        resource_name=role.name,
                        resource_kind=role.kind,
                        namespace=role.namespace,
                        message=(
                            f"{role.kind} '{role.name}' grants privilege escalation "
                            f"verb(s): [{verbs_str}]. These allow subjects to gain "
                            "higher cluster privileges than they currently hold."
                        ),
                        recommendation=(
                            "Remove escalation verbs unless absolutely required. "
                            "If impersonation is needed (e.g., for admission webhooks), "
                            "tightly scope it with resourceNames."
                        ),
                    ))
                    break
        return findings

    # ------------------------------------------------------------------
    # RBAC-GAP-007: system:masters group binding
    # ------------------------------------------------------------------

    def _check_007(self, bindings: List[RBACBinding]) -> List[RBACFinding]:
        """
        Flag bindings that include the 'system:masters' Group.
        Members of this group bypass RBAC entirely; the API server grants them
        unrestricted access even when RBAC policies would deny them.
        """
        findings: List[RBACFinding] = []
        for binding in bindings:
            for subject in binding.subjects:
                if (
                    subject.get("kind") == "Group"
                    and subject.get("name") == "system:masters"
                ):
                    findings.append(RBACFinding(
                        check_id="RBAC-GAP-007",
                        severity="CRITICAL",
                        resource_name=binding.name,
                        resource_kind=binding.kind,
                        namespace=binding.namespace,
                        message=(
                            f"{binding.kind} '{binding.name}' includes the "
                            "'system:masters' Group, which bypasses all RBAC policies "
                            "and grants unrestricted cluster-admin level access."
                        ),
                        recommendation=(
                            "Remove 'system:masters' from all RBAC bindings. "
                            "No workload or user should be a member of this group "
                            "in production clusters."
                        ),
                    ))
                    break
        return findings

    # ------------------------------------------------------------------
    # Core analysis engine
    # ------------------------------------------------------------------

    def _compute_risk_score(self, findings: List[RBACFinding]) -> int:
        """
        Compute risk_score = min(100, sum of weights for each unique fired
        check ID).  Each check ID contributes its weight at most once,
        regardless of how many individual findings it produced.
        """
        fired_ids = {f.check_id for f in findings}
        total = sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_ids)
        return min(100, total)

    def analyze(
        self,
        roles: List[RBACRole],
        bindings: List[RBACBinding],
    ) -> RBACGapResult:
        """
        Run all RBAC gap checks against the supplied roles and bindings.

        Parameters
        ----------
        roles:
            List of :class:`RBACRole` objects (Roles and/or ClusterRoles).
        bindings:
            List of :class:`RBACBinding` objects (RoleBindings and/or
            ClusterRoleBindings).

        Returns
        -------
        RBACGapResult
            Aggregated result containing all findings and a risk score.
        """
        all_findings: List[RBACFinding] = []

        # Role-based checks
        all_findings.extend(self._check_002(roles))
        all_findings.extend(self._check_003(roles))
        all_findings.extend(self._check_004(roles))
        all_findings.extend(self._check_006(roles))

        # Binding-based checks
        all_findings.extend(self._check_001(bindings))
        all_findings.extend(self._check_005(bindings))
        all_findings.extend(self._check_007(bindings))

        risk_score = self._compute_risk_score(all_findings)
        return RBACGapResult(findings=all_findings, risk_score=risk_score)

    def analyze_many(
        self,
        role_sets: List[Tuple[List[RBACRole], List[RBACBinding]]],
    ) -> List[RBACGapResult]:
        """
        Run :meth:`analyze` on multiple (roles, bindings) pairs.

        Parameters
        ----------
        role_sets:
            A list of (roles, bindings) tuples, one per logical namespace or
            analysis unit.

        Returns
        -------
        List[RBACGapResult]
            One result per input tuple, in the same order.
        """
        return [self.analyze(roles, bindings) for roles, bindings in role_sets]
