# CC BY 4.0 — Creative Commons Attribution 4.0 International
# https://creativecommons.org/licenses/by/4.0/
# Cyber Port — Container Defense Stack
# Module: service_account_auditor.py
# Purpose: Analyze Kubernetes ServiceAccount configurations for security
#          misconfigurations that enable privilege escalation or lateral movement.

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

# ---------------------------------------------------------------------------
# Check weight registry
# Each entry maps a check ID to its integer weight used in risk_score.
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "SA-001": 45,  # CRITICAL — cluster-admin ClusterRoleBinding
    "SA-002": 15,  # MEDIUM   — automountServiceAccountToken not explicitly false
    "SA-003": 25,  # HIGH     — wildcard verbs in bound role
    "SA-004": 40,  # CRITICAL — ClusterRole grants secrets read across cluster
    "SA-005": 25,  # HIGH     — default SA bound to non-trivial role
    "SA-006": 15,  # MEDIUM   — imagePullSecrets present (registry creds exposed)
    "SA-007": 20,  # HIGH     — kube-system SA with non-system binding
}

# Severity labels keyed by check ID (used when constructing SAFinding objects)
_CHECK_SEVERITY: Dict[str, str] = {
    "SA-001": "CRITICAL",
    "SA-002": "MEDIUM",
    "SA-003": "HIGH",
    "SA-004": "CRITICAL",
    "SA-005": "HIGH",
    "SA-006": "MEDIUM",
    "SA-007": "HIGH",
}

# Human-readable titles for each check
_CHECK_TITLES: Dict[str, str] = {
    "SA-001": "ServiceAccount bound to cluster-admin ClusterRoleBinding",
    "SA-002": "automountServiceAccountToken not explicitly disabled",
    "SA-003": "Bound role contains wildcard verb (*) granting all API actions",
    "SA-004": "ClusterRole grants secrets read/list/get across entire cluster",
    "SA-005": "Default ServiceAccount bound to non-trivial role",
    "SA-006": "imagePullSecrets present — registry credentials exposed to pods",
    "SA-007": "kube-system ServiceAccount has non-system binding",
}

# Read-only roles that are acceptable when bound to the default ServiceAccount
_DEFAULT_SA_ALLOWED_ROLES = frozenset(
    {
        "view",
        "system:aggregate-to-view",
        "system:aggregate-to-edit",
    }
)

# Verbs that constitute "read" access for SA-004 secrets check
_SECRETS_READ_VERBS = frozenset({"get", "list", "watch"})
_SERVICE_ACCOUNT_KIND = "ServiceAccount"
_BINDING_KINDS = frozenset({"RoleBinding", "ClusterRoleBinding"})
_ROLE_KINDS = frozenset({"Role", "ClusterRole"})


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class SABinding:
    """Represents a resolved binding between a ServiceAccount and a role."""

    binding_name: str
    binding_kind: str   # "ClusterRoleBinding" or "RoleBinding"
    role_name: str
    role_kind: str      # "ClusterRole" or "Role"
    verbs: List[str]    # flattened from all rules of the referenced role
    resources: List[str]  # flattened from all rules of the referenced role


@dataclass
class SAFinding:
    """A single security finding produced by one check."""

    check_id: str
    severity: str   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int


@dataclass
class SAResult:
    """Aggregated audit result for one ServiceAccount."""

    sa_name: str
    namespace: str
    findings: List[SAFinding] = field(default_factory=list)
    risk_score: int = 0  # min(100, sum of weights for fired checks)

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dictionary representation."""
        return {
            "sa_name": self.sa_name,
            "namespace": self.namespace,
            "risk_score": self.risk_score,
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
        """Return a one-line human-readable summary string."""
        finding_count = len(self.findings)
        severity_parts = []
        grouped = self.by_severity()
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            items = grouped.get(sev, [])
            if items:
                severity_parts.append(f"{len(items)} {sev}")
        severity_str = ", ".join(severity_parts) if severity_parts else "none"
        return (
            f"{self.sa_name}/{self.namespace} — "
            f"risk_score={self.risk_score}, "
            f"findings={finding_count} ({severity_str})"
        )

    def by_severity(self) -> Dict[str, List[SAFinding]]:
        """Return findings grouped by severity label."""
        grouped: Dict[str, List[SAFinding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.severity, []).append(finding)
        return grouped


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_rules(role: dict) -> tuple:
    """Return (flat_verbs, flat_resources) extracted from a role manifest."""
    rules: List[dict] = role.get("rules") or []
    verbs: List[str] = []
    resources: List[str] = []
    for rule in rules:
        verbs.extend(rule.get("verbs") or [])
        resources.extend(rule.get("resources") or [])
    return verbs, resources


def _resolve_bindings(
    sa_name: str,
    namespace: str,
    bindings: List[dict],
    roles: List[dict],
) -> List[SABinding]:
    """
    Filter `bindings` to those whose subjects include the given SA,
    then look up the referenced role in `roles` to produce SABinding objects.
    """
    # Build a fast lookup: (kind, name) -> role dict
    role_index: Dict[tuple, dict] = {}
    for role in roles:
        kind = role.get("kind", "")
        name = (role.get("metadata") or {}).get("name", "")
        role_index[(kind, name)] = role

    resolved: List[SABinding] = []

    for binding in bindings:
        subjects: List[dict] = binding.get("subjects") or []
        # Determine if any subject matches the ServiceAccount
        matched = False
        for subject in subjects:
            if subject.get("kind") != "ServiceAccount":
                continue
            if subject.get("name") != sa_name:
                continue
            # For ClusterRoleBindings the subject namespace may be omitted
            # in some manifests; only enforce namespace match for RoleBindings.
            binding_kind = binding.get("kind", "")
            subj_ns = subject.get("namespace", "")
            if binding_kind == "RoleBinding" and subj_ns and subj_ns != namespace:
                continue
            matched = True
            break

        if not matched:
            continue

        role_ref: dict = binding.get("roleRef") or {}
        role_kind = role_ref.get("kind", "")
        role_name = role_ref.get("name", "")
        binding_name = (binding.get("metadata") or {}).get("name", "")
        binding_kind = binding.get("kind", "")

        # Look up the role — it may be absent from the provided list (e.g.
        # built-in roles not supplied by the caller). Verbs/resources will
        # be empty in that case, but the binding itself is still recorded.
        role_obj = role_index.get((role_kind, role_name), {})
        verbs, resources = _extract_rules(role_obj)

        resolved.append(
            SABinding(
                binding_name=binding_name,
                binding_kind=binding_kind,
                role_name=role_name,
                role_kind=role_kind,
                verbs=verbs,
                resources=resources,
            )
        )

    return resolved


def _make_finding(check_id: str, detail: str) -> SAFinding:
    """Construct an SAFinding for the given check ID with the provided detail."""
    return SAFinding(
        check_id=check_id,
        severity=_CHECK_SEVERITY[check_id],
        title=_CHECK_TITLES[check_id],
        detail=detail,
        weight=_CHECK_WEIGHTS[check_id],
    )


# ---------------------------------------------------------------------------
# Check implementations
# ---------------------------------------------------------------------------


def _check_sa001(sa_bindings: List[SABinding]) -> Optional[SAFinding]:
    """SA-001: bound to ClusterRoleBinding referencing cluster-admin."""
    for b in sa_bindings:
        if b.binding_kind == "ClusterRoleBinding" and b.role_name == "cluster-admin":
            return _make_finding(
                "SA-001",
                f"Binding '{b.binding_name}' grants cluster-admin across the cluster.",
            )
    return None


def _check_sa002(sa: dict) -> Optional[SAFinding]:
    """SA-002: automountServiceAccountToken is not explicitly set to false."""
    value = sa.get("automountServiceAccountToken")
    # None means unset (defaults to true in Kubernetes), True is explicit opt-in
    if value is not True and value is not False and value is not None:
        # Unexpected type — treat as unset (conservative)
        pass
    if value is False:
        return None
    # Both None (unset) and True trigger this finding
    state = "not set (defaults to true)" if value is None else "explicitly set to true"
    return _make_finding(
        "SA-002",
        f"automountServiceAccountToken is {state}; token will be mounted into pods "
        "and can be used for API server authentication.",
    )


def _check_sa003(sa_bindings: List[SABinding]) -> Optional[SAFinding]:
    """SA-003: any bound role has a rule with wildcard verbs."""
    for b in sa_bindings:
        if "*" in b.verbs:
            return _make_finding(
                "SA-003",
                f"Binding '{b.binding_name}' (role '{b.role_name}') contains a rule "
                "with verb '*', granting all API actions on matched resources.",
            )
    return None


def _check_sa004(sa_bindings: List[SABinding]) -> Optional[SAFinding]:
    """SA-004: ClusterRoleBinding role grants secrets get/list/watch."""
    for b in sa_bindings:
        if b.binding_kind != "ClusterRoleBinding":
            continue
        # Check that the role has at least one read verb AND secrets in resources
        has_read_verb = bool(_SECRETS_READ_VERBS.intersection(b.verbs)) or "*" in b.verbs
        has_secrets = "secrets" in b.resources or "*" in b.resources
        if has_read_verb and has_secrets:
            return _make_finding(
                "SA-004",
                f"Binding '{b.binding_name}' (ClusterRole '{b.role_name}') grants "
                "get/list/watch on 'secrets' cluster-wide, enabling credential harvesting.",
            )
    return None


def _check_sa005(
    sa: dict, sa_bindings: List[SABinding]
) -> Optional[SAFinding]:
    """SA-005: default SA is bound to a non-trivial role."""
    sa_name = (sa.get("metadata") or {}).get("name", "")
    if sa_name != "default":
        return None
    for b in sa_bindings:
        if b.role_name not in _DEFAULT_SA_ALLOWED_ROLES:
            return _make_finding(
                "SA-005",
                f"Default ServiceAccount is bound via '{b.binding_name}' to role "
                f"'{b.role_name}', which may grant unintended permissions to all pods "
                "that do not specify a dedicated ServiceAccount.",
            )
    return None


def _check_sa006(sa: dict) -> Optional[SAFinding]:
    """SA-006: imagePullSecrets are present."""
    pull_secrets = sa.get("imagePullSecrets")
    if pull_secrets:  # non-None and non-empty list
        names = [
            (s.get("name") or "") for s in pull_secrets if isinstance(s, dict)
        ]
        return _make_finding(
            "SA-006",
            f"imagePullSecrets present ({', '.join(names) if names else 'unnamed'}); "
            "registry credentials are accessible to all pods using this ServiceAccount.",
        )
    return None


def _check_sa007(
    sa: dict, sa_bindings: List[SABinding]
) -> Optional[SAFinding]:
    """SA-007: kube-system SA has a non-system binding."""
    namespace = (sa.get("metadata") or {}).get("namespace", "")
    if namespace != "kube-system":
        return None
    for b in sa_bindings:
        if not b.binding_name.startswith("system:"):
            return _make_finding(
                "SA-007",
                f"ServiceAccount in kube-system namespace is bound via "
                f"'{b.binding_name}', a non-system binding. Compromise of this SA "
                "can affect critical cluster components.",
            )
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze(
    sa: dict,
    bindings: Optional[List[dict]] = None,
    roles: Optional[List[dict]] = None,
) -> SAResult:
    """
    Analyze a single Kubernetes ServiceAccount manifest for security
    misconfigurations.

    Parameters
    ----------
    sa:
        ServiceAccount manifest dict with at minimum a ``metadata`` sub-dict
        containing ``name`` and ``namespace`` keys.
    bindings:
        Optional list of RoleBinding / ClusterRoleBinding manifest dicts that
        should be inspected.  Only bindings whose subjects include this SA
        are evaluated.
    roles:
        Optional list of Role / ClusterRole manifest dicts used to resolve
        the permissions granted by each matching binding.

    Returns
    -------
    SAResult
        Aggregated result including all fired findings and a capped risk score.
    """
    metadata: dict = sa.get("metadata") or {}
    sa_name: str = metadata.get("name", "")
    namespace: str = metadata.get("namespace", "")

    # Normalise optional arguments
    effective_bindings: List[dict] = bindings or []
    effective_roles: List[dict] = roles or []

    # Resolve bindings relevant to this ServiceAccount
    sa_bindings = _resolve_bindings(sa_name, namespace, effective_bindings, effective_roles)

    # Run all checks
    checks = [
        _check_sa001(sa_bindings),
        _check_sa002(sa),
        _check_sa003(sa_bindings),
        _check_sa004(sa_bindings),
        _check_sa005(sa, sa_bindings),
        _check_sa006(sa),
        _check_sa007(sa, sa_bindings),
    ]

    # Collect fired findings
    findings: List[SAFinding] = [c for c in checks if c is not None]

    # Compute capped risk score
    risk_score: int = min(100, sum(f.weight for f in findings))

    return SAResult(
        sa_name=sa_name,
        namespace=namespace,
        findings=findings,
        risk_score=risk_score,
    )


def analyze_many(
    service_accounts: List[dict],
    bindings: Optional[List[dict]] = None,
    roles: Optional[List[dict]] = None,
) -> List[SAResult]:
    """
    Analyze a list of ServiceAccount manifests in bulk.

    Parameters
    ----------
    service_accounts:
        Iterable of ServiceAccount manifest dicts.
    bindings:
        Shared list of binding manifests applied to all SA analyses.
    roles:
        Shared list of role manifests applied to all SA analyses.

    Returns
    -------
    List[SAResult]
        One SAResult per input ServiceAccount, in the same order.
    """
    return [analyze(sa, bindings=bindings, roles=roles) for sa in service_accounts]


def load_audit_inputs_from_manifests(manifests: List[dict]) -> tuple[List[dict], List[dict], List[dict]]:
    """Split Kubernetes manifests into ServiceAccount, binding, and role lists."""
    service_accounts: List[dict] = []
    bindings: List[dict] = []
    roles: List[dict] = []

    for manifest in manifests:
        if not isinstance(manifest, dict):
            continue

        kind = str(manifest.get("kind", ""))
        if kind == _SERVICE_ACCOUNT_KIND:
            service_accounts.append(manifest)
        elif kind in _BINDING_KINDS:
            bindings.append(manifest)
        elif kind in _ROLE_KINDS:
            roles.append(manifest)

    return service_accounts, bindings, roles


def load_audit_inputs_from_file(path: Path) -> tuple[List[dict], List[dict], List[dict]]:
    """Load ServiceAccount audit inputs from a multi-document Kubernetes YAML file."""
    with path.open("r", encoding="utf-8") as handle:
        manifests = [doc for doc in yaml.safe_load_all(handle) if isinstance(doc, dict)]
    return load_audit_inputs_from_manifests(manifests)
