# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International License.
# https://creativecommons.org/licenses/by/4.0/
"""
Kubernetes Admission Webhook / Policy Security Analyzer
========================================================
Analyzes Kubernetes admission webhook configuration dicts for security
misconfigurations, overly-permissive failure policies, missing TLS
verification, and coverage gaps on critical resources.

Operates entirely offline on Python dicts — no live cluster API calls required.

Check IDs
----------
ADMS-001  Webhook fails open (failurePolicy=Ignore)              (CRITICAL, w=40)
ADMS-002  Applies to all namespaces incl. system namespaces      (HIGH,     w=25)
ADMS-003  Mutating webhook with no timeout                       (MEDIUM,   w=15)
ADMS-004  TLS insecure skip verify                               (HIGH,     w=25)
ADMS-005  No webhook covers critical resources (pods CREATE)     (HIGH,     w=25)
ADMS-006  Missing CA bundle — TLS cannot be verified             (HIGH,     w=20)
ADMS-007  Webhook side effects not None/NoneOnDryRun             (MEDIUM,   w=10)

Usage::

    from kubernetes.admission_policy_analyzer import (
        AdmissionPolicyAnalyzer, AdmissionWebhook, WebhookRule
    )

    hook = AdmissionWebhook(
        name="my-validating-webhook",
        webhook_type="Validating",
        failure_policy="Fail",
        namespace_selector={"matchLabels": {"admission": "enabled"}},
        timeout_seconds=10,
        ca_bundle="LS0tLS1CRUdJTi...",
        service_name="webhook-svc",
        tls_insecure_skip_verify=False,
        rules=[
            WebhookRule(
                api_groups=[""],
                api_versions=["v1"],
                resources=["pods"],
                operations=["CREATE"],
            )
        ],
        side_effects="None",
    )

    result = AdmissionPolicyAnalyzer().analyze([hook])
    print(result.summary())
    print(result.risk_score)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Check weight registry
# key   = check ID
# value = weight added to the risk score when that check fires
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "ADMS-001": 40,  # fails open — critical
    "ADMS-002": 25,  # no namespace selector — high
    "ADMS-003": 15,  # mutating, no timeout — medium
    "ADMS-004": 25,  # TLS insecure skip verify — high
    "ADMS-005": 25,  # no coverage of critical resources — high
    "ADMS-006": 20,  # missing CA bundle — high
    "ADMS-007": 10,  # non-None side effects — medium
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class WebhookRule:
    """Describes which API groups, versions, resources, and operations a
    webhook intercepts."""

    api_groups: List[str]   # e.g. ["*"] or ["apps", ""]
    api_versions: List[str]  # e.g. ["*"] or ["v1"]
    resources: List[str]    # e.g. ["pods", "deployments", "*"]
    operations: List[str]   # e.g. ["CREATE", "UPDATE", "*"]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "api_groups": self.api_groups,
            "api_versions": self.api_versions,
            "resources": self.resources,
            "operations": self.operations,
        }


@dataclass
class AdmissionWebhook:
    """Represents a single Kubernetes admission webhook configuration entry."""

    name: str
    webhook_type: str                          # "Mutating" or "Validating"
    failure_policy: str                        # "Fail" or "Ignore"
    namespace_selector: Optional[dict]         # None → no selector (applies everywhere)
    timeout_seconds: Optional[int]             # None → not set
    ca_bundle: Optional[str]                   # PEM CA cert; None → not set
    service_name: Optional[str]                # in-cluster service name; None if external
    tls_insecure_skip_verify: bool             # default False
    rules: List[WebhookRule]                   # resource/operation coverage rules
    side_effects: str = "None"                 # "None" | "NoneOnDryRun" | "Some" | "Unknown"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "name": self.name,
            "webhook_type": self.webhook_type,
            "failure_policy": self.failure_policy,
            "namespace_selector": self.namespace_selector,
            "timeout_seconds": self.timeout_seconds,
            "ca_bundle": self.ca_bundle,
            "service_name": self.service_name,
            "tls_insecure_skip_verify": self.tls_insecure_skip_verify,
            "rules": [r.to_dict() for r in self.rules],
            "side_effects": self.side_effects,
        }


@dataclass
class AdmissionFinding:
    """A single security finding produced by the analyzer."""

    check_id: str           # e.g. "ADMS-001"
    severity: str           # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    webhook_name: str       # name of the offending webhook, or "" for global checks
    webhook_type: str       # "Mutating" | "Validating" | "" for global checks
    message: str            # human-readable description of the issue
    recommendation: str     # actionable remediation advice

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "webhook_name": self.webhook_name,
            "webhook_type": self.webhook_type,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class AdmissionPolicyResult:
    """Aggregated result of analyzing one set of admission webhooks."""

    findings: List[AdmissionFinding] = field(default_factory=list)
    risk_score: int = 0  # 0–100

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a one-line human-readable summary of the analysis."""
        total = len(self.findings)
        sev_counts = self.by_severity()
        critical = sev_counts.get("CRITICAL", 0)
        high = sev_counts.get("HIGH", 0)
        medium = sev_counts.get("MEDIUM", 0)
        low = sev_counts.get("LOW", 0)
        return (
            f"AdmissionPolicyResult: {total} finding(s) "
            f"[CRITICAL={critical} HIGH={high} MEDIUM={medium} LOW={low}] "
            f"risk_score={self.risk_score}/100"
        )

    def by_severity(self) -> Dict[str, List[AdmissionFinding]]:
        """Return findings grouped by severity label."""
        groups: Dict[str, List[AdmissionFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "summary": self.summary(),
            "by_severity": {
                sev: [f.to_dict() for f in findings]
                for sev, findings in self.by_severity().items()
            },
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class AdmissionPolicyAnalyzer:
    """
    Stateless analyzer that inspects a list of :class:`AdmissionWebhook`
    objects and returns an :class:`AdmissionPolicyResult`.

    All checks operate entirely on the provided data — no network or cluster
    access is performed.
    """

    # Severity mapping per check ID (used when building findings)
    _SEVERITY: Dict[str, str] = {
        "ADMS-001": "CRITICAL",
        "ADMS-002": "HIGH",
        "ADMS-003": "MEDIUM",
        "ADMS-004": "HIGH",
        "ADMS-005": "HIGH",
        "ADMS-006": "HIGH",
        "ADMS-007": "MEDIUM",
    }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, webhooks: List[AdmissionWebhook]) -> AdmissionPolicyResult:
        """
        Analyze a list of admission webhooks and return a consolidated result.

        Parameters
        ----------
        webhooks:
            List of :class:`AdmissionWebhook` objects to evaluate.

        Returns
        -------
        :class:`AdmissionPolicyResult` with all findings and a risk score.
        """
        findings: List[AdmissionFinding] = []

        # Per-webhook checks (ADMS-001 through ADMS-004, ADMS-006, ADMS-007)
        for hook in webhooks:
            findings.extend(self._check_adms001(hook))
            findings.extend(self._check_adms002(hook))
            findings.extend(self._check_adms003(hook))
            findings.extend(self._check_adms004(hook))
            findings.extend(self._check_adms006(hook))
            findings.extend(self._check_adms007(hook))

        # Global / cross-webhook check (ADMS-005)
        findings.extend(self._check_adms005(webhooks))

        # Compute risk score: sum weights for unique fired check IDs, cap at 100
        fired_ids = {f.check_id for f in findings}
        raw_score = sum(_CHECK_WEIGHTS[cid] for cid in fired_ids if cid in _CHECK_WEIGHTS)
        risk_score = min(100, raw_score)

        return AdmissionPolicyResult(findings=findings, risk_score=risk_score)

    def analyze_many(
        self,
        webhook_groups: List[List[AdmissionWebhook]],
    ) -> List[AdmissionPolicyResult]:
        """
        Analyze multiple independent sets of admission webhooks.

        Parameters
        ----------
        webhook_groups:
            Each element is a list of webhooks belonging to one logical group
            (e.g. one cluster or one namespace context).

        Returns
        -------
        A list of :class:`AdmissionPolicyResult`, one per group.
        """
        return [self.analyze(group) for group in webhook_groups]

    # ------------------------------------------------------------------
    # Per-webhook checks
    # ------------------------------------------------------------------

    def _check_adms001(self, hook: AdmissionWebhook) -> List[AdmissionFinding]:
        """ADMS-001 — Webhook fails open (failurePolicy=Ignore)."""
        if hook.failure_policy != "Ignore":
            return []
        return [
            AdmissionFinding(
                check_id="ADMS-001",
                severity=self._SEVERITY["ADMS-001"],
                webhook_name=hook.name,
                webhook_type=hook.webhook_type,
                message=(
                    f"Webhook '{hook.name}' has failurePolicy=Ignore. "
                    "If the webhook endpoint is unreachable or errors, the "
                    "admission request will be silently allowed through."
                ),
                recommendation=(
                    "Set failurePolicy=Fail for security-critical webhooks so "
                    "that a backend failure causes the request to be denied "
                    "rather than permitted. Only use Ignore for non-critical, "
                    "advisory webhooks after explicit risk acceptance."
                ),
            )
        ]

    def _check_adms002(self, hook: AdmissionWebhook) -> List[AdmissionFinding]:
        """ADMS-002 — Webhook applies to all namespaces including system namespaces."""
        # None or empty dict both mean "no selector" → applies everywhere
        selector = hook.namespace_selector
        if selector is not None and selector != {}:
            return []
        return [
            AdmissionFinding(
                check_id="ADMS-002",
                severity=self._SEVERITY["ADMS-002"],
                webhook_name=hook.name,
                webhook_type=hook.webhook_type,
                message=(
                    f"Webhook '{hook.name}' has no namespaceSelector (or an "
                    "empty selector), so it applies to every namespace including "
                    "kube-system, kube-public, and other system namespaces. "
                    "A misconfigured or unavailable webhook can disrupt "
                    "control-plane operations."
                ),
                recommendation=(
                    "Add a namespaceSelector that excludes system namespaces "
                    "(e.g. matchExpressions excluding 'kube-system' and "
                    "'kube-public'), or use a label-based opt-in model so only "
                    "explicitly labelled namespaces are covered."
                ),
            )
        ]

    def _check_adms003(self, hook: AdmissionWebhook) -> List[AdmissionFinding]:
        """ADMS-003 — Mutating webhook with no timeout set."""
        if hook.webhook_type != "Mutating":
            return []
        if hook.timeout_seconds is not None:
            return []
        return [
            AdmissionFinding(
                check_id="ADMS-003",
                severity=self._SEVERITY["ADMS-003"],
                webhook_name=hook.name,
                webhook_type=hook.webhook_type,
                message=(
                    f"Mutating webhook '{hook.name}' has no timeoutSeconds "
                    "configured. Without an explicit timeout the API server "
                    "may wait indefinitely, causing admission request hangs "
                    "and potential cluster instability."
                ),
                recommendation=(
                    "Set timeoutSeconds to a reasonable value (e.g. 10–30 "
                    "seconds). Combine with failurePolicy=Fail and a robust "
                    "webhook backend to ensure predictable behavior under load "
                    "or degraded conditions."
                ),
            )
        ]

    def _check_adms004(self, hook: AdmissionWebhook) -> List[AdmissionFinding]:
        """ADMS-004 — Webhook with TLS insecure skip verify enabled."""
        if not hook.tls_insecure_skip_verify:
            return []
        return [
            AdmissionFinding(
                check_id="ADMS-004",
                severity=self._SEVERITY["ADMS-004"],
                webhook_name=hook.name,
                webhook_type=hook.webhook_type,
                message=(
                    f"Webhook '{hook.name}' has tlsInsecureSkipVerify=true. "
                    "The API server will not verify the webhook server's TLS "
                    "certificate, making it vulnerable to man-in-the-middle "
                    "attacks."
                ),
                recommendation=(
                    "Disable tlsInsecureSkipVerify and configure a valid "
                    "caBundle so the API server can cryptographically verify "
                    "the webhook backend's identity. Use a private CA or "
                    "cert-manager to issue and rotate certificates."
                ),
            )
        ]

    def _check_adms006(self, hook: AdmissionWebhook) -> List[AdmissionFinding]:
        """ADMS-006 — Webhook missing CA bundle."""
        # Fire when ca_bundle is None or empty string
        if hook.ca_bundle is not None and hook.ca_bundle != "":
            return []
        return [
            AdmissionFinding(
                check_id="ADMS-006",
                severity=self._SEVERITY["ADMS-006"],
                webhook_name=hook.name,
                webhook_type=hook.webhook_type,
                message=(
                    f"Webhook '{hook.name}' does not have a caBundle configured. "
                    "Without a CA bundle the API server cannot verify the TLS "
                    "certificate presented by the webhook backend, leaving the "
                    "connection open to interception."
                ),
                recommendation=(
                    "Populate caBundle with the PEM-encoded CA certificate that "
                    "signed the webhook server's TLS certificate. Use cert-manager "
                    "or a Kubernetes Secret-backed CA workflow to automate "
                    "certificate rotation."
                ),
            )
        ]

    def _check_adms007(self, hook: AdmissionWebhook) -> List[AdmissionFinding]:
        """ADMS-007 — Webhook side effects not None or NoneOnDryRun."""
        safe_side_effects = {"None", "NoneOnDryRun"}
        if hook.side_effects in safe_side_effects:
            return []
        return [
            AdmissionFinding(
                check_id="ADMS-007",
                severity=self._SEVERITY["ADMS-007"],
                webhook_name=hook.name,
                webhook_type=hook.webhook_type,
                message=(
                    f"Webhook '{hook.name}' declares sideEffects='{hook.side_effects}'. "
                    "Side effects of 'Some' or 'Unknown' mean the webhook may "
                    "make persistent changes even during dry-run requests, "
                    "violating the dry-run contract and potentially corrupting "
                    "external state."
                ),
                recommendation=(
                    "Set sideEffects to 'None' if the webhook performs no "
                    "out-of-band writes, or 'NoneOnDryRun' if side effects are "
                    "suppressed during dry-run. Audit the webhook backend to "
                    "ensure dry-run semantics are respected."
                ),
            )
        ]

    # ------------------------------------------------------------------
    # Global / cross-webhook checks
    # ------------------------------------------------------------------

    def _check_adms005(
        self, webhooks: List[AdmissionWebhook]
    ) -> List[AdmissionFinding]:
        """ADMS-005 — No webhook covers critical resources (pods + CREATE)."""
        # A webhook "covers" critical resources when at least one of its rules:
        #   - has "pods" OR "*" in resources, AND
        #   - has "CREATE" OR "*" in operations
        covers_critical = False
        for hook in webhooks:
            for rule in hook.rules:
                resource_match = any(
                    r in ("pods", "*") for r in rule.resources
                )
                operation_match = any(
                    op in ("CREATE", "*") for op in rule.operations
                )
                if resource_match and operation_match:
                    covers_critical = True
                    break
            if covers_critical:
                break

        if covers_critical:
            return []

        return [
            AdmissionFinding(
                check_id="ADMS-005",
                severity=self._SEVERITY["ADMS-005"],
                webhook_name="",
                webhook_type="",
                message=(
                    "No admission webhook covers pod CREATE operations. "
                    "Without a webhook intercepting pod creation, malicious or "
                    "non-compliant workloads can be scheduled without policy "
                    "enforcement."
                ),
                recommendation=(
                    "Deploy at least one validating or mutating admission webhook "
                    "whose rules include resources=['pods'] (or '*') and "
                    "operations=['CREATE'] (or '*'). Consider using OPA/Gatekeeper "
                    "or Kyverno for policy enforcement on pod workloads."
                ),
            )
        ]
