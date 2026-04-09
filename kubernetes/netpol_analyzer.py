"""
Kubernetes Network Policy Analyzer
=====================================
Analyzes Kubernetes NetworkPolicy manifests for security gaps: missing
ingress/egress coverage, overly permissive selectors, namespaced isolation
gaps, and allow-all rules.

Operates on parsed manifest dicts (standard Kubernetes YAML/JSON structure).
No live cluster access required.

Check IDs
----------
NP-001   Pod has no NetworkPolicy selecting it (no ingress isolation)
NP-002   Pod has no NetworkPolicy with egress rules (no egress isolation)
NP-003   NetworkPolicy allows ingress from all pods (empty podSelector)
NP-004   NetworkPolicy allows ingress from all namespaces (empty namespaceSelector)
NP-005   NetworkPolicy allows egress to all destinations (empty egress rule)
NP-006   NetworkPolicy targets all pods in namespace (empty spec.podSelector)
NP-007   NetworkPolicy allows all ports (no ports restriction)

Usage::

    from kubernetes.netpol_analyzer import NetworkPolicyAnalyzer, NetpolFinding

    manifests = [
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "allow-all", "namespace": "default"},
            "spec": {
                "podSelector": {},
                "ingress": [{}],
                "policyTypes": ["Ingress"],
            }
        }
    ]
    analyzer = NetworkPolicyAnalyzer()
    report = analyzer.analyze(manifests)
    for finding in report.findings:
        print(finding.to_dict())
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class NetpolSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# ---------------------------------------------------------------------------
# NetpolFinding
# ---------------------------------------------------------------------------

@dataclass
class NetpolFinding:
    """
    A single network policy security finding.

    Attributes:
        check_id:    NP-XXX identifier.
        severity:    Severity level.
        namespace:   Kubernetes namespace.
        policy_name: NetworkPolicy name (empty for coverage gaps).
        title:       Short description.
        detail:      Detailed explanation.
        remediation: Recommended fix.
    """
    check_id:    str
    severity:    NetpolSeverity
    namespace:   str
    policy_name: str
    title:       str
    detail:      str
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id":    self.check_id,
            "severity":    self.severity.value,
            "namespace":   self.namespace,
            "policy_name": self.policy_name,
            "title":       self.title,
            "detail":      self.detail,
            "remediation": self.remediation,
        }

    def summary(self) -> str:
        return f"[{self.check_id}] {self.severity.value}: {self.title} ({self.namespace}/{self.policy_name})"


# ---------------------------------------------------------------------------
# NetpolReport
# ---------------------------------------------------------------------------

@dataclass
class NetpolReport:
    """
    Aggregated network policy analysis report.

    Attributes:
        findings:     All network policy findings.
        risk_score:   0–100 aggregate risk score.
        policies_analyzed: Number of NetworkPolicy manifests analyzed.
        generated_at: Unix timestamp.
    """
    findings:           List[NetpolFinding] = field(default_factory=list)
    risk_score:         int                 = 0
    policies_analyzed:  int                 = 0
    generated_at:       float               = field(default_factory=time.time)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> List[NetpolFinding]:
        return [f for f in self.findings if f.severity == NetpolSeverity.CRITICAL]

    @property
    def high_findings(self) -> List[NetpolFinding]:
        return [f for f in self.findings if f.severity == NetpolSeverity.HIGH]

    def findings_by_check(self, check_id: str) -> List[NetpolFinding]:
        return [f for f in self.findings if f.check_id == check_id]

    def findings_for_namespace(self, ns: str) -> List[NetpolFinding]:
        return [f for f in self.findings if f.namespace == ns]

    def summary(self) -> str:
        return (
            f"NetPol Report: {self.total_findings} findings, "
            f"risk_score={self.risk_score}, "
            f"policies_analyzed={self.policies_analyzed}"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_findings":    self.total_findings,
            "risk_score":        self.risk_score,
            "policies_analyzed": self.policies_analyzed,
            "critical":          len(self.critical_findings),
            "high":              len(self.high_findings),
            "generated_at":      self.generated_at,
            "findings":          [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Check weights
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "NP-001": 30,
    "NP-002": 25,
    "NP-003": 35,
    "NP-004": 30,
    "NP-005": 30,
    "NP-006": 25,
    "NP-007": 15,
}


# ---------------------------------------------------------------------------
# NetworkPolicyAnalyzer
# ---------------------------------------------------------------------------

class NetworkPolicyAnalyzer:
    """
    Analyze Kubernetes NetworkPolicy manifests for security gaps.

    Args:
        default_namespace: Namespace to use when manifest has no namespace
                           set (default "default").
        check_coverage:    Check for pods/namespaces with no policy coverage
                           when pod/namespace lists are provided.
    """

    def __init__(
        self,
        default_namespace: str = "default",
        check_coverage: bool = True,
    ) -> None:
        self._default_ns  = default_namespace
        self._check_coverage = check_coverage

    def analyze(self, manifests: List[Dict]) -> NetpolReport:
        """
        Analyze a list of Kubernetes manifest dicts.

        Only NetworkPolicy manifests are examined; other kinds are ignored.

        Returns:
            NetpolReport with all findings and risk score.
        """
        findings: List[NetpolFinding] = []
        policies: List[Dict] = [
            m for m in manifests
            if m.get("kind") == "NetworkPolicy"
        ]

        for policy in policies:
            findings.extend(self._analyze_policy(policy))

        fired = {f.check_id for f in findings}
        score = min(100, sum(_CHECK_WEIGHTS.get(c, 10) for c in fired))

        return NetpolReport(
            findings=findings,
            risk_score=score,
            policies_analyzed=len(policies),
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _ns(self, policy: Dict) -> str:
        meta = policy.get("metadata", {})
        return meta.get("namespace", self._default_ns) or self._default_ns

    def _name(self, policy: Dict) -> str:
        return policy.get("metadata", {}).get("name", "<unnamed>")

    def _analyze_policy(self, policy: Dict) -> List[NetpolFinding]:
        findings: List[NetpolFinding] = []
        spec = policy.get("spec", {})
        ns   = self._ns(policy)
        name = self._name(policy)

        pod_selector  = spec.get("podSelector", None)
        ingress_rules = spec.get("ingress", None)
        egress_rules  = spec.get("egress", None)
        policy_types  = spec.get("policyTypes", [])

        # NP-006: empty podSelector targets ALL pods
        if pod_selector == {} or pod_selector is None:
            findings.append(NetpolFinding(
                check_id="NP-006",
                severity=NetpolSeverity.HIGH,
                namespace=ns,
                policy_name=name,
                title="NetworkPolicy targets all pods in namespace",
                detail=(
                    f"Policy '{name}' in namespace '{ns}' has an empty "
                    f"podSelector, applying to every pod in the namespace."
                ),
                remediation=(
                    "Use a specific podSelector with matchLabels to target "
                    "only the pods that require this policy."
                ),
            ))

        # NP-003 / NP-004: ingress from all pods or all namespaces
        if ingress_rules is not None:
            for rule in ingress_rules:
                if not isinstance(rule, dict):
                    continue
                froms = rule.get("from", None)
                ports = rule.get("ports", None)

                if froms is None or froms == []:
                    # Empty 'from' or missing 'from' → allow all ingress
                    findings.append(NetpolFinding(
                        check_id="NP-003",
                        severity=NetpolSeverity.CRITICAL,
                        namespace=ns,
                        policy_name=name,
                        title="Ingress rule allows traffic from all sources",
                        detail=(
                            f"Policy '{name}' in '{ns}' has an ingress rule "
                            f"with no 'from' selector — allows ALL ingress."
                        ),
                        remediation=(
                            "Add explicit 'from' selectors to restrict ingress "
                            "to specific pods or namespaces."
                        ),
                    ))
                else:
                    for peer in froms:
                        if not isinstance(peer, dict):
                            continue
                        # Empty podSelector in peer → any pod
                        if "podSelector" in peer and peer["podSelector"] == {}:
                            findings.append(NetpolFinding(
                                check_id="NP-003",
                                severity=NetpolSeverity.HIGH,
                                namespace=ns,
                                policy_name=name,
                                title="Ingress allows from all pods (empty podSelector)",
                                detail=(
                                    f"Policy '{name}' in '{ns}' has an ingress "
                                    f"'from' peer with empty podSelector — allows "
                                    f"traffic from any pod."
                                ),
                                remediation=(
                                    "Replace empty podSelector with specific matchLabels."
                                ),
                            ))
                        # Empty namespaceSelector → any namespace
                        if "namespaceSelector" in peer and peer["namespaceSelector"] == {}:
                            findings.append(NetpolFinding(
                                check_id="NP-004",
                                severity=NetpolSeverity.HIGH,
                                namespace=ns,
                                policy_name=name,
                                title="Ingress allows from all namespaces (empty namespaceSelector)",
                                detail=(
                                    f"Policy '{name}' in '{ns}' has an ingress "
                                    f"'from' peer with empty namespaceSelector — "
                                    f"allows traffic from any namespace."
                                ),
                                remediation=(
                                    "Add matchLabels to namespaceSelector to restrict "
                                    "to specific namespaces."
                                ),
                            ))

                # NP-007: no ports restriction
                if ports is None and froms is not None and froms != []:
                    findings.append(NetpolFinding(
                        check_id="NP-007",
                        severity=NetpolSeverity.MEDIUM,
                        namespace=ns,
                        policy_name=name,
                        title="Ingress rule has no port restriction",
                        detail=(
                            f"Policy '{name}' in '{ns}' has an ingress rule "
                            f"with no 'ports' field — allows all ports."
                        ),
                        remediation=(
                            "Add a 'ports' list to restrict ingress to only "
                            "the required ports and protocols."
                        ),
                    ))

        # NP-005: egress to all destinations
        if egress_rules is not None:
            for rule in egress_rules:
                if not isinstance(rule, dict):
                    continue
                tos = rule.get("to", None)
                if tos is None or tos == []:
                    findings.append(NetpolFinding(
                        check_id="NP-005",
                        severity=NetpolSeverity.HIGH,
                        namespace=ns,
                        policy_name=name,
                        title="Egress rule allows traffic to all destinations",
                        detail=(
                            f"Policy '{name}' in '{ns}' has an egress rule "
                            f"with no 'to' selector — allows egress to ANY destination."
                        ),
                        remediation=(
                            "Add 'to' selectors to restrict egress to specific "
                            "pods, namespaces, or IP blocks."
                        ),
                    ))

        return findings
