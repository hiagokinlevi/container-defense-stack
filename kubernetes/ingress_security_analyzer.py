# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International License.
# https://creativecommons.org/licenses/by/4.0/
"""
Kubernetes Ingress Security Analyzer
=====================================
Analyzes Kubernetes Ingress manifests for common security misconfigurations.

Operates entirely offline on Python dicts — no live cluster API calls required.

Check IDs
----------
ING-001  Ingress without TLS configured               (HIGH,   w=25)
ING-002  TLS but no HTTP→HTTPS redirect annotation    (MEDIUM, w=15)
ING-003  Wildcard host in Ingress rule                (HIGH,   w=25)
ING-004  Backend service on privileged port (<1024)   (MEDIUM, w=15)
ING-005  No auth/authorization middleware configured  (MEDIUM, w=15)
ING-006  CORS wildcard (*) in annotations             (HIGH,   w=20)
ING-007  Ingress in default namespace                 (LOW,    w=5)

Usage::

    from kubernetes.ingress_security_analyzer import (
        IngressSecurityAnalyzer, IngressSpec, IngressTLS, IngressRule
    )

    spec = IngressSpec(
        name="my-ingress",
        namespace="production",
        ingress_class="nginx",
        tls=[IngressTLS(hosts=["app.example.com"], secret_name="app-tls")],
        rules=[
            IngressRule(
                host="app.example.com",
                paths=[{
                    "path": "/",
                    "path_type": "Prefix",
                    "backend_service_name": "app-svc",
                    "backend_service_port": 8080,
                }],
            )
        ],
        annotations={
            "nginx.ingress.kubernetes.io/ssl-redirect": "true",
            "nginx.ingress.kubernetes.io/auth-url": "https://auth.example.com/verify",
        },
    )
    analyzer = IngressSecurityAnalyzer()
    result = analyzer.analyze(spec)
    print(result.summary())
    for finding in result.findings:
        print(finding.to_dict())
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Weight table — each check ID maps to its integer contribution to risk_score.
# risk_score = min(100, sum of weights for each *unique* fired check ID).
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "ING-001": 25,  # no TLS configured
    "ING-002": 15,  # TLS present but no HTTP→HTTPS redirect
    "ING-003": 25,  # wildcard host
    "ING-004": 15,  # backend on privileged port
    "ING-005": 15,  # no auth/authorization middleware
    "ING-006": 20,  # CORS wildcard origin
    "ING-007":  5,  # ingress in default namespace
}

# Annotations that indicate an HTTP→HTTPS redirect is configured.
# The presence of any one of these (with the required value) satisfies ING-002.
_REDIRECT_ANNOTATIONS: Dict[str, Optional[str]] = {
    "nginx.ingress.kubernetes.io/ssl-redirect":        "true",
    "nginx.ingress.kubernetes.io/force-ssl-redirect":  "true",
    "traefik.ingress.kubernetes.io/redirect-permanent": "true",
    "alb.ingress.kubernetes.io/actions.ssl-redirect":  None,  # any value counts
}

# Annotation keys that prove authentication/authorization is configured.
# A caller may also set any annotation key containing "auth" (case-insensitive).
_AUTH_ANNOTATION_KEYS = {
    "nginx.ingress.kubernetes.io/auth-url",
    "nginx.ingress.kubernetes.io/auth-type",
    "traefik.ingress.kubernetes.io/router.middlewares",
    "alb.ingress.kubernetes.io/auth-type",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class IngressTLS:
    """
    A single TLS block in a Kubernetes Ingress spec.

    Attributes:
        hosts:       Hostnames covered by this TLS certificate entry.
        secret_name: Name of the Kubernetes Secret holding the TLS key pair;
                     may be None when using a default wildcard certificate.
    """
    hosts:       List[str]
    secret_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "hosts":       self.hosts,
            "secret_name": self.secret_name,
        }


@dataclass
class IngressRule:
    """
    A single routing rule in a Kubernetes Ingress spec.

    Attributes:
        host:  Hostname this rule applies to.  None or ``"*"`` means catch-all.
        paths: List of path mapping dicts.  Each dict must contain:
               ``path`` (str), ``path_type`` (str),
               ``backend_service_name`` (str), ``backend_service_port`` (int).
    """
    host:  Optional[str]
    paths: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "host":  self.host,
            "paths": self.paths,
        }


@dataclass
class IngressSpec:
    """
    Normalised representation of a Kubernetes Ingress resource.

    Attributes:
        name:          Ingress resource name.
        namespace:     Kubernetes namespace (default: ``"default"``).
        ingress_class: Ingress controller class, e.g. ``"nginx"``, ``"traefik"``,
                       or ``"alb"``; None when not specified.
        tls:           List of :class:`IngressTLS` entries.
        rules:         List of :class:`IngressRule` routing rules.
        annotations:   All annotations on the Ingress as a flat string→string map.
    """
    name:          str
    namespace:     str                = "default"
    ingress_class: Optional[str]      = None
    tls:           List[IngressTLS]   = field(default_factory=list)
    rules:         List[IngressRule]  = field(default_factory=list)
    annotations:   Dict[str, str]     = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "name":          self.name,
            "namespace":     self.namespace,
            "ingress_class": self.ingress_class,
            "tls":           [t.to_dict() for t in self.tls],
            "rules":         [r.to_dict() for r in self.rules],
            "annotations":   self.annotations,
        }


@dataclass
class IngressFinding:
    """
    A single security finding produced by :class:`IngressSecurityAnalyzer`.

    Attributes:
        check_id:       Unique check identifier, e.g. ``"ING-001"``.
        severity:       One of ``"CRITICAL"``, ``"HIGH"``, ``"MEDIUM"``, ``"LOW"``.
        ingress_name:   Name of the Ingress resource where the issue was found.
        namespace:      Namespace of the Ingress resource.
        message:        Human-readable description of the problem.
        recommendation: Actionable remediation guidance.
    """
    check_id:       str
    severity:       str
    ingress_name:   str
    namespace:      str
    message:        str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "check_id":       self.check_id,
            "severity":       self.severity,
            "ingress_name":   self.ingress_name,
            "namespace":      self.namespace,
            "message":        self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class IngressSecurityResult:
    """
    Aggregated security analysis result for a single :class:`IngressSpec`.

    Attributes:
        ingress_name: Name of the analyzed Ingress resource.
        namespace:    Namespace of the analyzed Ingress resource.
        findings:     All :class:`IngressFinding` objects raised during analysis.
        risk_score:   Integer 0–100 derived from the unique check weights fired.
    """
    ingress_name: str
    namespace:    str
    findings:     List[IngressFinding] = field(default_factory=list)
    risk_score:   int                  = 0

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """
        Return a one-line human-readable summary of the analysis result.

        Example::

            "my-ingress (production): risk_score=35, findings=2 [HIGH=1, MEDIUM=1]"
        """
        if not self.findings:
            return (
                f"{self.ingress_name} ({self.namespace}): "
                f"risk_score={self.risk_score}, findings=0 [PASS]"
            )
        sev_counts = self.by_severity()
        parts = ", ".join(
            f"{sev}={count}"
            for sev, count in sorted(sev_counts.items())
            if count > 0
        )
        return (
            f"{self.ingress_name} ({self.namespace}): "
            f"risk_score={self.risk_score}, "
            f"findings={len(self.findings)} [{parts}]"
        )

    def by_severity(self) -> Dict[str, int]:
        """
        Return a dict mapping severity label to finding count.

        All four canonical severity levels are always present in the returned
        dict, even when their count is zero.

        Returns::

            {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
        """
        counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "ingress_name": self.ingress_name,
            "namespace":    self.namespace,
            "risk_score":   self.risk_score,
            "findings":     [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class IngressSecurityAnalyzer:
    """
    Offline Kubernetes Ingress security analyzer.

    Evaluates :class:`IngressSpec` objects against the seven built-in checks
    (ING-001 through ING-007) and returns an :class:`IngressSecurityResult`
    with all findings and a composite risk score.

    No network or cluster API calls are made; analysis is purely based on the
    data supplied in the :class:`IngressSpec`.

    Example::

        analyzer = IngressSecurityAnalyzer()
        result   = analyzer.analyze(my_ingress_spec)
        results  = analyzer.analyze_many([spec_a, spec_b, spec_c])
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, ingress: IngressSpec) -> IngressSecurityResult:
        """
        Analyze a single :class:`IngressSpec` and return a security result.

        Args:
            ingress: The normalised Ingress specification to evaluate.

        Returns:
            :class:`IngressSecurityResult` containing all fired findings and
            the computed risk score.
        """
        findings: List[IngressFinding] = []

        # Run all checks and collect findings.
        findings.extend(self._check_ing001(ingress))
        findings.extend(self._check_ing002(ingress))
        findings.extend(self._check_ing003(ingress))
        findings.extend(self._check_ing004(ingress))
        findings.extend(self._check_ing005(ingress))
        findings.extend(self._check_ing006(ingress))
        findings.extend(self._check_ing007(ingress))

        # Compute risk score: sum weights for *unique* fired check IDs, cap at 100.
        fired_ids = {f.check_id for f in findings}
        risk_score = min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired_ids))

        return IngressSecurityResult(
            ingress_name=ingress.name,
            namespace=ingress.namespace,
            findings=findings,
            risk_score=risk_score,
        )

    def analyze_many(self, ingresses: List[IngressSpec]) -> List[IngressSecurityResult]:
        """
        Analyze a list of :class:`IngressSpec` objects.

        Args:
            ingresses: Collection of normalised Ingress specifications.

        Returns:
            List of :class:`IngressSecurityResult`, one per input spec,
            in the same order as the input list.
        """
        return [self.analyze(ing) for ing in ingresses]

    # ------------------------------------------------------------------
    # Internal check methods
    # ------------------------------------------------------------------

    def _make_finding(
        self,
        check_id:       str,
        severity:       str,
        ingress:        IngressSpec,
        message:        str,
        recommendation: str,
    ) -> IngressFinding:
        """Construct a finding, injecting ingress name/namespace automatically."""
        return IngressFinding(
            check_id=check_id,
            severity=severity,
            ingress_name=ingress.name,
            namespace=ingress.namespace,
            message=message,
            recommendation=recommendation,
        )

    def _check_ing001(self, ingress: IngressSpec) -> List[IngressFinding]:
        """ING-001 — Ingress without TLS configured (HIGH, weight 25)."""
        if len(ingress.tls) == 0:
            return [self._make_finding(
                check_id="ING-001",
                severity="HIGH",
                ingress=ingress,
                message=(
                    f"Ingress '{ingress.name}' in namespace '{ingress.namespace}' "
                    "has no TLS configuration. All traffic is served over plain HTTP."
                ),
                recommendation=(
                    "Add a 'tls' block to the Ingress spec referencing a Kubernetes "
                    "Secret that holds a valid TLS certificate and private key. "
                    "Consider using cert-manager for automated certificate management."
                ),
            )]
        return []

    def _check_ing002(self, ingress: IngressSpec) -> List[IngressFinding]:
        """ING-002 — TLS configured but no HTTP→HTTPS redirect annotation (MEDIUM, weight 15)."""
        if len(ingress.tls) == 0:
            # ING-001 already covers the no-TLS case; skip redirect check.
            return []

        annotations = ingress.annotations
        for key, required_value in _REDIRECT_ANNOTATIONS.items():
            if key in annotations:
                # For annotations where any value counts, just seeing the key is enough.
                if required_value is None:
                    return []
                # For annotations with a specific required value, check it matches.
                if annotations[key] == required_value:
                    return []

        return [self._make_finding(
            check_id="ING-002",
            severity="MEDIUM",
            ingress=ingress,
            message=(
                f"Ingress '{ingress.name}' has TLS configured but no annotation "
                "enforcing HTTP→HTTPS redirection. Clients connecting over plain "
                "HTTP will not be automatically upgraded."
            ),
            recommendation=(
                "For NGINX: set annotation "
                "'nginx.ingress.kubernetes.io/ssl-redirect: \"true\"' or "
                "'nginx.ingress.kubernetes.io/force-ssl-redirect: \"true\"'. "
                "For Traefik: set 'traefik.ingress.kubernetes.io/redirect-permanent: \"true\"'. "
                "For ALB: configure 'alb.ingress.kubernetes.io/actions.ssl-redirect'."
            ),
        )]

    def _check_ing003(self, ingress: IngressSpec) -> List[IngressFinding]:
        """ING-003 — Wildcard host in Ingress rule (HIGH, weight 25)."""
        for rule in ingress.rules:
            host = rule.host
            # None, "*", or a wildcard pattern like "*.example.com" are all risky.
            if host is None or host == "*" or host.startswith("*."):
                return [self._make_finding(
                    check_id="ING-003",
                    severity="HIGH",
                    ingress=ingress,
                    message=(
                        f"Ingress '{ingress.name}' contains a wildcard or catch-all "
                        f"host rule (host={host!r}). This captures all unmatched "
                        "traffic and may expose unintended services."
                    ),
                    recommendation=(
                        "Replace wildcard host rules with explicit fully-qualified "
                        "hostnames. Each Ingress rule should target a specific, "
                        "well-defined domain or subdomain."
                    ),
                )]
        return []

    def _check_ing004(self, ingress: IngressSpec) -> List[IngressFinding]:
        """ING-004 — Backend service on privileged port (<1024) (MEDIUM, weight 15)."""
        for rule in ingress.rules:
            for path in rule.paths:
                try:
                    port = int(path.get("backend_service_port", 0))
                except (TypeError, ValueError):
                    continue
                if port < 1024:
                    svc   = path.get("backend_service_name", "<unknown>")
                    ppath = path.get("path", "/")
                    return [self._make_finding(
                        check_id="ING-004",
                        severity="MEDIUM",
                        ingress=ingress,
                        message=(
                            f"Ingress '{ingress.name}' routes to backend service "
                            f"'{svc}' on privileged port {port} (path: '{ppath}'). "
                            "Privileged ports (< 1024) require elevated capabilities "
                            "inside the container."
                        ),
                        recommendation=(
                            "Reconfigure the backend service to listen on an "
                            "unprivileged port (>= 1024). Common choices are 8080 "
                            "(HTTP) or 8443 (HTTPS). Remove any NET_BIND_SERVICE "
                            "capability grants where possible."
                        ),
                    )]
        return []

    def _check_ing005(self, ingress: IngressSpec) -> List[IngressFinding]:
        """ING-005 — No authentication/authorization middleware configured (MEDIUM, weight 15)."""
        annotations = ingress.annotations

        # Check well-known auth annotation keys first.
        for key in _AUTH_ANNOTATION_KEYS:
            if key in annotations:
                return []  # auth is configured

        # Accept any annotation key that contains "auth" (case-insensitive).
        for key in annotations:
            if "auth" in key.lower():
                return []  # auth is configured

        return [self._make_finding(
            check_id="ING-005",
            severity="MEDIUM",
            ingress=ingress,
            message=(
                f"Ingress '{ingress.name}' has no authentication or authorization "
                "middleware annotations. All traffic reaching this Ingress is "
                "forwarded to backends without identity verification."
            ),
            recommendation=(
                "Protect this Ingress with an authentication layer. For NGINX: "
                "configure 'nginx.ingress.kubernetes.io/auth-url' and "
                "'nginx.ingress.kubernetes.io/auth-type'. For Traefik: attach a "
                "middleware via 'traefik.ingress.kubernetes.io/router.middlewares'. "
                "For ALB: set 'alb.ingress.kubernetes.io/auth-type'."
            ),
        )]

    def _check_ing006(self, ingress: IngressSpec) -> List[IngressFinding]:
        """ING-006 — CORS wildcard (*) in annotations (HIGH, weight 20)."""
        annotations = ingress.annotations
        cors_origin  = annotations.get("nginx.ingress.kubernetes.io/cors-allow-origin", "")
        cors_enabled = annotations.get("nginx.ingress.kubernetes.io/enable-cors", "").lower()

        # Explicit wildcard origin.
        if cors_origin and ("*" in cors_origin):
            return [self._make_finding(
                check_id="ING-006",
                severity="HIGH",
                ingress=ingress,
                message=(
                    f"Ingress '{ingress.name}' sets 'cors-allow-origin' to "
                    f"'{cors_origin}', which includes a wildcard '*'. "
                    "This allows any origin to make cross-origin requests."
                ),
                recommendation=(
                    "Replace the wildcard CORS origin with an explicit allowlist of "
                    "trusted origins, e.g. 'https://app.example.com'. Never use '*' "
                    "for endpoints that handle authenticated or sensitive data."
                ),
            )]

        # CORS enabled but no origin restriction set.
        if cors_enabled == "true" and not cors_origin:
            return [self._make_finding(
                check_id="ING-006",
                severity="HIGH",
                ingress=ingress,
                message=(
                    f"Ingress '{ingress.name}' has CORS enabled "
                    "('nginx.ingress.kubernetes.io/enable-cors: \"true\"') but no "
                    "'cors-allow-origin' annotation is set, defaulting to wildcard "
                    "access."
                ),
                recommendation=(
                    "Set 'nginx.ingress.kubernetes.io/cors-allow-origin' to an "
                    "explicit list of trusted origins. Do not rely on the default "
                    "open-CORS behaviour of the NGINX Ingress controller."
                ),
            )]

        return []

    def _check_ing007(self, ingress: IngressSpec) -> List[IngressFinding]:
        """ING-007 — Ingress in default namespace (LOW, weight 5)."""
        if ingress.namespace == "default":
            return [self._make_finding(
                check_id="ING-007",
                severity="LOW",
                ingress=ingress,
                message=(
                    f"Ingress '{ingress.name}' is deployed in the 'default' "
                    "namespace. The default namespace lacks dedicated RBAC controls "
                    "and resource isolation."
                ),
                recommendation=(
                    "Move production Ingress resources into a dedicated namespace "
                    "(e.g., 'ingress-nginx', 'traefik', or an application-specific "
                    "namespace) and apply appropriate RBAC policies and network "
                    "policies to that namespace."
                ),
            )]
        return []
