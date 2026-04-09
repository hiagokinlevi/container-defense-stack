# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International License.
# https://creativecommons.org/licenses/by/4.0/
"""
Tests for kubernetes/ingress_security_analyzer.py
==================================================
85+ tests covering every check (ING-001–ING-007), boundary conditions,
risk_score capping, summary/by_severity format, analyze_many(), and all
to_dict() serialisation methods.
"""
from __future__ import annotations

import sys
import os

# ---------------------------------------------------------------------------
# Path bootstrap — allow running from the project root or the tests directory.
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import pytest
from kubernetes.ingress_security_analyzer import (
    IngressFinding,
    IngressRule,
    IngressSecurityAnalyzer,
    IngressSecurityResult,
    IngressSpec,
    IngressTLS,
    _CHECK_WEIGHTS,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ANALYZER = IngressSecurityAnalyzer()


def _make_spec(
    name: str = "test-ingress",
    namespace: str = "production",
    ingress_class: str | None = "nginx",
    tls: list | None = None,
    rules: list | None = None,
    annotations: dict | None = None,
) -> IngressSpec:
    """Return an IngressSpec with sensible defaults for test customisation."""
    return IngressSpec(
        name=name,
        namespace=namespace,
        ingress_class=ingress_class,
        tls=tls if tls is not None else [],
        rules=rules if rules is not None else [],
        annotations=annotations if annotations is not None else {},
    )


def _tls(hosts: list | None = None, secret: str | None = "app-tls") -> IngressTLS:
    """Shorthand for a TLS entry."""
    return IngressTLS(hosts=hosts or ["app.example.com"], secret_name=secret)


def _rule(
    host: str | None = "app.example.com",
    port: int = 8080,
    path: str = "/",
) -> IngressRule:
    """Shorthand for a routing rule with a single path."""
    return IngressRule(
        host=host,
        paths=[{
            "path": path,
            "path_type": "Prefix",
            "backend_service_name": "app-svc",
            "backend_service_port": port,
        }],
    )


def _ids(result: IngressSecurityResult) -> set:
    """Return the set of check IDs present in a result's findings."""
    return {f.check_id for f in result.findings}


# ---------------------------------------------------------------------------
# Compliant ingress — zero findings expected
# ---------------------------------------------------------------------------

class TestCompliantIngress:
    """A fully-configured, compliant Ingress produces no findings."""

    def _compliant(self) -> IngressSpec:
        return _make_spec(
            namespace="production",
            tls=[_tls()],
            rules=[_rule()],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "https://auth.example.com/verify",
            },
        )

    def test_compliant_no_findings(self):
        result = _ANALYZER.analyze(self._compliant())
        assert result.findings == []

    def test_compliant_risk_score_zero(self):
        result = _ANALYZER.analyze(self._compliant())
        assert result.risk_score == 0

    def test_compliant_summary_pass(self):
        result = _ANALYZER.analyze(self._compliant())
        assert "PASS" in result.summary()

    def test_compliant_by_severity_all_zero(self):
        result = _ANALYZER.analyze(self._compliant())
        bsev = result.by_severity()
        assert bsev == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}


# ---------------------------------------------------------------------------
# ING-001 — No TLS configured
# ---------------------------------------------------------------------------

class TestING001:
    """ING-001 fires when tls=[] and does NOT fire when tls is non-empty."""

    def test_no_tls_fires(self):
        spec = _make_spec(tls=[])
        result = _ANALYZER.analyze(spec)
        assert "ING-001" in _ids(result)

    def test_no_tls_severity_high(self):
        spec = _make_spec(tls=[])
        result = _ANALYZER.analyze(spec)
        finding = next(f for f in result.findings if f.check_id == "ING-001")
        assert finding.severity == "HIGH"

    def test_tls_present_does_not_fire(self):
        spec = _make_spec(
            tls=[_tls()],
            annotations={"nginx.ingress.kubernetes.io/ssl-redirect": "true",
                         "nginx.ingress.kubernetes.io/auth-url": "x"},
        )
        result = _ANALYZER.analyze(spec)
        assert "ING-001" not in _ids(result)

    def test_no_tls_risk_score_positive(self):
        spec = _make_spec(tls=[])
        result = _ANALYZER.analyze(spec)
        assert result.risk_score >= _CHECK_WEIGHTS["ING-001"]

    def test_no_tls_finding_message_contains_name(self):
        spec = _make_spec(name="my-ing", tls=[])
        result = _ANALYZER.analyze(spec)
        finding = next(f for f in result.findings if f.check_id == "ING-001")
        assert "my-ing" in finding.message

    def test_no_tls_finding_has_recommendation(self):
        spec = _make_spec(tls=[])
        result = _ANALYZER.analyze(spec)
        finding = next(f for f in result.findings if f.check_id == "ING-001")
        assert len(finding.recommendation) > 0

    def test_tls_with_no_secret_still_suppresses_001(self):
        """TLS without a secret_name (default cert scenario) still counts as TLS."""
        spec = _make_spec(
            tls=[IngressTLS(hosts=["app.example.com"], secret_name=None)],
            annotations={"nginx.ingress.kubernetes.io/ssl-redirect": "true",
                         "nginx.ingress.kubernetes.io/auth-url": "x"},
        )
        result = _ANALYZER.analyze(spec)
        assert "ING-001" not in _ids(result)


# ---------------------------------------------------------------------------
# ING-002 — TLS present but no HTTP→HTTPS redirect
# ---------------------------------------------------------------------------

class TestING002:
    """ING-002 fires when TLS is configured but no redirect annotation is present."""

    def _tls_no_redirect(self, extra_annotations: dict | None = None) -> IngressSpec:
        ann = {"nginx.ingress.kubernetes.io/auth-url": "x"}
        if extra_annotations:
            ann.update(extra_annotations)
        return _make_spec(tls=[_tls()], annotations=ann)

    def test_tls_no_redirect_fires(self):
        result = _ANALYZER.analyze(self._tls_no_redirect())
        assert "ING-002" in _ids(result)

    def test_tls_no_redirect_severity_medium(self):
        result = _ANALYZER.analyze(self._tls_no_redirect())
        finding = next(f for f in result.findings if f.check_id == "ING-002")
        assert finding.severity == "MEDIUM"

    def test_nginx_ssl_redirect_true_suppresses(self):
        result = _ANALYZER.analyze(self._tls_no_redirect({
            "nginx.ingress.kubernetes.io/ssl-redirect": "true",
        }))
        assert "ING-002" not in _ids(result)

    def test_nginx_ssl_redirect_false_does_not_suppress(self):
        result = _ANALYZER.analyze(self._tls_no_redirect({
            "nginx.ingress.kubernetes.io/ssl-redirect": "false",
        }))
        assert "ING-002" in _ids(result)

    def test_nginx_force_ssl_redirect_suppresses(self):
        result = _ANALYZER.analyze(self._tls_no_redirect({
            "nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
        }))
        assert "ING-002" not in _ids(result)

    def test_traefik_redirect_permanent_suppresses(self):
        result = _ANALYZER.analyze(self._tls_no_redirect({
            "traefik.ingress.kubernetes.io/redirect-permanent": "true",
        }))
        assert "ING-002" not in _ids(result)

    def test_alb_ssl_redirect_any_value_suppresses(self):
        result = _ANALYZER.analyze(self._tls_no_redirect({
            "alb.ingress.kubernetes.io/actions.ssl-redirect": "301",
        }))
        assert "ING-002" not in _ids(result)

    def test_alb_ssl_redirect_empty_string_suppresses(self):
        """ALB key present with any value — even empty — satisfies the check."""
        result = _ANALYZER.analyze(self._tls_no_redirect({
            "alb.ingress.kubernetes.io/actions.ssl-redirect": "",
        }))
        assert "ING-002" not in _ids(result)

    def test_no_tls_skips_ing002(self):
        """ING-002 must NOT fire when there is no TLS (ING-001 covers that case)."""
        spec = _make_spec(tls=[])
        result = _ANALYZER.analyze(spec)
        assert "ING-002" not in _ids(result)

    def test_ing002_has_recommendation(self):
        result = _ANALYZER.analyze(self._tls_no_redirect())
        finding = next(f for f in result.findings if f.check_id == "ING-002")
        assert len(finding.recommendation) > 0


# ---------------------------------------------------------------------------
# ING-003 — Wildcard host
# ---------------------------------------------------------------------------

class TestING003:
    """ING-003 fires on catch-all or wildcard host rules."""

    def _with_host(self, host) -> IngressSpec:
        return _make_spec(
            tls=[_tls()],
            rules=[_rule(host=host)],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )

    def test_host_none_fires(self):
        result = _ANALYZER.analyze(self._with_host(None))
        assert "ING-003" in _ids(result)

    def test_host_star_fires(self):
        result = _ANALYZER.analyze(self._with_host("*"))
        assert "ING-003" in _ids(result)

    def test_host_wildcard_prefix_fires(self):
        result = _ANALYZER.analyze(self._with_host("*.example.com"))
        assert "ING-003" in _ids(result)

    def test_host_wildcard_prefix_deep_fires(self):
        result = _ANALYZER.analyze(self._with_host("*.sub.example.com"))
        assert "ING-003" in _ids(result)

    def test_host_specific_does_not_fire(self):
        result = _ANALYZER.analyze(self._with_host("app.example.com"))
        assert "ING-003" not in _ids(result)

    def test_host_subdomain_does_not_fire(self):
        result = _ANALYZER.analyze(self._with_host("api.internal.example.com"))
        assert "ING-003" not in _ids(result)

    def test_ing003_severity_high(self):
        result = _ANALYZER.analyze(self._with_host(None))
        finding = next(f for f in result.findings if f.check_id == "ING-003")
        assert finding.severity == "HIGH"

    def test_empty_rules_no_ing003(self):
        spec = _make_spec(
            tls=[_tls()],
            rules=[],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )
        result = _ANALYZER.analyze(spec)
        assert "ING-003" not in _ids(result)

    def test_ing003_message_contains_host_repr(self):
        result = _ANALYZER.analyze(self._with_host("*.example.com"))
        finding = next(f for f in result.findings if f.check_id == "ING-003")
        assert "*.example.com" in finding.message


# ---------------------------------------------------------------------------
# ING-004 — Backend on privileged port
# ---------------------------------------------------------------------------

class TestING004:
    """ING-004 fires when any backend port is < 1024."""

    def _with_port(self, port: int) -> IngressSpec:
        return _make_spec(
            tls=[_tls()],
            rules=[_rule(port=port)],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )

    def test_port_80_fires(self):
        result = _ANALYZER.analyze(self._with_port(80))
        assert "ING-004" in _ids(result)

    def test_port_443_fires(self):
        result = _ANALYZER.analyze(self._with_port(443))
        assert "ING-004" in _ids(result)

    def test_port_1023_fires(self):
        result = _ANALYZER.analyze(self._with_port(1023))
        assert "ING-004" in _ids(result)

    def test_port_1_fires(self):
        result = _ANALYZER.analyze(self._with_port(1))
        assert "ING-004" in _ids(result)

    def test_port_1024_does_not_fire(self):
        """1024 is the boundary: >= 1024 is safe."""
        result = _ANALYZER.analyze(self._with_port(1024))
        assert "ING-004" not in _ids(result)

    def test_port_8080_does_not_fire(self):
        result = _ANALYZER.analyze(self._with_port(8080))
        assert "ING-004" not in _ids(result)

    def test_port_65535_does_not_fire(self):
        result = _ANALYZER.analyze(self._with_port(65535))
        assert "ING-004" not in _ids(result)

    def test_ing004_severity_medium(self):
        result = _ANALYZER.analyze(self._with_port(80))
        finding = next(f for f in result.findings if f.check_id == "ING-004")
        assert finding.severity == "MEDIUM"

    def test_ing004_message_contains_port(self):
        result = _ANALYZER.analyze(self._with_port(80))
        finding = next(f for f in result.findings if f.check_id == "ING-004")
        assert "80" in finding.message

    def test_no_paths_no_ing004(self):
        spec = _make_spec(
            tls=[_tls()],
            rules=[IngressRule(host="app.example.com", paths=[])],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )
        result = _ANALYZER.analyze(spec)
        assert "ING-004" not in _ids(result)

    def test_second_path_privileged_fires(self):
        """ING-004 triggers if *any* path uses a privileged port."""
        rule = IngressRule(
            host="app.example.com",
            paths=[
                {
                    "path": "/api",
                    "path_type": "Prefix",
                    "backend_service_name": "api-svc",
                    "backend_service_port": 8080,  # safe
                },
                {
                    "path": "/legacy",
                    "path_type": "Prefix",
                    "backend_service_name": "legacy-svc",
                    "backend_service_port": 80,  # privileged
                },
            ],
        )
        spec = _make_spec(
            tls=[_tls()],
            rules=[rule],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )
        result = _ANALYZER.analyze(spec)
        assert "ING-004" in _ids(result)


# ---------------------------------------------------------------------------
# ING-005 — No auth/authorization middleware
# ---------------------------------------------------------------------------

class TestING005:
    """ING-005 fires when no authentication annotation is present."""

    def _base(self, annotations: dict | None = None) -> IngressSpec:
        return _make_spec(
            tls=[_tls()],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                **(annotations or {}),
            },
        )

    def test_no_auth_fires(self):
        result = _ANALYZER.analyze(self._base())
        assert "ING-005" in _ids(result)

    def test_no_auth_severity_medium(self):
        result = _ANALYZER.analyze(self._base())
        finding = next(f for f in result.findings if f.check_id == "ING-005")
        assert finding.severity == "MEDIUM"

    def test_nginx_auth_url_suppresses(self):
        result = _ANALYZER.analyze(self._base({
            "nginx.ingress.kubernetes.io/auth-url": "https://auth.example.com/",
        }))
        assert "ING-005" not in _ids(result)

    def test_nginx_auth_type_suppresses(self):
        result = _ANALYZER.analyze(self._base({
            "nginx.ingress.kubernetes.io/auth-type": "basic",
        }))
        assert "ING-005" not in _ids(result)

    def test_traefik_middlewares_suppresses(self):
        result = _ANALYZER.analyze(self._base({
            "traefik.ingress.kubernetes.io/router.middlewares": "default-auth@kubernetescrd",
        }))
        assert "ING-005" not in _ids(result)

    def test_alb_auth_type_suppresses(self):
        result = _ANALYZER.analyze(self._base({
            "alb.ingress.kubernetes.io/auth-type": "cognito",
        }))
        assert "ING-005" not in _ids(result)

    def test_custom_auth_annotation_key_suppresses(self):
        """Any annotation key containing 'auth' (case-insensitive) suppresses ING-005."""
        result = _ANALYZER.analyze(self._base({
            "mycompany.io/auth-middleware": "oauth2-proxy",
        }))
        assert "ING-005" not in _ids(result)

    def test_auth_case_insensitive_uppercase_suppresses(self):
        result = _ANALYZER.analyze(self._base({
            "mycompany.io/AUTH-required": "true",
        }))
        assert "ING-005" not in _ids(result)

    def test_auth_case_insensitive_mixed_suppresses(self):
        result = _ANALYZER.analyze(self._base({
            "example.com/Authorization-Policy": "enforce",
        }))
        assert "ING-005" not in _ids(result)

    def test_unrelated_annotation_does_not_suppress(self):
        result = _ANALYZER.analyze(self._base({
            "nginx.ingress.kubernetes.io/proxy-body-size": "10m",
        }))
        assert "ING-005" in _ids(result)

    def test_ing005_has_recommendation(self):
        result = _ANALYZER.analyze(self._base())
        finding = next(f for f in result.findings if f.check_id == "ING-005")
        assert len(finding.recommendation) > 0


# ---------------------------------------------------------------------------
# ING-006 — CORS wildcard
# ---------------------------------------------------------------------------

class TestING006:
    """ING-006 fires on wildcard CORS origin or CORS-enabled without restriction."""

    def _base(self, annotations: dict | None = None) -> IngressSpec:
        return _make_spec(
            tls=[_tls()],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
                **(annotations or {}),
            },
        )

    def test_cors_allow_origin_star_fires(self):
        result = _ANALYZER.analyze(self._base({
            "nginx.ingress.kubernetes.io/cors-allow-origin": "*",
        }))
        assert "ING-006" in _ids(result)

    def test_cors_allow_origin_containing_star_fires(self):
        result = _ANALYZER.analyze(self._base({
            "nginx.ingress.kubernetes.io/cors-allow-origin": "https://app.com, *",
        }))
        assert "ING-006" in _ids(result)

    def test_enable_cors_true_no_origin_fires(self):
        result = _ANALYZER.analyze(self._base({
            "nginx.ingress.kubernetes.io/enable-cors": "true",
        }))
        assert "ING-006" in _ids(result)

    def test_cors_allow_origin_specific_does_not_fire(self):
        result = _ANALYZER.analyze(self._base({
            "nginx.ingress.kubernetes.io/cors-allow-origin": "https://app.example.com",
        }))
        assert "ING-006" not in _ids(result)

    def test_enable_cors_true_with_specific_origin_does_not_fire(self):
        result = _ANALYZER.analyze(self._base({
            "nginx.ingress.kubernetes.io/enable-cors": "true",
            "nginx.ingress.kubernetes.io/cors-allow-origin": "https://app.example.com",
        }))
        assert "ING-006" not in _ids(result)

    def test_enable_cors_false_no_origin_does_not_fire(self):
        result = _ANALYZER.analyze(self._base({
            "nginx.ingress.kubernetes.io/enable-cors": "false",
        }))
        assert "ING-006" not in _ids(result)

    def test_no_cors_annotations_does_not_fire(self):
        result = _ANALYZER.analyze(self._base())
        assert "ING-006" not in _ids(result)

    def test_ing006_severity_high(self):
        result = _ANALYZER.analyze(self._base({
            "nginx.ingress.kubernetes.io/cors-allow-origin": "*",
        }))
        finding = next(f for f in result.findings if f.check_id == "ING-006")
        assert finding.severity == "HIGH"

    def test_ing006_message_contains_wildcard(self):
        result = _ANALYZER.analyze(self._base({
            "nginx.ingress.kubernetes.io/cors-allow-origin": "*",
        }))
        finding = next(f for f in result.findings if f.check_id == "ING-006")
        assert "*" in finding.message

    def test_ing006_enable_cors_has_recommendation(self):
        result = _ANALYZER.analyze(self._base({
            "nginx.ingress.kubernetes.io/enable-cors": "true",
        }))
        finding = next(f for f in result.findings if f.check_id == "ING-006")
        assert len(finding.recommendation) > 0


# ---------------------------------------------------------------------------
# ING-007 — Default namespace
# ---------------------------------------------------------------------------

class TestING007:
    """ING-007 fires when the Ingress is in the 'default' namespace."""

    def test_default_namespace_fires(self):
        spec = _make_spec(
            namespace="default",
            tls=[_tls()],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )
        result = _ANALYZER.analyze(spec)
        assert "ING-007" in _ids(result)

    def test_default_namespace_severity_low(self):
        spec = _make_spec(
            namespace="default",
            tls=[_tls()],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )
        result = _ANALYZER.analyze(spec)
        finding = next(f for f in result.findings if f.check_id == "ING-007")
        assert finding.severity == "LOW"

    def test_production_namespace_does_not_fire(self):
        spec = _make_spec(
            namespace="production",
            tls=[_tls()],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )
        result = _ANALYZER.analyze(spec)
        assert "ING-007" not in _ids(result)

    def test_kube_system_namespace_does_not_fire(self):
        spec = _make_spec(
            namespace="kube-system",
            tls=[_tls()],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )
        result = _ANALYZER.analyze(spec)
        assert "ING-007" not in _ids(result)

    def test_ingress_nginx_namespace_does_not_fire(self):
        spec = _make_spec(
            namespace="ingress-nginx",
            tls=[_tls()],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )
        result = _ANALYZER.analyze(spec)
        assert "ING-007" not in _ids(result)

    def test_ing007_has_recommendation(self):
        spec = _make_spec(
            namespace="default",
            tls=[_tls()],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )
        result = _ANALYZER.analyze(spec)
        finding = next(f for f in result.findings if f.check_id == "ING-007")
        assert len(finding.recommendation) > 0

    def test_ing007_message_contains_default(self):
        spec = _make_spec(
            namespace="default",
            tls=[_tls()],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )
        result = _ANALYZER.analyze(spec)
        finding = next(f for f in result.findings if f.check_id == "ING-007")
        assert "default" in finding.message


# ---------------------------------------------------------------------------
# Multiple findings on same ingress
# ---------------------------------------------------------------------------

class TestMultipleFindings:
    """Verify several checks can co-exist in one result."""

    def test_no_tls_no_auth_fires_001_and_005(self):
        spec = _make_spec(namespace="production", tls=[], annotations={})
        result = _ANALYZER.analyze(spec)
        assert "ING-001" in _ids(result)
        assert "ING-005" in _ids(result)

    def test_no_tls_default_ns_fires_001_and_007(self):
        spec = _make_spec(namespace="default", tls=[], annotations={})
        result = _ANALYZER.analyze(spec)
        assert "ING-001" in _ids(result)
        assert "ING-007" in _ids(result)

    def test_wildcard_host_and_privileged_port_fires_003_and_004(self):
        spec = _make_spec(
            tls=[_tls()],
            rules=[_rule(host=None, port=80)],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )
        result = _ANALYZER.analyze(spec)
        assert "ING-003" in _ids(result)
        assert "ING-004" in _ids(result)

    def test_all_checks_fire_worst_case(self):
        """Worst-case spec: no TLS, wildcard host, privileged port, no auth,
        CORS wildcard, default namespace."""
        spec = _make_spec(
            namespace="default",
            tls=[],
            rules=[_rule(host=None, port=80)],
            annotations={
                "nginx.ingress.kubernetes.io/cors-allow-origin": "*",
            },
        )
        result = _ANALYZER.analyze(spec)
        fired = _ids(result)
        # ING-001, ING-003, ING-004, ING-005, ING-006, ING-007 must fire.
        # ING-002 should NOT fire (no TLS — handled by ING-001 guard).
        assert "ING-001" in fired
        assert "ING-002" not in fired
        assert "ING-003" in fired
        assert "ING-004" in fired
        assert "ING-005" in fired
        assert "ING-006" in fired
        assert "ING-007" in fired

    def test_multiple_findings_count(self):
        spec = _make_spec(namespace="default", tls=[], annotations={})
        result = _ANALYZER.analyze(spec)
        # At minimum ING-001, ING-005, ING-007 fire on this spec.
        assert len(result.findings) >= 3


# ---------------------------------------------------------------------------
# Risk score
# ---------------------------------------------------------------------------

class TestRiskScore:
    """Verify risk_score computation and cap behaviour."""

    def test_zero_risk_for_compliant(self):
        spec = _make_spec(
            tls=[_tls()],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )
        assert _ANALYZER.analyze(spec).risk_score == 0

    def test_ing001_weight_25(self):
        spec = _make_spec(
            namespace="production",
            tls=[],
            annotations={"nginx.ingress.kubernetes.io/auth-url": "x"},
            rules=[_rule()],
        )
        result = _ANALYZER.analyze(spec)
        assert _CHECK_WEIGHTS["ING-001"] == 25
        # Only ING-001 fired; score must be exactly 25.
        assert result.risk_score == 25

    def test_risk_score_capped_at_100(self):
        """Sum of all check weights exceeds 100; score must be capped."""
        spec = _make_spec(
            namespace="default",
            tls=[],
            rules=[_rule(host=None, port=80)],
            annotations={
                "nginx.ingress.kubernetes.io/cors-allow-origin": "*",
            },
        )
        result = _ANALYZER.analyze(spec)
        assert result.risk_score <= 100

    def test_risk_score_non_negative(self):
        spec = _make_spec(tls=[])
        assert _ANALYZER.analyze(spec).risk_score >= 0

    def test_risk_score_int_type(self):
        spec = _make_spec(tls=[])
        assert isinstance(_ANALYZER.analyze(spec).risk_score, int)

    def test_unique_check_ids_not_double_counted(self):
        """Multiple findings with the same check_id should only count once."""
        # ING-003 fires once even if multiple wildcard rules exist.
        rule1 = IngressRule(host=None, paths=[])
        rule2 = IngressRule(host="*", paths=[])
        spec = _make_spec(
            tls=[_tls()],
            rules=[rule1, rule2],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )
        result = _ANALYZER.analyze(spec)
        ing003_count = sum(1 for f in result.findings if f.check_id == "ING-003")
        # Only one ING-003 finding; score should include ING-003 weight once.
        assert ing003_count == 1


# ---------------------------------------------------------------------------
# by_severity()
# ---------------------------------------------------------------------------

class TestBySeverity:
    """Verify by_severity() structure and counts."""

    def test_by_severity_keys_always_present(self):
        spec = _make_spec(tls=[])
        bsev = _ANALYZER.analyze(spec).by_severity()
        assert set(bsev.keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    def test_by_severity_all_zero_when_compliant(self):
        spec = _make_spec(
            tls=[_tls()],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )
        bsev = _ANALYZER.analyze(spec).by_severity()
        assert all(v == 0 for v in bsev.values())

    def test_by_severity_high_increments_on_ing001(self):
        spec = _make_spec(
            namespace="production",
            tls=[],
            annotations={"nginx.ingress.kubernetes.io/auth-url": "x"},
            rules=[_rule()],
        )
        bsev = _ANALYZER.analyze(spec).by_severity()
        # ING-001 is HIGH; verify HIGH >= 1
        assert bsev["HIGH"] >= 1

    def test_by_severity_low_increments_on_ing007(self):
        spec = _make_spec(
            namespace="default",
            tls=[_tls()],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )
        bsev = _ANALYZER.analyze(spec).by_severity()
        assert bsev["LOW"] >= 1

    def test_by_severity_values_are_ints(self):
        spec = _make_spec(tls=[])
        bsev = _ANALYZER.analyze(spec).by_severity()
        assert all(isinstance(v, int) for v in bsev.values())


# ---------------------------------------------------------------------------
# summary()
# ---------------------------------------------------------------------------

class TestSummary:
    """Verify summary() format."""

    def test_summary_contains_ingress_name(self):
        spec = _make_spec(name="edge-ingress", tls=[])
        s = _ANALYZER.analyze(spec).summary()
        assert "edge-ingress" in s

    def test_summary_contains_namespace(self):
        spec = _make_spec(namespace="staging", tls=[])
        s = _ANALYZER.analyze(spec).summary()
        assert "staging" in s

    def test_summary_contains_risk_score(self):
        spec = _make_spec(tls=[])
        s = _ANALYZER.analyze(spec).summary()
        assert "risk_score=" in s

    def test_summary_contains_findings_count(self):
        spec = _make_spec(tls=[])
        result = _ANALYZER.analyze(spec)
        s = result.summary()
        assert f"findings={len(result.findings)}" in s

    def test_summary_pass_label_when_zero_findings(self):
        spec = _make_spec(
            tls=[_tls()],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )
        s = _ANALYZER.analyze(spec).summary()
        assert "PASS" in s

    def test_summary_is_string(self):
        spec = _make_spec(tls=[])
        assert isinstance(_ANALYZER.analyze(spec).summary(), str)

    def test_summary_contains_severity_breakdown_when_findings_exist(self):
        spec = _make_spec(tls=[])
        s = _ANALYZER.analyze(spec).summary()
        # Should contain at least one severity label.
        assert any(sev in s for sev in ("HIGH", "MEDIUM", "LOW", "CRITICAL"))


# ---------------------------------------------------------------------------
# analyze_many()
# ---------------------------------------------------------------------------

class TestAnalyzeMany:
    """Verify analyze_many() returns a list matching the input length."""

    def test_returns_list(self):
        specs = [_make_spec(name=f"ing-{i}", tls=[]) for i in range(3)]
        results = _ANALYZER.analyze_many(specs)
        assert isinstance(results, list)

    def test_length_matches_input(self):
        specs = [_make_spec(name=f"ing-{i}", tls=[]) for i in range(5)]
        results = _ANALYZER.analyze_many(specs)
        assert len(results) == 5

    def test_empty_input_returns_empty_list(self):
        assert _ANALYZER.analyze_many([]) == []

    def test_order_preserved(self):
        names = ["alpha", "beta", "gamma"]
        specs = [_make_spec(name=n, tls=[]) for n in names]
        results = _ANALYZER.analyze_many(specs)
        assert [r.ingress_name for r in results] == names

    def test_single_element_list(self):
        spec = _make_spec(name="solo", tls=[])
        results = _ANALYZER.analyze_many([spec])
        assert len(results) == 1
        assert results[0].ingress_name == "solo"

    def test_each_element_is_ingress_security_result(self):
        specs = [_make_spec(name=f"ing-{i}") for i in range(3)]
        for r in _ANALYZER.analyze_many(specs):
            assert isinstance(r, IngressSecurityResult)


# ---------------------------------------------------------------------------
# to_dict() serialisation
# ---------------------------------------------------------------------------

class TestToDict:
    """Verify all to_dict() methods return complete, correctly-typed dicts."""

    def test_ingress_tls_to_dict_keys(self):
        tls = IngressTLS(hosts=["a.com"], secret_name="sec")
        d = tls.to_dict()
        assert set(d.keys()) == {"hosts", "secret_name"}

    def test_ingress_tls_to_dict_values(self):
        tls = IngressTLS(hosts=["a.com", "b.com"], secret_name="my-secret")
        d = tls.to_dict()
        assert d["hosts"] == ["a.com", "b.com"]
        assert d["secret_name"] == "my-secret"

    def test_ingress_tls_to_dict_none_secret(self):
        tls = IngressTLS(hosts=[], secret_name=None)
        d = tls.to_dict()
        assert d["secret_name"] is None

    def test_ingress_rule_to_dict_keys(self):
        rule = _rule()
        d = rule.to_dict()
        assert set(d.keys()) == {"host", "paths"}

    def test_ingress_rule_to_dict_values(self):
        rule = IngressRule(host="app.com", paths=[{"path": "/", "path_type": "Prefix",
                                                    "backend_service_name": "svc",
                                                    "backend_service_port": 8080}])
        d = rule.to_dict()
        assert d["host"] == "app.com"
        assert len(d["paths"]) == 1

    def test_ingress_spec_to_dict_keys(self):
        spec = _make_spec()
        d = spec.to_dict()
        assert set(d.keys()) == {
            "name", "namespace", "ingress_class", "tls", "rules", "annotations"
        }

    def test_ingress_spec_to_dict_tls_serialised(self):
        spec = _make_spec(tls=[_tls()])
        d = spec.to_dict()
        assert isinstance(d["tls"], list)
        assert isinstance(d["tls"][0], dict)

    def test_ingress_spec_to_dict_rules_serialised(self):
        spec = _make_spec(rules=[_rule()])
        d = spec.to_dict()
        assert isinstance(d["rules"], list)
        assert isinstance(d["rules"][0], dict)

    def test_ingress_finding_to_dict_keys(self):
        finding = IngressFinding(
            check_id="ING-001",
            severity="HIGH",
            ingress_name="foo",
            namespace="bar",
            message="msg",
            recommendation="rec",
        )
        d = finding.to_dict()
        assert set(d.keys()) == {
            "check_id", "severity", "ingress_name", "namespace",
            "message", "recommendation"
        }

    def test_ingress_finding_to_dict_values(self):
        finding = IngressFinding(
            check_id="ING-001",
            severity="HIGH",
            ingress_name="foo",
            namespace="bar",
            message="msg",
            recommendation="rec",
        )
        d = finding.to_dict()
        assert d["check_id"] == "ING-001"
        assert d["severity"] == "HIGH"
        assert d["ingress_name"] == "foo"

    def test_ingress_security_result_to_dict_keys(self):
        spec = _make_spec(tls=[])
        result = _ANALYZER.analyze(spec)
        d = result.to_dict()
        assert set(d.keys()) == {
            "ingress_name", "namespace", "risk_score", "findings"
        }

    def test_ingress_security_result_to_dict_findings_are_dicts(self):
        spec = _make_spec(tls=[])
        result = _ANALYZER.analyze(spec)
        d = result.to_dict()
        assert all(isinstance(f, dict) for f in d["findings"])

    def test_ingress_security_result_to_dict_risk_score_is_int(self):
        spec = _make_spec(tls=[])
        result = _ANALYZER.analyze(spec)
        d = result.to_dict()
        assert isinstance(d["risk_score"], int)

    def test_ingress_security_result_to_dict_empty_findings(self):
        spec = _make_spec(
            tls=[_tls()],
            annotations={
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/auth-url": "x",
            },
        )
        result = _ANALYZER.analyze(spec)
        d = result.to_dict()
        assert d["findings"] == []


# ---------------------------------------------------------------------------
# IngressSpec default field values
# ---------------------------------------------------------------------------

class TestIngressSpecDefaults:
    """Verify dataclass default values."""

    def test_default_namespace_is_default(self):
        spec = IngressSpec(name="x")
        assert spec.namespace == "default"

    def test_default_tls_empty(self):
        spec = IngressSpec(name="x")
        assert spec.tls == []

    def test_default_rules_empty(self):
        spec = IngressSpec(name="x")
        assert spec.rules == []

    def test_default_annotations_empty(self):
        spec = IngressSpec(name="x")
        assert spec.annotations == {}

    def test_default_ingress_class_none(self):
        spec = IngressSpec(name="x")
        assert spec.ingress_class is None


# ---------------------------------------------------------------------------
# IngressFinding fields
# ---------------------------------------------------------------------------

class TestIngressFindingFields:
    """Verify finding fields are correctly populated by the analyzer."""

    def test_finding_ingress_name_matches_spec(self):
        spec = _make_spec(name="named-ingress", tls=[])
        result = _ANALYZER.analyze(spec)
        assert all(f.ingress_name == "named-ingress" for f in result.findings)

    def test_finding_namespace_matches_spec(self):
        spec = _make_spec(namespace="staging", tls=[])
        result = _ANALYZER.analyze(spec)
        assert all(f.namespace == "staging" for f in result.findings)

    def test_finding_check_id_format(self):
        spec = _make_spec(tls=[])
        result = _ANALYZER.analyze(spec)
        for f in result.findings:
            assert f.check_id.startswith("ING-")

    def test_finding_severity_is_known_value(self):
        spec = _make_spec(tls=[])
        result = _ANALYZER.analyze(spec)
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for f in result.findings:
            assert f.severity in valid
