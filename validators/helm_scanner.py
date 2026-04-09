"""
Helm chart security scanner.

Parses Helm chart values files and templates to detect common security
misconfigurations before deployment. Complements the manifest_validator
with Helm-specific checks (image tags, securityContext defaults, resource
limits, service account settings, and network exposure).

All checks are static — no cluster connection is required.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class HelmFinding:
    """A single security finding from Helm chart analysis."""

    rule_id: str
    severity: Severity
    message: str
    location: str  # e.g. "values.yaml:image.tag" or "templates/deployment.yaml"
    remediation: str


@dataclass
class HelmScanResult:
    """Aggregated result of scanning a Helm chart directory."""

    chart_name: str
    chart_path: Path
    findings: list[HelmFinding] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def passed(self) -> bool:
        """Returns True if there are no CRITICAL or HIGH findings."""
        return self.critical_count == 0 and self.high_count == 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_chart(chart_dir: Path) -> HelmScanResult:
    """
    Scan a Helm chart directory for security misconfigurations.

    Reads:
      - values.yaml (primary values)
      - Chart.yaml (chart metadata)
      - templates/*.yaml (rendered template fragments)

    Args:
        chart_dir: Path to the chart root (the directory containing Chart.yaml).

    Returns:
        HelmScanResult with all findings.
    """
    chart_yaml_path = chart_dir / "Chart.yaml"
    chart_name = _read_chart_name(chart_yaml_path)
    result = HelmScanResult(chart_name=chart_name, chart_path=chart_dir)

    values_path = chart_dir / "values.yaml"
    if values_path.exists():
        values = _load_yaml(values_path)
        _check_values(values, result, values_path)
    else:
        result.findings.append(HelmFinding(
            rule_id="HELM000",
            severity=Severity.INFO,
            message="No values.yaml found — skipping values-based checks",
            location=str(chart_dir),
            remediation="Add a values.yaml with documented defaults",
        ))

    # Scan raw template files for hardcoded secrets and known patterns
    templates_dir = chart_dir / "templates"
    if templates_dir.exists():
        for tmpl_file in sorted(templates_dir.glob("*.yaml")):
            _check_template_file(tmpl_file, result)

    return result


def scan_values_file(values_path: Path, chart_name: str = "unknown") -> HelmScanResult:
    """
    Scan a standalone values file (no chart structure needed).

    Useful for CI pipelines that validate values files independently.

    Args:
        values_path: Path to a Helm values YAML file.
        chart_name:  Chart name for result labelling.

    Returns:
        HelmScanResult with findings from values analysis only.
    """
    result = HelmScanResult(chart_name=chart_name, chart_path=values_path.parent)
    values = _load_yaml(values_path)
    _check_values(values, result, values_path)
    return result


# ---------------------------------------------------------------------------
# Values checks
# ---------------------------------------------------------------------------


def _check_values(values: dict[str, Any], result: HelmScanResult, values_path: Path) -> None:
    """Run all security checks against a parsed values dict."""
    _check_image_tags(values, result, values_path)
    _check_security_context(values, result, values_path)
    _check_resource_limits(values, result, values_path)
    _check_service_account(values, result, values_path)
    _check_network_exposure(values, result, values_path)
    _check_hardcoded_credentials(values, result, values_path)


def _check_image_tags(
    values: dict[str, Any], result: HelmScanResult, values_path: Path
) -> None:
    """Flag image references using the ':latest' tag or no tag at all."""
    image = values.get("image", {})
    if not isinstance(image, dict):
        return

    tag = str(image.get("tag", ""))
    repo = image.get("repository", "")

    if not tag or tag.lower() == "latest":
        result.findings.append(HelmFinding(
            rule_id="HELM001",
            severity=Severity.HIGH,
            message=f"Image tag is '{tag or 'unset'}' — non-deterministic deployments can pull untested versions",
            location=f"{values_path.name}:image.tag",
            remediation="Pin to a specific semver tag (e.g. '1.2.3') or a full image digest",
        ))

    # Detect 'latest' embedded in the repository string (e.g. "myimage:latest")
    if ":latest" in str(repo).lower():
        result.findings.append(HelmFinding(
            rule_id="HELM001",
            severity=Severity.HIGH,
            message=f"Repository value '{repo}' contains ':latest' — split into repository + tag fields",
            location=f"{values_path.name}:image.repository",
            remediation="Use separate image.repository and image.tag fields; pin image.tag to a specific version",
        ))


def _check_security_context(
    values: dict[str, Any], result: HelmScanResult, values_path: Path
) -> None:
    """Check for missing or insecure securityContext defaults in values."""
    sc = values.get("securityContext", {})
    if not isinstance(sc, dict):
        sc = {}

    pod_sc = values.get("podSecurityContext", {})
    if not isinstance(pod_sc, dict):
        pod_sc = {}

    # Check container-level securityContext
    if sc.get("privileged") is True:
        result.findings.append(HelmFinding(
            rule_id="HELM002",
            severity=Severity.CRITICAL,
            message="Default securityContext sets privileged: true",
            location=f"{values_path.name}:securityContext.privileged",
            remediation="Remove securityContext.privileged or set it to false",
        ))

    if sc.get("allowPrivilegeEscalation") is not False:
        result.findings.append(HelmFinding(
            rule_id="HELM003",
            severity=Severity.HIGH,
            message="securityContext does not explicitly deny privilege escalation",
            location=f"{values_path.name}:securityContext.allowPrivilegeEscalation",
            remediation="Set securityContext.allowPrivilegeEscalation: false",
        ))

    if sc.get("readOnlyRootFilesystem") is not True:
        result.findings.append(HelmFinding(
            rule_id="HELM004",
            severity=Severity.MEDIUM,
            message="securityContext does not enforce read-only root filesystem",
            location=f"{values_path.name}:securityContext.readOnlyRootFilesystem",
            remediation="Set securityContext.readOnlyRootFilesystem: true",
        ))

    if sc.get("runAsNonRoot") is not True:
        result.findings.append(HelmFinding(
            rule_id="HELM005",
            severity=Severity.HIGH,
            message="securityContext does not enforce non-root execution",
            location=f"{values_path.name}:securityContext.runAsNonRoot",
            remediation="Set securityContext.runAsNonRoot: true and a non-zero runAsUser",
        ))

    # Pod-level: check if run-as user is 0
    run_as_user = pod_sc.get("runAsUser") or sc.get("runAsUser")
    if run_as_user == 0:
        result.findings.append(HelmFinding(
            rule_id="HELM006",
            severity=Severity.HIGH,
            message="runAsUser is explicitly set to 0 (root)",
            location=f"{values_path.name}:securityContext.runAsUser",
            remediation="Use a non-zero UID (e.g. 10001) for least-privilege execution",
        ))


def _check_resource_limits(
    values: dict[str, Any], result: HelmScanResult, values_path: Path
) -> None:
    """Check for missing resource limits."""
    resources = values.get("resources", {})
    if not isinstance(resources, dict):
        return

    limits = resources.get("limits", {})
    if not limits:
        result.findings.append(HelmFinding(
            rule_id="HELM007",
            severity=Severity.MEDIUM,
            message="No resource limits defined in values — containers may consume unbounded CPU/memory",
            location=f"{values_path.name}:resources.limits",
            remediation="Add resources.limits.memory and resources.limits.cpu",
        ))
        return

    if not limits.get("memory"):
        result.findings.append(HelmFinding(
            rule_id="HELM008",
            severity=Severity.MEDIUM,
            message="No memory limit defined",
            location=f"{values_path.name}:resources.limits.memory",
            remediation="Set resources.limits.memory (e.g. '256Mi')",
        ))

    if not limits.get("cpu"):
        result.findings.append(HelmFinding(
            rule_id="HELM009",
            severity=Severity.LOW,
            message="No CPU limit defined",
            location=f"{values_path.name}:resources.limits.cpu",
            remediation="Set resources.limits.cpu (e.g. '500m')",
        ))


def _check_service_account(
    values: dict[str, Any], result: HelmScanResult, values_path: Path
) -> None:
    """Check service account configuration."""
    sa = values.get("serviceAccount", {})
    if not isinstance(sa, dict):
        return

    # automountServiceAccountToken defaults to True in Kubernetes if not set
    if sa.get("automountServiceAccountToken") is not False:
        result.findings.append(HelmFinding(
            rule_id="HELM010",
            severity=Severity.MEDIUM,
            message="serviceAccount.automountServiceAccountToken is not explicitly false",
            location=f"{values_path.name}:serviceAccount.automountServiceAccountToken",
            remediation="Set serviceAccount.automountServiceAccountToken: false unless the pod needs API server access",
        ))


def _check_network_exposure(
    values: dict[str, Any], result: HelmScanResult, values_path: Path
) -> None:
    """Flag services exposed with LoadBalancer or NodePort types."""
    service = values.get("service", {})
    if not isinstance(service, dict):
        return

    svc_type = service.get("type", "ClusterIP")
    if svc_type == "LoadBalancer":
        result.findings.append(HelmFinding(
            rule_id="HELM011",
            severity=Severity.INFO,
            message="Service type is LoadBalancer — this creates a public cloud load balancer",
            location=f"{values_path.name}:service.type",
            remediation="Confirm external exposure is intentional; consider using an Ingress with TLS instead",
        ))
    elif svc_type == "NodePort":
        result.findings.append(HelmFinding(
            rule_id="HELM012",
            severity=Severity.INFO,
            message="Service type is NodePort — the service is reachable on all node IPs",
            location=f"{values_path.name}:service.type",
            remediation="Prefer ClusterIP + Ingress for external traffic; restrict NodePort range in cluster config",
        ))


def _check_hardcoded_credentials(
    values: dict[str, Any], result: HelmScanResult, values_path: Path
) -> None:
    """
    Scan values for keys that suggest embedded credentials.

    Checks key names matching password/secret/token/key patterns with
    non-empty string values that are not references to Secret objects.
    """
    _walk_for_credentials(values, "", result, values_path)


_CREDENTIAL_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api[_\-]?key|private[_\-]?key|access[_\-]?key)",
    re.IGNORECASE,
)

# Values that are clearly placeholder/empty — skip these
_SAFE_VALUES = {"", "changeme", "CHANGEME", "replace-me", "your-secret-here", None}


def _walk_for_credentials(
    obj: Any, path: str, result: HelmScanResult, values_path: Path
) -> None:
    """Recursively walk a values dict looking for credential-like key/value pairs."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            child_path = f"{path}.{key}" if path else key
            if _CREDENTIAL_KEY_RE.search(key) and isinstance(value, str):
                if value not in _SAFE_VALUES and len(value) > 0:
                    result.findings.append(HelmFinding(
                        rule_id="HELM013",
                        severity=Severity.CRITICAL,
                        message=f"Possible hardcoded credential at '{child_path}' — value appears to be a real secret",
                        location=f"{values_path.name}:{child_path}",
                        remediation=(
                            "Remove the value from values.yaml and inject it via a Kubernetes Secret, "
                            "external-secrets-operator, or Vault; never commit real credentials to version control"
                        ),
                    ))
            _walk_for_credentials(value, child_path, result, values_path)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _walk_for_credentials(item, f"{path}[{i}]", result, values_path)


# ---------------------------------------------------------------------------
# Template file checks
# ---------------------------------------------------------------------------

# Secrets baked directly into template YAML (not templated references)
_HARDCODED_SECRET_RE = re.compile(
    r"(?:password|secret|token|api.?key|private.?key)\s*:\s*(?!{{)[\"']?[A-Za-z0-9+/=]{8,}",
    re.IGNORECASE,
)


def _check_template_file(tmpl_path: Path, result: HelmScanResult) -> None:
    """
    Scan a raw template file for hardcoded secrets and other patterns.

    Templates may contain Go template syntax; we do not evaluate it.
    We only flag static literal values that look like real credentials.
    """
    try:
        text = tmpl_path.read_text(encoding="utf-8")
    except OSError:
        return

    for i, line in enumerate(text.splitlines(), start=1):
        if _HARDCODED_SECRET_RE.search(line):
            result.findings.append(HelmFinding(
                rule_id="HELM014",
                severity=Severity.CRITICAL,
                message=f"Possible hardcoded secret in template at line {i}",
                location=f"templates/{tmpl_path.name}:{i}",
                remediation=(
                    "Reference a Kubernetes Secret or use {{ .Values.<key> }} with the value "
                    "injected at deploy time via -f secrets.yaml (gitignored)"
                ),
            ))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load the first YAML document from a file, returning {} on error."""
    try:
        with path.open() as fh:
            data = yaml.safe_load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _read_chart_name(chart_yaml_path: Path) -> str:
    """Read chart name from Chart.yaml; return 'unknown' on failure."""
    if not chart_yaml_path.exists():
        return "unknown"
    data = _load_yaml(chart_yaml_path)
    return str(data.get("name", "unknown"))
