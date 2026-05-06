from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass
class ValidationFinding:
    rule_id: str
    severity: str
    message: str
    path: str


RULES: Dict[str, Dict[str, str]] = {
    "SEC001": {"severity": "HIGH", "title": "Privileged containers must be disabled"},
    "SEC002": {"severity": "HIGH", "title": "Containers should not run as root"},
    "SEC003": {"severity": "MEDIUM", "title": "Read-only root filesystem should be enabled"},
    "SEC039": {
        "severity": "HIGH",
        "title": "Containers must set securityContext.allowPrivilegeEscalation=false",
    },
}


SUPPORTED_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}


def _workload_template_spec(resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = resource.get("kind")
    spec = resource.get("spec", {})

    if kind == "Pod":
        return spec
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}:
        return (((spec or {}).get("template") or {}).get("spec"))
    if kind == "CronJob":
        return (((((spec or {}).get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec"))
    return None


def _iter_containers(template_spec: Dict[str, Any]) -> Iterable[Tuple[str, int, Dict[str, Any]]]:
    for field in ("containers", "initContainers"):
        for idx, container in enumerate(template_spec.get(field, []) or []):
            if isinstance(container, dict):
                yield field, idx, container


def _check_sec039(resource: Dict[str, Any]) -> List[ValidationFinding]:
    findings: List[ValidationFinding] = []
    kind = resource.get("kind")
    if kind not in SUPPORTED_KINDS:
        return findings

    template_spec = _workload_template_spec(resource)
    if not isinstance(template_spec, dict):
        return findings

    for container_field, idx, container in _iter_containers(template_spec):
        sc = container.get("securityContext") or {}
        ape = sc.get("allowPrivilegeEscalation") if isinstance(sc, dict) else None
        if ape is not False:
            name = container.get("name", f"index-{idx}")
            findings.append(
                ValidationFinding(
                    rule_id="SEC039",
                    severity=RULES["SEC039"]["severity"],
                    message=(
                        f"{kind} {container_field} '{name}' must explicitly set "
                        "securityContext.allowPrivilegeEscalation: false"
                    ),
                    path=f"spec.{container_field}[{idx}].securityContext.allowPrivilegeEscalation",
                )
            )

    return findings


def validate_manifest_resource(resource: Dict[str, Any]) -> List[ValidationFinding]:
    findings: List[ValidationFinding] = []
    findings.extend(_check_sec039(resource))
    return findings
