from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    remediation: str
    path: Optional[str] = None


RULES: Dict[str, Dict[str, str]] = {
    "SEC022": {
        "severity": "MEDIUM",
        "message": "Container root filesystem is writable (readOnlyRootFilesystem not set to true).",
        "remediation": "Set securityContext.readOnlyRootFilesystem: true on every container and initContainer to reduce tampering and persistence risk.",
    }
}


def _iter_podspec_containers(resource: Dict[str, Any]) -> List[tuple[str, int, Dict[str, Any]]]:
    kind = (resource or {}).get("kind")
    spec = (resource or {}).get("spec") or {}

    pod_spec = None
    if kind == "Pod":
        pod_spec = spec
    else:
        template = spec.get("template") or {}
        pod_spec = template.get("spec") or {}

    out: List[tuple[str, int, Dict[str, Any]]] = []
    for key in ("containers", "initContainers"):
        items = pod_spec.get(key) or []
        if isinstance(items, list):
            for i, c in enumerate(items):
                if isinstance(c, dict):
                    out.append((key, i, c))
    return out


def validate_manifest(resource: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []

    for section, idx, container in _iter_podspec_containers(resource):
        sc = container.get("securityContext") or {}
        if sc.get("readOnlyRootFilesystem") is not True:
            rule = RULES["SEC022"]
            name = container.get("name", f"{section}[{idx}]")
            findings.append(
                Finding(
                    rule_id="SEC022",
                    severity=rule["severity"],
                    message=f"{rule['message']} Container: {name}",
                    remediation=rule["remediation"],
                    path=f"spec.template.spec.{section}[{idx}].securityContext.readOnlyRootFilesystem",
                )
            )

    return findings
