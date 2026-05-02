from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ValidationIssue:
    rule_id: str
    title: str
    message: str
    severity: str = "HIGH"
    resource: Optional[str] = None
    container: Optional[str] = None


RULES: Dict[str, Dict[str, str]] = {
    "SEC027": {
        "title": "Container must drop all Linux capabilities",
        "severity": "HIGH",
        "description": "Containers should explicitly set securityContext.capabilities.drop to include ALL.",
        "remediation": "Set securityContext.capabilities.drop: [\"ALL\"] for every container and initContainer.",
    }
}


class KubernetesValidator:
    def __init__(self) -> None:
        self.rules = RULES

    def validate_manifest(self, manifest: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        spec = self._extract_pod_spec(manifest)
        if not spec:
            return issues

        issues.extend(self._check_sec027(manifest, spec))
        return issues

    def _extract_pod_spec(self, manifest: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        kind = (manifest or {}).get("kind", "")
        if kind == "Pod":
            return manifest.get("spec")

        spec = (manifest or {}).get("spec", {})
        template = spec.get("template", {})
        return template.get("spec")

    def _check_sec027(self, manifest: Dict[str, Any], pod_spec: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        all_containers = []

        for c in pod_spec.get("containers", []) or []:
            all_containers.append(("container", c))
        for c in pod_spec.get("initContainers", []) or []:
            all_containers.append(("initContainer", c))

        for ctype, container in all_containers:
            name = container.get("name", "<unnamed>")
            security_context = container.get("securityContext") or {}
            capabilities = security_context.get("capabilities") or {}
            drop = capabilities.get("drop")

            has_all = isinstance(drop, list) and any(str(item).upper() == "ALL" for item in drop)
            if not has_all:
                rule = self.rules["SEC027"]
                issues.append(
                    ValidationIssue(
                        rule_id="SEC027",
                        title=rule["title"],
                        severity=rule["severity"],
                        resource=f"{manifest.get('kind', 'Unknown')}/{(manifest.get('metadata') or {}).get('name', '<unnamed>')}",
                        container=name,
                        message=(
                            f"{ctype} '{name}' is missing securityContext.capabilities.drop: ['ALL']. "
                            f"Remediation: {rule['remediation']}"
                        ),
                    )
                )

        return issues
