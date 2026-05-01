from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import yaml


@dataclass
class ValidationIssue:
    rule_id: str
    message: str
    severity: str = "HIGH"
    path: Optional[str] = None


RULES: Dict[str, Dict[str, str]] = {
    "SEC001": {
        "title": "Containers must not run as privileged",
        "severity": "CRITICAL",
    },
    "SEC002": {
        "title": "Containers must drop all capabilities",
        "severity": "HIGH",
    },
    "SEC003": {
        "title": "Containers should run as non-root",
        "severity": "HIGH",
    },
    "SEC004": {
        "title": "readOnlyRootFilesystem should be enabled",
        "severity": "MEDIUM",
    },
    "SEC005": {
        "title": "Host network should not be enabled",
        "severity": "HIGH",
    },
    "SEC025": {
        "title": "Containers must set securityContext.allowPrivilegeEscalation=false",
        "severity": "HIGH",
    },
}


class KubernetesValidator:
    def validate_manifest(self, manifest_text: str) -> List[ValidationIssue]:
        docs = [d for d in yaml.safe_load_all(manifest_text) if d]
        issues: List[ValidationIssue] = []
        for doc in docs:
            pod_spec = self._extract_pod_spec(doc)
            if not pod_spec:
                continue
            issues.extend(self._check_allow_privilege_escalation(pod_spec))
        return issues

    def _extract_pod_spec(self, obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        kind = (obj or {}).get("kind")
        spec = (obj or {}).get("spec", {})

        if kind in {"Pod"}:
            return spec

        template = spec.get("template", {})
        if isinstance(template, dict):
            tmpl_spec = template.get("spec")
            if isinstance(tmpl_spec, dict):
                return tmpl_spec

        return None

    def _check_allow_privilege_escalation(self, pod_spec: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []

        for field in ("containers", "initContainers"):
            entries = pod_spec.get(field, []) or []
            for idx, c in enumerate(entries):
                if not isinstance(c, dict):
                    continue
                sc = c.get("securityContext") or {}
                ape = sc.get("allowPrivilegeEscalation")
                if ape is not False:
                    name = c.get("name", f"index-{idx}")
                    issues.append(
                        ValidationIssue(
                            rule_id="SEC025",
                            message=(
                                f"{field}[{name}] missing securityContext.allowPrivilegeEscalation=false"
                            ),
                            severity=RULES["SEC025"]["severity"],
                            path=f"spec.{field}[{idx}].securityContext.allowPrivilegeEscalation",
                        )
                    )

        return issues
