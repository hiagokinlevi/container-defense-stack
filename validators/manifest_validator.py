from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ValidationIssue:
    rule_id: str
    message: str
    severity: str
    path: str


class ManifestValidator:
    def __init__(self) -> None:
        self.rule_dispatch = {
            "SEC040": self._rule_sec040_capabilities_drop_all,
        }

    def validate(self, manifest: Dict[str, Any], enabled_rules: Optional[List[str]] = None) -> List[ValidationIssue]:
        rules = enabled_rules or list(self.rule_dispatch.keys())
        issues: List[ValidationIssue] = []
        for rule_id in rules:
            fn = self.rule_dispatch.get(rule_id)
            if fn:
                issues.extend(fn(manifest))
        return issues

    def _rule_sec040_capabilities_drop_all(self, manifest: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []

        spec = manifest.get("spec", {})
        template_spec = spec.get("template", {}).get("spec", {}) if isinstance(spec, dict) else {}
        pod_spec = template_spec or spec

        if not isinstance(pod_spec, dict):
            return issues

        pod_drop = self._extract_drop_list(pod_spec.get("securityContext"))

        for field in ("containers", "initContainers"):
            containers = pod_spec.get(field, []) or []
            if not isinstance(containers, list):
                continue

            for idx, container in enumerate(containers):
                if not isinstance(container, dict):
                    continue

                name = container.get("name", f"{field}[{idx}]")
                c_drop = self._extract_drop_list(container.get("securityContext"))

                effective_drop = c_drop if c_drop is not None else pod_drop
                if not effective_drop or "ALL" not in {str(v).upper() for v in effective_drop}:
                    issues.append(
                        ValidationIssue(
                            rule_id="SEC040",
                            severity="high",
                            path=f"spec.{field}[{idx}].securityContext.capabilities.drop",
                            message=(
                                f"{name}: missing explicit securityContext.capabilities.drop including 'ALL'."
                            ),
                        )
                    )

        return issues

    @staticmethod
    def _extract_drop_list(security_context: Any) -> Optional[List[Any]]:
        if not isinstance(security_context, dict):
            return None
        capabilities = security_context.get("capabilities")
        if not isinstance(capabilities, dict):
            return None
        drop = capabilities.get("drop")
        if isinstance(drop, list):
            return drop
        return None
