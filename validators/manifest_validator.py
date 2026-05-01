from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

import yaml


@dataclass
class ValidationFinding:
    rule_id: str
    severity: str
    message: str
    remediation: str
    resource: str


class ManifestValidator:
    """Kubernetes manifest security validator."""

    def validate(self, content: str) -> List[ValidationFinding]:
        findings: List[ValidationFinding] = []
        docs = list(yaml.safe_load_all(content))

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind", "Unknown")
            name = (doc.get("metadata") or {}).get("name", "unknown")
            resource = f"{kind}/{name}"

            pod_spec = self._extract_pod_spec(doc)
            if pod_spec is None:
                continue

            findings.extend(self._check_sec026_host_namespace_sharing(pod_spec, resource))

        return findings

    def _extract_pod_spec(self, doc: Dict[str, Any]) -> Dict[str, Any] | None:
        kind = doc.get("kind")
        spec = doc.get("spec")
        if not isinstance(spec, dict):
            return None

        if kind == "Pod":
            return spec

        template = spec.get("template")
        if isinstance(template, dict):
            template_spec = template.get("spec")
            if isinstance(template_spec, dict):
                return template_spec

        return None

    def _check_sec026_host_namespace_sharing(
        self, pod_spec: Dict[str, Any], resource: str
    ) -> List[ValidationFinding]:
        findings: List[ValidationFinding] = []
        flags: List[Tuple[str, Any]] = [
            ("hostNetwork", pod_spec.get("hostNetwork", False)),
            ("hostPID", pod_spec.get("hostPID", False)),
            ("hostIPC", pod_spec.get("hostIPC", False)),
        ]

        for field, value in flags:
            if value is True:
                findings.append(
                    ValidationFinding(
                        rule_id="SEC026",
                        severity="HIGH",
                        message=f"{field} is enabled (true).",
                        remediation=(
                            f"Set spec.{field}: false by default and only enable it when explicitly justified "
                            "and documented for the workload."
                        ),
                        resource=resource,
                    )
                )

        return findings
