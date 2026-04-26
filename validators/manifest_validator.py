from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    kind: str
    name: str


RULES: Dict[str, Dict[str, str]] = {
    "SEC023": {
        "severity": "HIGH",
        "title": "Containers must define CPU/memory requests and limits",
    }
}


class ManifestValidator:
    def __init__(self) -> None:
        self.findings: List[Finding] = []

    def validate(self, manifest: Dict[str, Any]) -> List[Finding]:
        self.findings = []
        self._check_sec023_resources_required(manifest)
        return self.findings

    def _pod_spec_for_kind(self, manifest: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        kind = (manifest.get("kind") or "").lower()
        spec = manifest.get("spec") or {}

        if kind in {"deployment", "statefulset", "daemonset", "job"}:
            return ((spec.get("template") or {}).get("spec")) or {}
        if kind == "cronjob":
            return ((((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")) or {}
        if kind == "pod":
            return spec or {}
        return None

    def _check_sec023_resources_required(self, manifest: Dict[str, Any]) -> None:
        pod_spec = self._pod_spec_for_kind(manifest)
        if pod_spec is None:
            return

        kind = manifest.get("kind", "Unknown")
        name = ((manifest.get("metadata") or {}).get("name")) or "unknown"

        for c in pod_spec.get("containers") or []:
            cname = c.get("name") or "unnamed"
            resources = c.get("resources") or {}
            requests = resources.get("requests") or {}
            limits = resources.get("limits") or {}

            missing: List[str] = []
            if "cpu" not in requests:
                missing.append("requests.cpu")
            if "memory" not in requests:
                missing.append("requests.memory")
            if "cpu" not in limits:
                missing.append("limits.cpu")
            if "memory" not in limits:
                missing.append("limits.memory")

            if missing:
                self.findings.append(
                    Finding(
                        rule_id="SEC023",
                        severity=RULES["SEC023"]["severity"],
                        message=f"Container '{cname}' missing required resources: {', '.join(missing)}",
                        kind=kind,
                        name=name,
                    )
                )
