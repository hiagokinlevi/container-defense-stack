from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ValidationIssue:
    rule_id: str
    message: str
    severity: str = "HIGH"
    resource_kind: str | None = None
    resource_name: str | None = None


RULES: dict[str, str] = {
    "SEC001": "Container must not run privileged",
    "SEC002": "Container must not allow privilege escalation",
    "SEC003": "Container should run as non-root",
    "SEC004": "Container should use read-only root filesystem",
    "SEC005": "Container should drop all capabilities",
    "SEC006": "Image tag should not be latest",
    "SEC007": "Resources requests/limits should be set",
    "SEC008": "Liveness/readiness probes should be configured",
    "SEC009": "Host networking should be avoided",
    "SEC010": "Host PID/IPC should be avoided",
    "SEC011": "HostPath mounts should be avoided",
    "SEC012": "ServiceAccount token automount should be disabled when not needed",
    "SEC013": "seccompProfile should be RuntimeDefault/Localhost",
    "SEC014": "NetworkPolicy default deny should exist",
    "SEC015": "Namespace should define baseline security labels",
    "SEC029": "Namespace must set pod-security.kubernetes.io/enforce label",
}


class ManifestValidator:
    def validate_file(self, path: str | Path) -> list[ValidationIssue]:
        with open(path, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
        return self.validate_documents(docs)

    def validate_documents(self, docs: list[dict[str, Any] | None]) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            kind = str(doc.get("kind", ""))
            metadata = doc.get("metadata") or {}
            name = metadata.get("name")

            if kind == "Namespace":
                labels = metadata.get("labels") or {}
                enforce = labels.get("pod-security.kubernetes.io/enforce")
                if not enforce:
                    issues.append(
                        ValidationIssue(
                            rule_id="SEC029",
                            message="Namespace is missing pod-security.kubernetes.io/enforce label",
                            severity="HIGH",
                            resource_kind=kind,
                            resource_name=name,
                        )
                    )
        return issues
