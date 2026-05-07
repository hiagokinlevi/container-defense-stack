from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    resource: str


RULES: Dict[str, Dict[str, str]] = {
    "SEC041": {
        "severity": "HIGH",
        "title": "Unsafe hostNetwork usage",
        "description": "Flags workloads that enable spec.hostNetwork: true outside approved namespaces/exceptions.",
    }
}

ALLOWED_HOSTNETWORK_NAMESPACES = {
    "kube-system",
    "kube-public",
    "kube-node-lease",
}


def _kind_name(doc: Dict[str, Any]) -> str:
    kind = doc.get("kind", "Unknown")
    name = ((doc.get("metadata") or {}).get("name")) or "unnamed"
    ns = ((doc.get("metadata") or {}).get("namespace")) or "default"
    return f"{kind}/{ns}/{name}"


def _pod_spec(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = doc.get("kind")
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    template = spec.get("template") or {}
    return template.get("spec")


def _is_exception(doc: Dict[str, Any]) -> bool:
    metadata = doc.get("metadata") or {}
    ns = metadata.get("namespace", "default")
    if ns in ALLOWED_HOSTNETWORK_NAMESPACES:
        return True

    annotations = metadata.get("annotations") or {}
    if str(annotations.get("security.container-defense-stack.io/allow-hostnetwork", "")).lower() == "true":
        return True

    labels = metadata.get("labels") or {}
    if str(labels.get("security.container-defense-stack.io/allow-hostnetwork", "")).lower() == "true":
        return True

    return False


def validate_manifest(docs: List[Dict[str, Any]]) -> List[Finding]:
    findings: List[Finding] = []

    for doc in docs:
        pod_spec = _pod_spec(doc)
        if not pod_spec:
            continue

        if pod_spec.get("hostNetwork") is True and not _is_exception(doc):
            findings.append(
                Finding(
                    rule_id="SEC041",
                    severity=RULES["SEC041"]["severity"],
                    message="hostNetwork: true is not allowed unless explicitly approved for system namespaces or documented exceptions.",
                    resource=_kind_name(doc),
                )
            )

    return findings
