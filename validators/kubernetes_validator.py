from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ValidationIssue:
    rule_id: str
    message: str
    resource_kind: str
    resource_name: str


WORKLOAD_KINDS = {
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Job",
    "CronJob",
    "Pod",
}


RULES: Dict[str, Dict[str, str]] = {
    "SEC034": {
        "title": "Disable ServiceAccount token automount at Pod spec level",
        "severity": "medium",
        "description": "Workloads should set spec.template.spec.automountServiceAccountToken: false (or spec.automountServiceAccountToken for Pods) unless explicitly exempted.",
    }
}


def _metadata(doc: Dict[str, Any]) -> Dict[str, Any]:
    return doc.get("metadata") or {}


def _name(doc: Dict[str, Any]) -> str:
    return (_metadata(doc).get("name") or "<unknown>")


def _kind(doc: Dict[str, Any]) -> str:
    return doc.get("kind") or "<unknown>"


def _is_sec034_exempt(doc: Dict[str, Any]) -> bool:
    md = _metadata(doc)
    annotations = md.get("annotations") or {}
    labels = md.get("labels") or {}

    # Explicit exemption knobs (string values for YAML compatibility)
    for source in (annotations, labels):
        if str(source.get("container-defense-stack.io/sec034-exempt", "")).lower() == "true":
            return True
        if str(source.get("security.container-defense-stack.io/sec034-exempt", "")).lower() == "true":
            return True
    return False


def _pod_spec(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = _kind(doc)
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")
    return ((spec.get("template") or {}).get("spec"))


def validate_manifest_docs(docs: List[Dict[str, Any]]) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []

    for doc in docs:
        kind = _kind(doc)
        if kind not in WORKLOAD_KINDS:
            continue

        if _is_sec034_exempt(doc):
            continue

        pod_spec = _pod_spec(doc) or {}
        if pod_spec.get("automountServiceAccountToken") is not False:
            issues.append(
                ValidationIssue(
                    rule_id="SEC034",
                    message="Set automountServiceAccountToken: false at Pod spec level (or explicitly exempt SEC034).",
                    resource_kind=kind,
                    resource_name=_name(doc),
                )
            )

    return issues
