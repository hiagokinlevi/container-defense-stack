from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ValidationFinding:
    rule_id: str
    severity: str
    resource: str
    message: str
    remediation: str


RULES: Dict[str, Dict[str, str]] = {
    "SEC021": {
        "title": "Disable ServiceAccount token automount by default",
        "severity": "HIGH",
        "description": "Workloads should explicitly set automountServiceAccountToken: false at pod spec level unless Kubernetes API access is required.",
        "remediation": "Set spec.automountServiceAccountToken: false for Pod manifests, or spec.template.spec.automountServiceAccountToken: false for controller-managed pods (Deployment/StatefulSet/DaemonSet/Job/CronJob).",
    }
}


def _resource_name(doc: Dict[str, Any]) -> str:
    kind = doc.get("kind", "Unknown")
    name = (((doc.get("metadata") or {}).get("name")) or "<unnamed>")
    return f"{kind}/{name}"


def _pod_spec_for(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = doc.get("kind")
    spec = doc.get("spec") or {}

    if kind == "Pod":
        return spec if isinstance(spec, dict) else None

    if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet", "ReplicationController"}:
        tmpl = spec.get("template") or {}
        return (tmpl.get("spec") or {}) if isinstance(tmpl, dict) else None

    if kind == "CronJob":
        jt = (spec.get("jobTemplate") or {}).get("spec") or {}
        tmpl = (jt.get("template") or {})
        return (tmpl.get("spec") or {}) if isinstance(tmpl, dict) else None

    return None


def _check_sec021(doc: Dict[str, Any]) -> List[ValidationFinding]:
    supported = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
    kind = doc.get("kind")
    if kind not in supported:
        return []

    pod_spec = _pod_spec_for(doc) or {}
    value = pod_spec.get("automountServiceAccountToken", None)

    if value is False:
        return []

    return [
        ValidationFinding(
            rule_id="SEC021",
            severity=RULES["SEC021"]["severity"],
            resource=_resource_name(doc),
            message=(
                "automountServiceAccountToken is not explicitly set to false on the pod spec; "
                "default token mounting can enable token theft and lateral movement."
            ),
            remediation=RULES["SEC021"]["remediation"],
        )
    ]


def validate_manifest_documents(documents: List[Dict[str, Any]]) -> List[ValidationFinding]:
    findings: List[ValidationFinding] = []
    for doc in documents:
        if not isinstance(doc, dict) or not doc:
            continue
        findings.extend(_check_sec021(doc))
    return findings
