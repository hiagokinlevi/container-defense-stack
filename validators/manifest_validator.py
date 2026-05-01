from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class Finding:
    rule_id: str
    severity: str
    resource: str
    message: str


RULES: Dict[str, Dict[str, str]] = {
    "SEC001": {"severity": "HIGH", "title": "Privileged container enabled"},
    "SEC002": {"severity": "HIGH", "title": "Privilege escalation allowed"},
    "SEC003": {"severity": "MEDIUM", "title": "Capabilities not dropped"},
    "SEC004": {"severity": "HIGH", "title": "Host network enabled"},
    "SEC005": {"severity": "HIGH", "title": "Host PID enabled"},
    "SEC006": {"severity": "HIGH", "title": "Host IPC enabled"},
    "SEC007": {"severity": "MEDIUM", "title": "Image tag latest used"},
    "SEC008": {"severity": "MEDIUM", "title": "No resource limits"},
    "SEC009": {"severity": "MEDIUM", "title": "No resource requests"},
    "SEC010": {"severity": "HIGH", "title": "HostPath volume mounted"},
    "SEC011": {"severity": "MEDIUM", "title": "ServiceAccount token automount enabled"},
    "SEC012": {"severity": "MEDIUM", "title": "readOnlyRootFilesystem not true"},
    "SEC013": {"severity": "MEDIUM", "title": "Missing seccompProfile RuntimeDefault"},
    "SEC014": {"severity": "MEDIUM", "title": "allowPrivilegeEscalation not false"},
    "SEC015": {"severity": "LOW", "title": "No liveness/readiness probes configured"},
    "SEC024": {"severity": "HIGH", "title": "runAsNonRoot not explicitly true"},
}


WORKLOAD_KINDS = {"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"}


def _resource_name(doc: Dict[str, Any]) -> str:
    kind = doc.get("kind", "Unknown")
    name = ((doc.get("metadata") or {}).get("name")) or "unnamed"
    return f"{kind}/{name}"


def _pod_spec(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = doc.get("kind")
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"}:
        return ((spec.get("template") or {}).get("spec")) or {}
    if kind == "CronJob":
        return ((((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")) or {}
    return None


def _containers(pod_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    out.extend(pod_spec.get("containers") or [])
    out.extend(pod_spec.get("initContainers") or [])
    return out


def _check_sec024(doc: Dict[str, Any]) -> List[Finding]:
    if doc.get("kind") not in WORKLOAD_KINDS:
        return []

    pod_spec = _pod_spec(doc)
    if not pod_spec:
        return []

    findings: List[Finding] = []
    resource = _resource_name(doc)

    pod_sc = pod_spec.get("securityContext") or {}
    pod_ranr = pod_sc.get("runAsNonRoot")

    for c in _containers(pod_spec):
        c_name = c.get("name", "unnamed")
        c_sc = c.get("securityContext") or {}
        c_ranr = c_sc.get("runAsNonRoot")
        effective = c_ranr if c_ranr is not None else pod_ranr
        if effective is not True:
            findings.append(
                Finding(
                    rule_id="SEC024",
                    severity=RULES["SEC024"]["severity"],
                    resource=resource,
                    message=f"container '{c_name}' does not explicitly enforce runAsNonRoot=true at container or pod level",
                )
            )

    return findings


def validate_manifest(path: str) -> List[Finding]:
    findings: List[Finding] = []
    with open(path, "r", encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))

    for doc in docs:
        if not isinstance(doc, dict):
            continue
        findings.extend(_check_sec024(doc))

    findings.sort(key=lambda x: (x.rule_id, x.resource, x.message))
    return findings


def findings_to_json(findings: List[Finding]) -> str:
    return json.dumps([f.__dict__ for f in findings], indent=2)
