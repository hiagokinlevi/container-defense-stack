from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class ValidationIssue:
    rule_id: str
    severity: str
    message: str
    resource_kind: str
    resource_name: str
    path: str
    remediation: str


RULES: Dict[str, Dict[str, str]] = {
    "SEC035": {
        "title": "Container memory limit required",
        "severity": "HIGH",
        "description": "All containers and initContainers must define resources.limits.memory.",
        "remediation": "Set resources.limits.memory for every container and initContainer to prevent memory overconsumption and node instability.",
    }
}


POD_SPEC_WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}


def _resource_meta(doc: Dict[str, Any]) -> Tuple[str, str]:
    kind = str(doc.get("kind") or "Unknown")
    name = str((doc.get("metadata") or {}).get("name") or "unknown")
    return kind, name


def _pod_spec(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = doc.get("kind")
    if kind == "Pod":
        return doc.get("spec")
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}:
        return (((doc.get("spec") or {}).get("template") or {}).get("spec"))
    if kind == "CronJob":
        return ((((doc.get("spec") or {}).get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")
    return None


def _has_memory_limit(container: Dict[str, Any]) -> bool:
    resources = container.get("resources") or {}
    limits = resources.get("limits") or {}
    memory = limits.get("memory")
    return memory is not None and str(memory).strip() != ""


def validate_manifest_documents(documents: List[Dict[str, Any]]) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []

    for doc in documents:
        kind, name = _resource_meta(doc)
        if kind not in POD_SPEC_WORKLOAD_KINDS:
            continue

        pod_spec = _pod_spec(doc) or {}

        containers = pod_spec.get("containers") or []
        for i, container in enumerate(containers):
            if not _has_memory_limit(container):
                cname = container.get("name") or f"index-{i}"
                issues.append(
                    ValidationIssue(
                        rule_id="SEC035",
                        severity=RULES["SEC035"]["severity"],
                        message=f"Container '{cname}' is missing resources.limits.memory.",
                        resource_kind=kind,
                        resource_name=name,
                        path=f"spec.template.spec.containers[{i}].resources.limits.memory" if kind != "Pod" else f"spec.containers[{i}].resources.limits.memory",
                        remediation=RULES["SEC035"]["remediation"],
                    )
                )

        init_containers = pod_spec.get("initContainers") or []
        for i, container in enumerate(init_containers):
            if not _has_memory_limit(container):
                cname = container.get("name") or f"index-{i}"
                issues.append(
                    ValidationIssue(
                        rule_id="SEC035",
                        severity=RULES["SEC035"]["severity"],
                        message=f"initContainer '{cname}' is missing resources.limits.memory.",
                        resource_kind=kind,
                        resource_name=name,
                        path=f"spec.template.spec.initContainers[{i}].resources.limits.memory" if kind != "Pod" else f"spec.initContainers[{i}].resources.limits.memory",
                        remediation=RULES["SEC035"]["remediation"],
                    )
                )

    return issues
