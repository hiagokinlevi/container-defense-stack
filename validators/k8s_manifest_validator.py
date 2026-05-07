from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ValidationIssue:
    rule_id: str
    message: str
    resource_kind: str
    resource_name: str


def _get_in(obj: Dict[str, Any], path: List[str]) -> Optional[Any]:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def _pod_spec_for_resource(resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = (resource.get("kind") or "").strip()
    if kind == "Pod":
        return _get_in(resource, ["spec"])
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}:
        return _get_in(resource, ["spec", "template", "spec"])
    if kind == "CronJob":
        return _get_in(resource, ["spec", "jobTemplate", "spec", "template", "spec"])
    return None


def _resource_name(resource: Dict[str, Any]) -> str:
    return (
        _get_in(resource, ["metadata", "name"])
        or _get_in(resource, ["metadata", "generateName"])
        or "<unknown>"
    )


def validate_sec042_termination_grace_period(resource: Dict[str, Any]) -> List[ValidationIssue]:
    """
    SEC042: Ensure terminationGracePeriodSeconds is explicitly set and >= 10.
    Applies to Pod specs in Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob.
    """
    pod_spec = _pod_spec_for_resource(resource)
    if pod_spec is None:
        return []

    value = pod_spec.get("terminationGracePeriodSeconds")
    kind = (resource.get("kind") or "<unknown>")
    name = _resource_name(resource)

    if value is None:
        return [
            ValidationIssue(
                rule_id="SEC042",
                message=(
                    "Pod spec missing terminationGracePeriodSeconds. "
                    "Set spec.terminationGracePeriodSeconds to at least 10 seconds "
                    "to allow graceful shutdown."
                ),
                resource_kind=kind,
                resource_name=name,
            )
        ]

    if not isinstance(value, int) or value < 10:
        return [
            ValidationIssue(
                rule_id="SEC042",
                message=(
                    "Unsafe terminationGracePeriodSeconds value detected. "
                    "Use an integer value >= 10 seconds for graceful termination."
                ),
                resource_kind=kind,
                resource_name=name,
            )
        ]

    return []


def validate_manifest(resources: List[Dict[str, Any]]) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []
    for resource in resources:
        issues.extend(validate_sec042_termination_grace_period(resource))
    return issues
