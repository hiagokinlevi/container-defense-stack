from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ValidationIssue:
    rule_id: str
    message: str
    severity: str = "HIGH"
    path: Optional[str] = None


RULES: Dict[str, Dict[str, str]] = {
    "SEC001": {"title": "Disallow latest tag", "severity": "MEDIUM"},
    "SEC002": {"title": "Require non-root user", "severity": "HIGH"},
    "SEC003": {"title": "Require resource limits", "severity": "MEDIUM"},
    "SEC004": {"title": "Require resource requests", "severity": "MEDIUM"},
    "SEC005": {"title": "Disallow hostNetwork", "severity": "HIGH"},
    "SEC006": {"title": "Disallow hostPID", "severity": "HIGH"},
    "SEC007": {"title": "Disallow hostIPC", "severity": "HIGH"},
    "SEC008": {"title": "Disallow hostPath volumes", "severity": "HIGH"},
    "SEC009": {"title": "Require readOnlyRootFilesystem", "severity": "MEDIUM"},
    "SEC010": {"title": "Drop all Linux capabilities", "severity": "MEDIUM"},
    "SEC011": {"title": "Disallow privileged escalation", "severity": "HIGH"},
    "SEC012": {"title": "Require seccomp profile", "severity": "HIGH"},
    "SEC013": {"title": "Disallow default service account", "severity": "LOW"},
    "SEC014": {"title": "Require imagePullPolicy", "severity": "LOW"},
    "SEC015": {"title": "Require liveness/readiness probes", "severity": "LOW"},
    "SEC028": {"title": "Disallow privileged containers", "severity": "CRITICAL"},
}


def _pod_spec(doc: Dict[str, Any]) -> Dict[str, Any]:
    kind = (doc or {}).get("kind", "")
    spec = (doc or {}).get("spec", {}) or {}

    if kind in {"Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job"}:
        return ((spec.get("template") or {}).get("spec") or {})
    if kind == "CronJob":
        return ((((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {})
    return spec


def _iter_containers_with_paths(pod_spec: Dict[str, Any]):
    for section in ("containers", "initContainers"):
        items = pod_spec.get(section) or []
        if isinstance(items, list):
            for idx, container in enumerate(items):
                yield section, idx, (container or {})


def check_sec028_no_privileged_true(doc: Dict[str, Any]) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []
    pod_spec = _pod_spec(doc)

    for section, idx, container in _iter_containers_with_paths(pod_spec):
        sc = container.get("securityContext") or {}
        if sc.get("privileged") is True:
            name = container.get("name", f"{section}[{idx}]")
            issues.append(
                ValidationIssue(
                    rule_id="SEC028",
                    message=f"Container '{name}' sets securityContext.privileged=true",
                    severity=RULES["SEC028"]["severity"],
                    path=f"spec.{section}[{idx}].securityContext.privileged",
                )
            )

    return issues


def validate_manifest_dict(doc: Dict[str, Any]) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []
    issues.extend(check_sec028_no_privileged_true(doc))
    return issues
