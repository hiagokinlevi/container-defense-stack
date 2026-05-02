from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ValidationIssue:
    rule_id: str
    message: str
    resource_kind: str
    resource_name: str
    remediation: str


def _safe_get(d: Dict[str, Any], path: List[str], default=None):
    cur: Any = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def _pod_spec_and_meta(doc: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], str, str]:
    kind = str(doc.get("kind", ""))
    name = str(_safe_get(doc, ["metadata", "name"], "<unknown>"))

    if kind == "Pod":
        return doc.get("spec"), kind, name
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet", "ReplicationController"}:
        return _safe_get(doc, ["spec", "template", "spec"]), kind, name
    if kind == "CronJob":
        return _safe_get(doc, ["spec", "jobTemplate", "spec", "template", "spec"]), kind, name
    return None, kind, name


def _all_containers(pod_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    containers: List[Dict[str, Any]] = []
    for key in ("containers", "initContainers", "ephemeralContainers"):
        value = pod_spec.get(key, [])
        if isinstance(value, list):
            containers.extend([c for c in value if isinstance(c, dict)])
    return containers


def _seccomp_type_from_security_context(sc: Optional[Dict[str, Any]]) -> Optional[str]:
    if not isinstance(sc, dict):
        return None
    seccomp = sc.get("seccompProfile")
    if not isinstance(seccomp, dict):
        return None
    t = seccomp.get("type")
    return str(t) if t is not None else None


def validate_sec030(documents: List[Dict[str, Any]]) -> List[ValidationIssue]:
    """
    SEC030: Fail when neither pod-level nor container-level seccompProfile.type
    is effectively set to RuntimeDefault for every container in workload pod templates.
    """
    issues: List[ValidationIssue] = []

    for doc in documents:
        pod_spec, kind, name = _pod_spec_and_meta(doc)
        if pod_spec is None:
            continue

        pod_sc = pod_spec.get("securityContext", {}) if isinstance(pod_spec, dict) else {}
        pod_seccomp_type = _seccomp_type_from_security_context(pod_sc)

        offenders: List[str] = []
        for c in _all_containers(pod_spec):
            cname = str(c.get("name", "<unnamed>"))
            c_sc = c.get("securityContext", {}) if isinstance(c, dict) else {}
            c_seccomp_type = _seccomp_type_from_security_context(c_sc)

            effective = c_seccomp_type if c_seccomp_type is not None else pod_seccomp_type
            if effective != "RuntimeDefault":
                offenders.append(cname)

        if offenders:
            issues.append(
                ValidationIssue(
                    rule_id="SEC030",
                    message=(
                        f"{kind}/{name} has container(s) without effective seccompProfile.type=RuntimeDefault: "
                        + ", ".join(offenders)
                    ),
                    resource_kind=kind,
                    resource_name=name,
                    remediation=(
                        "Set spec.template.spec.securityContext.seccompProfile.type: RuntimeDefault "
                        f"(or spec.securityContext for Pod), and ensure any container-level override also uses RuntimeDefault."
                    ),
                )
            )

    return issues
