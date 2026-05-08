from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional


RULES: Dict[str, str] = {
    "SEC043": "Workloads must set securityContext.seccompProfile.type to RuntimeDefault or Localhost at pod-level or per-container.",
}


WORKLOAD_PODSPEC_PATHS = {
    "Pod": ["spec"],
    "Deployment": ["spec", "template", "spec"],
    "Job": ["spec", "template", "spec"],
    "CronJob": ["spec", "jobTemplate", "spec", "template", "spec"],
}


def _get_path(obj: Dict[str, Any], path: Iterable[str]) -> Optional[Dict[str, Any]]:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur if isinstance(cur, dict) else None


def _seccomp_type(sc: Optional[Dict[str, Any]]) -> Optional[str]:
    if not isinstance(sc, dict):
        return None
    seccomp = sc.get("seccompProfile")
    if not isinstance(seccomp, dict):
        return None
    sec_type = seccomp.get("type")
    return sec_type if isinstance(sec_type, str) else None


def _allowed_seccomp(sec_type: Optional[str]) -> bool:
    return sec_type in {"RuntimeDefault", "Localhost"}


def _check_sec043(doc: Dict[str, Any]) -> List[Dict[str, str]]:
    kind = doc.get("kind")
    if kind not in WORKLOAD_PODSPEC_PATHS:
        return []

    podspec = _get_path(doc, WORKLOAD_PODSPEC_PATHS[kind])
    if not isinstance(podspec, dict):
        return []

    pod_level_type = _seccomp_type(podspec.get("securityContext"))

    containers = []
    for field in ("containers", "initContainers", "ephemeralContainers"):
        value = podspec.get(field)
        if isinstance(value, list):
            containers.extend([c for c in value if isinstance(c, dict)])

    # If there are no containers, do not emit SEC043 here.
    if not containers:
        return []

    if _allowed_seccomp(pod_level_type):
        return []

    for c in containers:
        c_type = _seccomp_type(c.get("securityContext"))
        if not _allowed_seccomp(c_type):
            name = c.get("name", "<unnamed>")
            return [
                {
                    "id": "SEC043",
                    "message": f"Container '{name}' is missing seccompProfile.type RuntimeDefault/Localhost and no compliant pod-level default is set.",
                }
            ]

    return []


def validate_manifest_docs(docs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    for doc in docs:
        if isinstance(doc, dict):
            findings.extend(_check_sec043(doc))
    return findings
