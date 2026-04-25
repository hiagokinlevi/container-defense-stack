from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    rule_id: str
    message: str
    kind: str
    name: str


RULES: Dict[str, str] = {
    "SEC020": "securityContext.seccompProfile.type must be RuntimeDefault",
}


def _as_list(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _pod_spec(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = (doc or {}).get("kind")
    spec = (doc or {}).get("spec", {})

    if kind == "Pod":
        return spec if isinstance(spec, dict) else None
    if kind in {"Deployment", "Job"}:
        tmpl = spec.get("template", {}) if isinstance(spec, dict) else {}
        return tmpl.get("spec") if isinstance(tmpl, dict) else None
    if kind == "CronJob":
        jt = spec.get("jobTemplate", {}) if isinstance(spec, dict) else {}
        jts = jt.get("spec", {}) if isinstance(jt, dict) else {}
        tmpl = jts.get("template", {}) if isinstance(jts, dict) else {}
        return tmpl.get("spec") if isinstance(tmpl, dict) else None
    return None


def _seccomp_type_from_obj(obj: Dict[str, Any]) -> Optional[str]:
    sc = obj.get("securityContext", {}) if isinstance(obj, dict) else {}
    if not isinstance(sc, dict):
        return None
    sp = sc.get("seccompProfile", {})
    if not isinstance(sp, dict):
        return None
    t = sp.get("type")
    return t if isinstance(t, str) else None


def _allow_localhost() -> bool:
    return os.getenv("K1N_ALLOW_LOCALHOST_SECCOMP", "false").lower() in {"1", "true", "yes", "on"}


def validate_sec020(doc: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    kind = (doc or {}).get("kind", "Unknown")
    meta = (doc or {}).get("metadata", {}) if isinstance((doc or {}).get("metadata", {}), dict) else {}
    name = meta.get("name", "unknown")

    pod_spec = _pod_spec(doc)
    if not isinstance(pod_spec, dict):
        return findings

    pod_level = _seccomp_type_from_obj(pod_spec)
    allow_localhost = _allow_localhost()

    def valid_type(value: Optional[str]) -> bool:
        if value == "RuntimeDefault":
            return True
        if allow_localhost and value == "Localhost":
            return True
        return False

    if not valid_type(pod_level):
        findings.append(
            Finding(
                rule_id="SEC020",
                message="Pod securityContext.seccompProfile.type must be RuntimeDefault"
                + (" (Localhost allowed by configuration)" if allow_localhost else ""),
                kind=kind,
                name=name,
            )
        )

    containers = _as_list(pod_spec.get("containers"))
    init_containers = _as_list(pod_spec.get("initContainers"))
    ephemeral = _as_list(pod_spec.get("ephemeralContainers"))

    for c in containers + init_containers + ephemeral:
        c_name = c.get("name", "unnamed")
        c_type = _seccomp_type_from_obj(c)
        effective = c_type or pod_level
        if not valid_type(effective):
            findings.append(
                Finding(
                    rule_id="SEC020",
                    message=f"Container '{c_name}' effective seccompProfile.type must be RuntimeDefault"
                    + (" (Localhost allowed by configuration)" if allow_localhost else ""),
                    kind=kind,
                    name=name,
                )
            )

    return findings


def validate_manifest(doc: Dict[str, Any]) -> List[Finding]:
    return validate_sec020(doc)
