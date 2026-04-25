from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml


@dataclass
class Finding:
    rule_id: str
    message: str
    severity: str = "high"
    resource: Optional[str] = None


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    return []


def _iter_containers(spec: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    for section in ("containers", "initContainers", "ephemeralContainers"):
        for c in _as_list(spec.get(section)):
            if isinstance(c, dict):
                yield section, c


def _extract_pod_spec(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = str(doc.get("kind", ""))
    spec = doc.get("spec")
    if not isinstance(spec, dict):
        return None

    if kind in {"Pod"}:
        return spec

    template = spec.get("template")
    if isinstance(template, dict):
        t_spec = template.get("spec")
        if isinstance(t_spec, dict):
            return t_spec

    job_template = spec.get("jobTemplate")
    if isinstance(job_template, dict):
        jt_spec = job_template.get("spec")
        if isinstance(jt_spec, dict):
            jt_template = jt_spec.get("template")
            if isinstance(jt_template, dict):
                jt_t_spec = jt_template.get("spec")
                if isinstance(jt_t_spec, dict):
                    return jt_t_spec

    return None


def _is_digest_pinned(image: str) -> bool:
    return "@sha256:" in image


def _has_explicit_tag(image: str) -> bool:
    # If digest pinned, treat as immutable and valid.
    if _is_digest_pinned(image):
        return True

    # Strip registry/repository path and inspect final component.
    last = image.rsplit("/", 1)[-1]
    return ":" in last


def _tag_of(image: str) -> Optional[str]:
    if _is_digest_pinned(image):
        return None
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return None
    return last.rsplit(":", 1)[-1]


def _validate_sec018(doc: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    pod_spec = _extract_pod_spec(doc)
    if not pod_spec:
        return findings

    meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    resource_name = meta.get("name") if isinstance(meta, dict) else None

    for section, container in _iter_containers(pod_spec):
        image = container.get("image")
        name = container.get("name", "<unnamed>")
        if not isinstance(image, str) or not image.strip():
            continue

        image = image.strip()

        if _is_digest_pinned(image):
            continue

        if not _has_explicit_tag(image):
            findings.append(
                Finding(
                    rule_id="SEC018",
                    message=(
                        f"{section}.{name} uses image '{image}' without an explicit immutable tag; "
                        "use a fixed version tag or digest pin (@sha256:...)."
                    ),
                    severity="high",
                    resource=resource_name,
                )
            )
            continue

        tag = _tag_of(image)
        if tag and tag.lower() == "latest":
            findings.append(
                Finding(
                    rule_id="SEC018",
                    message=(
                        f"{section}.{name} uses mutable image tag ':latest' in '{image}'; "
                        "use a fixed version tag or digest pin (@sha256:...)."
                    ),
                    severity="high",
                    resource=resource_name,
                )
            )

    return findings


def validate_manifest(content: str) -> List[Dict[str, Any]]:
    findings: List[Finding] = []
    for doc in yaml.safe_load_all(content):
        if not isinstance(doc, dict):
            continue
        findings.extend(_validate_sec018(doc))

    return [
        {
            "rule_id": f.rule_id,
            "message": f.message,
            "severity": f.severity,
            "resource": f.resource,
        }
        for f in findings
    ]
