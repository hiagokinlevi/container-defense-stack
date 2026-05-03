from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass
class ValidationFinding:
    rule_id: str
    message: str
    resource_kind: str
    resource_name: str
    path: str


RULES_INDEX: Dict[str, str] = {
    "SEC032": "Container images must define imagePullPolicy; :latest requires Always, pinned tags allow IfNotPresent/Always.",
}


def _get(obj: Dict[str, Any], path: Iterable[str]) -> Optional[Any]:
    cur: Any = obj
    for part in path:
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _pod_spec_locations(resource: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    kind = (resource.get("kind") or "")
    out: List[Tuple[str, Dict[str, Any]]] = []

    if kind in {"Pod"}:
        spec = resource.get("spec")
        if isinstance(spec, dict):
            out.append(("spec", spec))
        return out

    if kind in {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}:
        spec = _get(resource, ["spec", "template", "spec"])
        if isinstance(spec, dict):
            out.append(("spec.template.spec", spec))
        return out

    if kind == "CronJob":
        spec = _get(resource, ["spec", "jobTemplate", "spec", "template", "spec"])
        if isinstance(spec, dict):
            out.append(("spec.jobTemplate.spec.template.spec", spec))
        return out

    return out


def _is_latest_or_implicit_latest(image: str) -> bool:
    if "@sha256:" in image:
        return False
    image_no_repo_digest = image.split("@", 1)[0]
    tail = image_no_repo_digest.rsplit("/", 1)[-1]
    if ":" not in tail:
        return True
    return image_no_repo_digest.endswith(":latest")


def _validate_sec032(resource: Dict[str, Any]) -> List[ValidationFinding]:
    findings: List[ValidationFinding] = []
    kind = resource.get("kind") or "Unknown"
    name = _get(resource, ["metadata", "name"]) or "unknown"

    for base_path, pod_spec in _pod_spec_locations(resource):
        for field in ("containers", "initContainers"):
            containers = pod_spec.get(field) or []
            if not isinstance(containers, list):
                continue
            for idx, c in enumerate(containers):
                if not isinstance(c, dict):
                    continue
                image = c.get("image") or ""
                policy = c.get("imagePullPolicy")
                c_name = c.get("name") or f"index-{idx}"
                c_path = f"{base_path}.{field}[{idx}]"

                if policy is None:
                    findings.append(
                        ValidationFinding(
                            rule_id="SEC032",
                            message=f"{field[:-1]} '{c_name}' is missing imagePullPolicy",
                            resource_kind=kind,
                            resource_name=name,
                            path=c_path,
                        )
                    )
                    continue

                if _is_latest_or_implicit_latest(image):
                    if policy != "Always":
                        findings.append(
                            ValidationFinding(
                                rule_id="SEC032",
                                message=f"{field[:-1]} '{c_name}' uses latest/implicit-latest image and must set imagePullPolicy=Always",
                                resource_kind=kind,
                                resource_name=name,
                                path=f"{c_path}.imagePullPolicy",
                            )
                        )
                else:
                    if policy not in {"IfNotPresent", "Always"}:
                        findings.append(
                            ValidationFinding(
                                rule_id="SEC032",
                                message=f"{field[:-1]} '{c_name}' uses pinned image and must set imagePullPolicy to IfNotPresent or Always",
                                resource_kind=kind,
                                resource_name=name,
                                path=f"{c_path}.imagePullPolicy",
                            )
                        )

    return findings


def validate_manifest_documents(documents: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    for doc in documents:
        for f in _validate_sec032(doc):
            findings.append(
                {
                    "rule_id": f.rule_id,
                    "message": f.message,
                    "resource_kind": f.resource_kind,
                    "resource_name": f.resource_name,
                    "path": f.path,
                    "rule": RULES_INDEX.get(f.rule_id, ""),
                }
            )
    return findings
