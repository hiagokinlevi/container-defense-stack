from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List

import yaml


@dataclass
class ValidationIssue:
    rule_id: str
    severity: str
    message: str
    path: str = ""


LIKELY_SECRET_NAME_RE = re.compile(
    r"(password|passwd|pwd|secret|token|apikey|api_key|private[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)


def _is_pod_controller(kind: str) -> bool:
    return kind in {
        "Pod",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "ReplicaSet",
        "ReplicationController",
        "Job",
        "CronJob",
    }


def _pod_spec_for(doc: Dict[str, Any]) -> Dict[str, Any] | None:
    kind = doc.get("kind")
    if kind == "Pod":
        return doc.get("spec")
    if kind == "CronJob":
        return (
            doc.get("spec", {})
            .get("jobTemplate", {})
            .get("spec", {})
            .get("template", {})
            .get("spec")
        )
    return doc.get("spec", {}).get("template", {}).get("spec")


def _iter_containers(pod_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    containers: List[Dict[str, Any]] = []
    containers.extend(pod_spec.get("containers", []) or [])
    containers.extend(pod_spec.get("initContainers", []) or [])
    containers.extend(pod_spec.get("ephemeralContainers", []) or [])
    return containers


def validate_manifest_text(manifest_text: str) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []
    for doc_index, doc in enumerate(yaml.safe_load_all(manifest_text), start=1):
        if not isinstance(doc, dict):
            continue

        kind = doc.get("kind", "")
        if not _is_pod_controller(kind):
            continue

        pod_spec = _pod_spec_for(doc)
        if not isinstance(pod_spec, dict):
            continue

        # SEC016-A: likely secret literals in env.value instead of secretKeyRef
        for c_index, container in enumerate(_iter_containers(pod_spec), start=1):
            env_list = container.get("env", []) or []
            for e_index, env in enumerate(env_list, start=1):
                if not isinstance(env, dict):
                    continue
                name = str(env.get("name", ""))
                has_literal = "value" in env and env.get("value") is not None
                has_secret_ref = (
                    isinstance(env.get("valueFrom"), dict)
                    and isinstance(env.get("valueFrom", {}).get("secretKeyRef"), dict)
                )

                if has_literal and not has_secret_ref and LIKELY_SECRET_NAME_RE.search(name):
                    issues.append(
                        ValidationIssue(
                            rule_id="SEC016",
                            severity="HIGH",
                            message=(
                                f"Likely secret env var '{name}' uses literal value; "
                                "use valueFrom.secretKeyRef instead."
                            ),
                            path=f"doc[{doc_index}].spec.container[{c_index}].env[{e_index}]",
                        )
                    )

        # SEC016-B: secret volume mount should be readOnly
        secret_volume_names = {
            str(v.get("name"))
            for v in (pod_spec.get("volumes", []) or [])
            if isinstance(v, dict) and isinstance(v.get("secret"), dict)
        }

        if secret_volume_names:
            for c_index, container in enumerate(_iter_containers(pod_spec), start=1):
                for m_index, mount in enumerate(container.get("volumeMounts", []) or [], start=1):
                    if not isinstance(mount, dict):
                        continue
                    vname = str(mount.get("name", ""))
                    if vname in secret_volume_names and mount.get("readOnly") is not True:
                        issues.append(
                            ValidationIssue(
                                rule_id="SEC016",
                                severity="MEDIUM",
                                message=(
                                    f"Secret volume '{vname}' is mounted without readOnly: true."
                                ),
                                path=f"doc[{doc_index}].spec.container[{c_index}].volumeMounts[{m_index}]",
                            )
                        )

    return issues
