#!/usr/bin/env python3
"""Kubernetes manifest security validator.

Validates workload manifests against SEC001+ hardening checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


@dataclass
class Finding:
    rule_id: str
    message: str
    resource_kind: str
    resource_name: str


RULES: Dict[str, str] = {
    "SEC001": "Containers must not run privileged",
    "SEC002": "Containers should drop all capabilities",
    "SEC003": "Containers should run as non-root",
    "SEC004": "hostNetwork should not be enabled",
    "SEC005": "hostPID should not be enabled",
    "SEC006": "hostIPC should not be enabled",
    "SEC007": "Avoid hostPath mounts",
    "SEC008": "Disallow latest image tags",
    "SEC009": "Require resource limits",
    "SEC010": "Require resource requests",
    "SEC011": "Disallow automountServiceAccountToken by default",
    "SEC012": "Require seccomp profile",
    "SEC013": "Require allowPrivilegeEscalation=false",
    "SEC014": "Require readiness/liveness probes",
    "SEC015": "Require imagePullPolicy",
    "SEC019": "Require securityContext.readOnlyRootFilesystem=true",
}


def _obj_meta(obj: Dict[str, Any]) -> Tuple[str, str]:
    kind = obj.get("kind", "Unknown")
    name = obj.get("metadata", {}).get("name", "unknown")
    return kind, name


def _pod_spec(obj: Dict[str, Any]) -> Dict[str, Any]:
    kind = obj.get("kind")
    if kind == "Pod":
        return obj.get("spec", {})
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}:
        return obj.get("spec", {}).get("template", {}).get("spec", {})
    if kind == "CronJob":
        return (
            obj.get("spec", {})
            .get("jobTemplate", {})
            .get("spec", {})
            .get("template", {})
            .get("spec", {})
        )
    return {}


def _containers(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    return (spec.get("containers") or []) + (spec.get("initContainers") or [])


def _check_sec019(obj: Dict[str, Any]) -> List[Finding]:
    kind, name = _obj_meta(obj)
    if kind not in {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}:
        return []

    findings: List[Finding] = []
    for c in _containers(_pod_spec(obj)):
        ro_root = (c.get("securityContext") or {}).get("readOnlyRootFilesystem")
        if ro_root is not True:
            findings.append(
                Finding(
                    rule_id="SEC019",
                    resource_kind=kind,
                    resource_name=name,
                    message=(
                        f"Container '{c.get('name', 'unnamed')}' is missing "
                        "securityContext.readOnlyRootFilesystem: true"
                    ),
                )
            )
    return findings


def validate_manifest_obj(obj: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(_check_sec019(obj))
    return findings


SEC019_DOC = (
    "SEC019: Enforce immutable container root filesystems by setting "
    "securityContext.readOnlyRootFilesystem: true on every container (including initContainers). "
    "Rationale: writable roots increase tampering/persistence risk after compromise. "
    "Remediation: mount dedicated writable volumes (e.g., emptyDir/PVC) only where needed and keep / read-only."
)


if __name__ == "__main__":
    # Minimal fixture-style self-checks for SEC019.
    failing = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "fail-sec019"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "image": "nginx:1.25",
                            "securityContext": {"runAsNonRoot": True},
                        }
                    ]
                }
            }
        },
    }
    passing = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": "pass-sec019"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "worker",
                            "image": "busybox:1.36",
                            "securityContext": {"readOnlyRootFilesystem": True},
                        }
                    ],
                    "restartPolicy": "Never",
                }
            }
        },
    }

    assert any(f.rule_id == "SEC019" for f in validate_manifest_obj(failing))
    assert not any(f.rule_id == "SEC019" for f in validate_manifest_obj(passing))
