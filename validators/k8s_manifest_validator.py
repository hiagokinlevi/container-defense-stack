from __future__ import annotations

from typing import Any, Dict, List


RULES: Dict[str, Dict[str, str]] = {
    "SEC031": {
        "id": "SEC031",
        "title": "hostPath volume usage is denied",
        "severity": "HIGH",
        "description": "hostPath volumes mount node filesystem paths directly into pods and can enable container escape or host tampering.",
        "remediation": "Replace hostPath with safer storage patterns such as ConfigMap, Secret, PersistentVolumeClaim, or emptyDir as appropriate.",
    }
}


WORKLOAD_KINDS_WITH_TEMPLATES = {
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Job",
    "CronJob",
}


def _pod_spec_from_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    kind = manifest.get("kind")
    spec = manifest.get("spec", {})

    if kind == "Pod":
        return spec if isinstance(spec, dict) else {}

    if kind in WORKLOAD_KINDS_WITH_TEMPLATES:
        template = spec.get("template", {}) if isinstance(spec, dict) else {}
        template_spec = template.get("spec", {}) if isinstance(template, dict) else {}
        return template_spec if isinstance(template_spec, dict) else {}

    return {}


def validate_manifest(manifest: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    pod_spec = _pod_spec_from_manifest(manifest)

    for volume in pod_spec.get("volumes", []) or []:
        if isinstance(volume, dict) and "hostPath" in volume:
            rule = RULES["SEC031"]
            findings.append(
                {
                    "rule_id": rule["id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "remediation": rule["remediation"],
                }
            )
            break

    return findings
