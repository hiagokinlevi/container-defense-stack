"""
Kubernetes manifest security validator.

Checks manifests for common misconfigurations and produces structured findings.
Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
import yaml


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ManifestFinding:
    rule_id: str
    severity: Severity
    message: str
    path: str  # dot-notation path to the offending field
    remediation: str


def validate_manifest(manifest_path: Path) -> list[ManifestFinding]:
    """
    Parse a YAML Kubernetes manifest and return a list of security findings.

    Args:
        manifest_path: Path to the YAML manifest file.

    Returns:
        List of ManifestFinding objects (empty if manifest is secure).
    """
    findings: list[ManifestFinding] = []

    with manifest_path.open() as fh:
        docs = list(yaml.safe_load_all(fh))

    for doc in docs:
        if not doc:
            continue
        kind = doc.get("kind", "")
        if kind in ("Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob", "Pod"):
            _check_workload(doc, findings)

    return findings


def _get_containers(doc: dict[str, Any]) -> list[dict]:
    """Extract container specs from any workload kind."""
    spec = doc.get("spec", {})
    if doc.get("kind") == "CronJob":
        spec = spec.get("jobTemplate", {}).get("spec", {})
    pod_spec = spec.get("template", {}).get("spec", {}) if doc.get("kind") != "Pod" else spec
    return pod_spec.get("containers", []) + pod_spec.get("initContainers", [])


def _check_workload(doc: dict[str, Any], findings: list[ManifestFinding]) -> None:
    """Run all security checks against a workload manifest."""
    containers = _get_containers(doc)
    name = doc.get("metadata", {}).get("name", "<unnamed>")

    for c in containers:
        cname = c.get("name", "<unnamed>")
        sc = c.get("securityContext", {})
        prefix = f"{name}.containers.{cname}"

        if sc.get("privileged") is True:
            findings.append(ManifestFinding(
                rule_id="SEC001",
                severity=Severity.CRITICAL,
                message=f"Container '{cname}' runs as privileged",
                path=f"{prefix}.securityContext.privileged",
                remediation="Set securityContext.privileged: false or remove the field",
            ))

        if sc.get("allowPrivilegeEscalation") is not False:
            findings.append(ManifestFinding(
                rule_id="SEC002",
                severity=Severity.HIGH,
                message=f"Container '{cname}' does not explicitly deny privilege escalation",
                path=f"{prefix}.securityContext.allowPrivilegeEscalation",
                remediation="Set securityContext.allowPrivilegeEscalation: false",
            ))

        if sc.get("readOnlyRootFilesystem") is not True:
            findings.append(ManifestFinding(
                rule_id="SEC003",
                severity=Severity.MEDIUM,
                message=f"Container '{cname}' root filesystem is writable",
                path=f"{prefix}.securityContext.readOnlyRootFilesystem",
                remediation="Set securityContext.readOnlyRootFilesystem: true and use emptyDir for writable paths",
            ))

        if sc.get("runAsNonRoot") is not True:
            findings.append(ManifestFinding(
                rule_id="SEC004",
                severity=Severity.HIGH,
                message=f"Container '{cname}' does not enforce non-root execution",
                path=f"{prefix}.securityContext.runAsNonRoot",
                remediation="Set securityContext.runAsNonRoot: true and runAsUser to a non-zero UID",
            ))

        caps = sc.get("capabilities", {})
        dropped = caps.get("drop", [])
        if "ALL" not in dropped:
            findings.append(ManifestFinding(
                rule_id="SEC005",
                severity=Severity.MEDIUM,
                message=f"Container '{cname}' does not drop all Linux capabilities",
                path=f"{prefix}.securityContext.capabilities.drop",
                remediation="Set securityContext.capabilities.drop: [ALL]",
            ))

        resources = c.get("resources", {})
        if not resources.get("limits", {}).get("memory"):
            findings.append(ManifestFinding(
                rule_id="SEC006",
                severity=Severity.LOW,
                message=f"Container '{cname}' has no memory limit",
                path=f"{prefix}.resources.limits.memory",
                remediation="Set resources.limits.memory to prevent resource exhaustion",
            ))

        if not resources.get("limits", {}).get("cpu"):
            findings.append(ManifestFinding(
                rule_id="SEC007",
                severity=Severity.LOW,
                message=f"Container '{cname}' has no CPU limit",
                path=f"{prefix}.resources.limits.cpu",
                remediation="Set resources.limits.cpu",
            ))

    # Pod-level checks
    spec = doc.get("spec", {})
    pod_spec = spec.get("template", {}).get("spec", {}) if doc.get("kind") != "Pod" else spec
    if pod_spec.get("automountServiceAccountToken") is not False:
        findings.append(ManifestFinding(
            rule_id="SEC008",
            severity=Severity.MEDIUM,
            message="Service account token auto-mounted (unnecessary for most workloads)",
            path=f"{name}.spec.template.spec.automountServiceAccountToken",
            remediation="Set automountServiceAccountToken: false unless the pod needs API access",
        ))
