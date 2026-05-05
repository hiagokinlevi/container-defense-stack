from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class ValidationIssue:
    code: str
    message: str
    severity: str
    resource_kind: str
    resource_name: str
    path: str
    remediation: str


POD_TEMPLATE_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
DIRECT_POD_KIND = "Pod"


class KubernetesManifestValidator:
    def validate(self, docs: Iterable[Dict[str, Any]]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            issues.extend(self._check_sec038_missing_cpu_limits(doc))
        return issues

    def _metadata_name(self, doc: Dict[str, Any]) -> str:
        return str(doc.get("metadata", {}).get("name", "<unnamed>"))

    def _pod_spec(self, doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        kind = doc.get("kind")
        spec = doc.get("spec", {})
        if kind == DIRECT_POD_KIND:
            return spec if isinstance(spec, dict) else None
        if kind in POD_TEMPLATE_KINDS:
            if kind == "CronJob":
                return (
                    spec.get("jobTemplate", {})
                    .get("spec", {})
                    .get("template", {})
                    .get("spec", {})
                )
            return spec.get("template", {}).get("spec", {})
        return None

    def _iter_container_entries(self, pod_spec: Dict[str, Any]):
        for container_type in ("containers", "initContainers"):
            entries = pod_spec.get(container_type, [])
            if not isinstance(entries, list):
                continue
            for idx, container in enumerate(entries):
                if isinstance(container, dict):
                    yield container_type, idx, container

    def _check_sec038_missing_cpu_limits(self, doc: Dict[str, Any]) -> List[ValidationIssue]:
        kind = doc.get("kind")
        if kind not in POD_TEMPLATE_KINDS and kind != DIRECT_POD_KIND:
            return []

        pod_spec = self._pod_spec(doc)
        if not isinstance(pod_spec, dict):
            return []

        issues: List[ValidationIssue] = []
        name = self._metadata_name(doc)
        for container_type, idx, container in self._iter_container_entries(pod_spec):
            resources = container.get("resources", {}) if isinstance(container, dict) else {}
            limits = resources.get("limits", {}) if isinstance(resources, dict) else {}
            cpu_limit = limits.get("cpu") if isinstance(limits, dict) else None
            if cpu_limit in (None, ""):
                cname = str(container.get("name", f"{container_type}[{idx}]"))
                issues.append(
                    ValidationIssue(
                        code="SEC038",
                        message=(
                            f"{kind}/{name} {container_type} '{cname}' is missing resources.limits.cpu"
                        ),
                        severity="MEDIUM",
                        resource_kind=str(kind),
                        resource_name=name,
                        path=f"spec.{container_type}[{idx}].resources.limits.cpu",
                        remediation=(
                            "Set an explicit CPU limit for every container and initContainer, e.g. "
                            "resources: { requests: { cpu: '100m' }, limits: { cpu: '500m' } }, "
                            "to prevent noisy-neighbor CPU starvation and improve scheduling safety."
                        ),
                    )
                )
        return issues


# ----------------------------
# Minimal fixture-style tests
# ----------------------------

def test_sec038_fails_when_cpu_limit_missing_in_deployment_container_and_initcontainer():
    validator = KubernetesManifestValidator()
    docs = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "api"},
            "spec": {
                "template": {
                    "spec": {
                        "initContainers": [
                            {
                                "name": "init-db",
                                "image": "busybox",
                                "resources": {"limits": {"memory": "128Mi"}},
                            }
                        ],
                        "containers": [
                            {
                                "name": "app",
                                "image": "nginx",
                                "resources": {"requests": {"cpu": "100m"}},
                            }
                        ],
                    }
                }
            },
        }
    ]

    issues = validator.validate(docs)
    sec038 = [i for i in issues if i.code == "SEC038"]

    assert len(sec038) == 2
    assert "missing resources.limits.cpu" in sec038[0].message
    assert "noisy-neighbor CPU starvation" in sec038[0].remediation


def test_sec038_passes_when_cpu_limits_set_for_all_pod_containers():
    validator = KubernetesManifestValidator()
    docs = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "worker"},
            "spec": {
                "initContainers": [
                    {
                        "name": "bootstrap",
                        "image": "busybox",
                        "resources": {
                            "requests": {"cpu": "50m"},
                            "limits": {"cpu": "100m"},
                        },
                    }
                ],
                "containers": [
                    {
                        "name": "main",
                        "image": "alpine",
                        "resources": {
                            "requests": {"cpu": "100m"},
                            "limits": {"cpu": "250m"},
                        },
                    }
                ],
            },
        }
    ]

    issues = validator.validate(docs)
    assert not any(i.code == "SEC038" for i in issues)
