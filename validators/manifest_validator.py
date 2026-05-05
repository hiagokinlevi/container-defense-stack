from __future__ import annotations

from typing import Any, Dict, List, Tuple


class ManifestValidator:
    """Kubernetes manifest security validator."""

    EXCEPTION_ANNOTATIONS = {
        "container-guard.io/exception-sec036": "SEC036",
        "security.container-guard.io/exception-sec036": "SEC036",
    }

    def validate(self, manifest: Dict[str, Any]) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []
        findings.extend(self._check_sec036_hostport_denied(manifest))
        return findings

    def _check_sec036_hostport_denied(self, manifest: Dict[str, Any]) -> List[Dict[str, str]]:
        """SEC036: Deny hostPort usage in Pod specs unless explicitly excepted by annotation.

        Rationale: hostPort binds container ports on node interfaces and increases attack surface.
        Remediation: expose workloads via ClusterIP Service/Ingress rather than host-level binding.
        """
        findings: List[Dict[str, str]] = []

        kind = (manifest.get("kind") or "").strip()
        metadata = manifest.get("metadata") or {}

        pod_spec, pod_metadata = self._extract_pod_spec_and_metadata(manifest)
        if not pod_spec:
            return findings

        if self._has_sec036_exception(metadata) or self._has_sec036_exception(pod_metadata):
            return findings

        containers = list(pod_spec.get("containers") or []) + list(pod_spec.get("initContainers") or [])
        for container in containers:
            cname = container.get("name", "<unnamed>")
            for port in container.get("ports") or []:
                host_port = port.get("hostPort", 0)
                try:
                    hp = int(host_port)
                except (TypeError, ValueError):
                    continue
                if hp > 0:
                    findings.append(
                        {
                            "id": "SEC036",
                            "severity": "HIGH",
                            "kind": kind or "Unknown",
                            "message": (
                                f"Container '{cname}' sets hostPort={hp}. Avoid host-level port binding; "
                                "prefer ClusterIP Service/Ingress exposure."
                            ),
                        }
                    )
        return findings

    def _extract_pod_spec_and_metadata(self, manifest: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        kind = (manifest.get("kind") or "").strip()
        spec = manifest.get("spec") or {}

        if kind == "Pod":
            return spec, manifest.get("metadata") or {}

        if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}:
            template = spec.get("template") or {}
            return template.get("spec") or {}, template.get("metadata") or {}

        if kind == "CronJob":
            template = (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {})
            return template.get("spec") or {}, template.get("metadata") or {}

        return {}, {}

    def _has_sec036_exception(self, metadata: Dict[str, Any]) -> bool:
        annotations = (metadata or {}).get("annotations") or {}
        for key, rule in self.EXCEPTION_ANNOTATIONS.items():
            if rule == "SEC036" and str(annotations.get(key, "")).strip().lower() in {"true", "1", "yes", "allow"}:
                return True
        return False
