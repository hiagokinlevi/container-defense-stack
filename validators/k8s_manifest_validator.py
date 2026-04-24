from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class ValidationIssue:
    rule_id: str
    message: str
    resource_kind: str
    resource_name: str


class K8sManifestValidator:
    """Kubernetes manifest validator with security guardrails."""

    # Existing rules are assumed to exist in upstream codebase.
    # SEC017: hostPath usage restrictions.
    SEC017_ALLOWED_HOSTPATH_PREFIXES: Tuple[str, ...] = (
        "/var/lib/kubelet/pods",
        "/var/lib/containerd/io.containerd.metadata.v1.bolt",
        "/run/containerd",
    )

    def validate(self, manifest: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []

        kind = manifest.get("kind", "")
        metadata = manifest.get("metadata", {}) or {}
        name = metadata.get("name", "unknown")

        pod_spec = self._extract_pod_spec(manifest)
        if pod_spec:
            issues.extend(self._check_sec017_hostpath_restrictions(kind, name, pod_spec))

        return issues

    def _extract_pod_spec(self, manifest: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        kind = (manifest.get("kind") or "").lower()
        spec = manifest.get("spec") or {}

        if kind == "pod":
            return spec

        template = spec.get("template") or {}
        template_spec = template.get("spec")
        if isinstance(template_spec, dict):
            return template_spec

        return None

    def _check_sec017_hostpath_restrictions(
        self,
        kind: str,
        name: str,
        pod_spec: Dict[str, Any],
    ) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []

        volumes = pod_spec.get("volumes") or []
        containers = (pod_spec.get("containers") or []) + (pod_spec.get("initContainers") or [])

        hostpath_volumes: Dict[str, str] = {}
        for vol in volumes:
            if not isinstance(vol, dict):
                continue
            hp = vol.get("hostPath")
            if not isinstance(hp, dict):
                continue
            vol_name = vol.get("name")
            hp_path = hp.get("path", "")
            if vol_name:
                hostpath_volumes[vol_name] = hp_path

        if not hostpath_volumes:
            return issues

        # Rule 1: hostPath path must match allowlist prefixes
        for vol_name, hp_path in hostpath_volumes.items():
            if not any(str(hp_path).startswith(prefix) for prefix in self.SEC017_ALLOWED_HOSTPATH_PREFIXES):
                issues.append(
                    ValidationIssue(
                        rule_id="SEC017",
                        message=(
                            f"hostPath volume '{vol_name}' uses disallowed path '{hp_path}'. "
                            f"Allowed prefixes: {', '.join(self.SEC017_ALLOWED_HOSTPATH_PREFIXES)}"
                        ),
                        resource_kind=kind or "Unknown",
                        resource_name=name,
                    )
                )

        # Rule 2: any mounted hostPath volume must be mounted readOnly: true
        mounted_readonly_state: Dict[str, bool] = {}
        mounted_hostpath_names: Set[str] = set()

        for c in containers:
            if not isinstance(c, dict):
                continue
            for vm in c.get("volumeMounts") or []:
                if not isinstance(vm, dict):
                    continue
                mount_name = vm.get("name")
                if mount_name in hostpath_volumes:
                    mounted_hostpath_names.add(mount_name)
                    mounted_readonly_state[mount_name] = bool(vm.get("readOnly", False))

        for mount_name in mounted_hostpath_names:
            if not mounted_readonly_state.get(mount_name, False):
                issues.append(
                    ValidationIssue(
                        rule_id="SEC017",
                        message=(
                            f"hostPath volume '{mount_name}' must be mounted with readOnly: true"
                        ),
                        resource_kind=kind or "Unknown",
                        resource_name=name,
                    )
                )

        return issues
