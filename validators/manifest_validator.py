from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set


@dataclass
class ValidationFinding:
    code: str
    message: str
    path: str
    severity: str = "high"


class ManifestValidator:
    """Kubernetes manifest validator."""

    def validate(self, manifest: Dict[str, Any]) -> List[ValidationFinding]:
        findings: List[ValidationFinding] = []

        pod_spec = self._extract_pod_spec(manifest)
        if not pod_spec:
            return findings

        findings.extend(self._check_sec033_readonly_config_secret_mounts(pod_spec))
        return findings

    def _extract_pod_spec(self, manifest: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        kind = manifest.get("kind")
        spec = manifest.get("spec", {})

        if kind == "Pod":
            return spec

        template = spec.get("template", {})
        return template.get("spec")

    def _config_secret_volume_names(self, pod_spec: Dict[str, Any]) -> Set[str]:
        names: Set[str] = set()
        for vol in pod_spec.get("volumes", []) or []:
            if not isinstance(vol, dict):
                continue
            name = vol.get("name")
            if not name:
                continue
            if "configMap" in vol or "secret" in vol:
                names.add(name)
        return names

    def _check_container_mounts(
        self,
        containers: List[Dict[str, Any]],
        volume_names: Set[str],
        container_type: str,
    ) -> List[ValidationFinding]:
        findings: List[ValidationFinding] = []
        for i, container in enumerate(containers or []):
            mounts = container.get("volumeMounts", []) or []
            cname = container.get("name", f"{container_type}-{i}")
            for j, mount in enumerate(mounts):
                if not isinstance(mount, dict):
                    continue
                vol_name = mount.get("name")
                if vol_name not in volume_names:
                    continue
                if mount.get("readOnly") is not True:
                    findings.append(
                        ValidationFinding(
                            code="SEC033",
                            severity="medium",
                            path=f"spec.{container_type}[{i}].volumeMounts[{j}]",
                            message=(
                                f"{container_type[:-1].capitalize()} '{cname}' mounts ConfigMap/Secret volume "
                                f"'{vol_name}' without readOnly: true"
                            ),
                        )
                    )
        return findings

    def _check_sec033_readonly_config_secret_mounts(
        self, pod_spec: Dict[str, Any]
    ) -> List[ValidationFinding]:
        target_volumes = self._config_secret_volume_names(pod_spec)
        if not target_volumes:
            return []

        findings: List[ValidationFinding] = []
        findings.extend(
            self._check_container_mounts(
                pod_spec.get("containers", []) or [],
                target_volumes,
                "containers",
            )
        )
        findings.extend(
            self._check_container_mounts(
                pod_spec.get("initContainers", []) or [],
                target_volumes,
                "initContainers",
            )
        )
        return findings
