# SPDX-License-Identifier: CC-BY-4.0
# Cyber Port — Container Defense Stack
# Module: workload_identity_checker.py
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# Analyzes Kubernetes workload configurations for cloud identity and IAM
# misconfigurations: improper IRSA/Workload Identity bindings, overly
# permissive role grants, default ServiceAccount with cloud credentials,
# and missing audience restrictions.

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Cloud-provider environment variable names that indicate credential injection.
# Used by WID-001 and WID-004.
_CLOUD_ENV_VARS: frozenset = frozenset(
    {
        "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AZURE_CLIENT_ID",
        "AZURE_TENANT_ID",
        "AZURE_FEDERATED_TOKEN_FILE",
    }
)

# Substrings in an IAM role name / ARN that indicate overly broad AWS access.
_OVERLY_BROAD_ROLE_PATTERNS: tuple = (
    "admin",
    "fullaccess",
    "poweruser",
    "administratoraccess",
)

# Annotation keys for the three major cloud workload-identity mechanisms.
_IRSA_ANNOTATION = "eks.amazonaws.com/role-arn"
_GCP_WI_ANNOTATION = "iam.gke.io/gcp-service-account"
_AZURE_WI_ANNOTATION = "azure.workload.identity/client-id"

# Maximum risk score cap.
_MAX_RISK_SCORE = 100

# Check weights — severity and numeric weight for each check ID.
_CHECK_WEIGHTS: Dict[str, int] = {
    "WID-001": 25,
    "WID-002": 45,
    "WID-003": 45,
    "WID-004": 25,
    "WID-005": 15,
    "WID-006": 15,
    "WID-007": 15,
}

_CHECK_SEVERITIES: Dict[str, str] = {
    "WID-001": "HIGH",
    "WID-002": "CRITICAL",
    "WID-003": "CRITICAL",
    "WID-004": "HIGH",
    "WID-005": "MEDIUM",
    "WID-006": "MEDIUM",
    "WID-007": "MEDIUM",
}

_SUPPORTED_WORKLOAD_KINDS: frozenset[str] = frozenset(
    {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class WorkloadIdentityConfig:
    """Snapshot of identity-related fields for a single Kubernetes workload."""

    workload_name: str
    workload_kind: str  # "Deployment", "StatefulSet", "DaemonSet", "Pod"
    namespace: str
    service_account: str
    annotations: Dict[str, str]  # pod / SA annotations
    env_var_names: List[str]  # env var names across all containers
    projected_token_audiences: List[str]  # serviceAccountToken.audience values
    projected_token_expiry_seconds: Optional[int]  # expirationSeconds; None if absent


@dataclass
class WIDFinding:
    """A single security finding produced by a check."""

    check_id: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int


@dataclass
class WIDResult:
    """Aggregated findings for one workload."""

    workload_name: str
    workload_kind: str
    namespace: str
    findings: List[WIDFinding] = field(default_factory=list)
    risk_score: int = 0  # min(100, sum of weights for unique fired check IDs)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a plain-dict representation suitable for JSON serialisation."""
        return {
            "workload_name": self.workload_name,
            "workload_kind": self.workload_kind,
            "namespace": self.namespace,
            "risk_score": self.risk_score,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                }
                for f in self.findings
            ],
        }

    def summary(self) -> str:
        """One-line human-readable summary of the result."""
        count = len(self.findings)
        ids = ", ".join(f.check_id for f in self.findings) if self.findings else "none"
        return (
            f"{self.workload_kind}/{self.workload_name} "
            f"(ns={self.namespace}) — "
            f"risk_score={self.risk_score}, "
            f"findings={count} [{ids}]"
        )

    def by_severity(self) -> Dict[str, List[WIDFinding]]:
        """Group findings by severity label."""
        groups: Dict[str, List[WIDFinding]] = {}
        for f in self.findings:
            groups.setdefault(f.severity, []).append(f)
        return groups


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _has_cloud_env_var(env_var_names: List[str]) -> bool:
    """Return True if any name in *env_var_names* matches a cloud credential var."""
    upper = {v.upper() for v in env_var_names}
    return bool(upper & _CLOUD_ENV_VARS)


def _has_workload_identity_annotation(annotations: Dict[str, str]) -> bool:
    """Return True if any recognised workload-identity annotation is present."""
    return (
        _IRSA_ANNOTATION in annotations
        or _GCP_WI_ANNOTATION in annotations
        or _AZURE_WI_ANNOTATION in annotations
    )


def _make_finding(check_id: str, title: str, detail: str) -> WIDFinding:
    """Construct a WIDFinding from the global severity/weight tables."""
    return WIDFinding(
        check_id=check_id,
        severity=_CHECK_SEVERITIES[check_id],
        title=title,
        detail=detail,
        weight=_CHECK_WEIGHTS[check_id],
    )


def _compute_risk_score(findings: List[WIDFinding]) -> int:
    """Sum weights of unique check IDs, capped at _MAX_RISK_SCORE."""
    seen: set = set()
    total = 0
    for f in findings:
        if f.check_id not in seen:
            seen.add(f.check_id)
            total += f.weight
    return min(_MAX_RISK_SCORE, total)


def _extract_pod_metadata_and_spec(manifest: dict) -> tuple[dict, dict]:
    """Return pod-template metadata/spec for supported workload kinds."""
    kind = manifest.get("kind", "")
    spec = manifest.get("spec") or {}
    if kind == "Pod":
        return manifest.get("metadata") or {}, spec
    if kind == "CronJob":
        template = ((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}
    else:
        template = spec.get("template") or {}
    return template.get("metadata") or {}, template.get("spec") or {}


def _collect_env_var_names(pod_spec: dict) -> List[str]:
    """Collect env var names across init and app containers."""
    env_var_names: List[str] = []
    for group_name in ("initContainers", "containers"):
        for container in pod_spec.get(group_name) or []:
            if not isinstance(container, dict):
                continue
            for env_item in container.get("env") or []:
                if isinstance(env_item, dict) and env_item.get("name"):
                    env_var_names.append(str(env_item["name"]))
    return env_var_names


def _collect_projected_token_settings(pod_spec: dict) -> tuple[List[str], Optional[int]]:
    """Collect projected ServiceAccountToken audiences and max expiry."""
    audiences: List[str] = []
    expiry_seconds: List[int] = []
    for volume in pod_spec.get("volumes") or []:
        if not isinstance(volume, dict):
            continue
        projected = volume.get("projected")
        if not isinstance(projected, dict):
            continue
        for source in projected.get("sources") or []:
            if not isinstance(source, dict):
                continue
            token = source.get("serviceAccountToken")
            if not isinstance(token, dict):
                continue
            audience = token.get("audience")
            if audience is not None:
                audiences.append(str(audience))
            expiry = token.get("expirationSeconds")
            if expiry is not None:
                expiry_seconds.append(int(expiry))
    max_expiry = max(expiry_seconds) if expiry_seconds else None
    return audiences, max_expiry


def load_configs_from_manifests(manifests: List[dict]) -> List[WorkloadIdentityConfig]:
    """Build WorkloadIdentityConfig objects from Kubernetes YAML documents."""
    service_accounts: Dict[tuple[str, str], Dict[str, str]] = {}
    for manifest in manifests:
        if not isinstance(manifest, dict) or manifest.get("kind") != "ServiceAccount":
            continue
        metadata = manifest.get("metadata") or {}
        namespace = str(metadata.get("namespace") or "default")
        name = str(metadata.get("name") or "default")
        annotations = {
            str(key): str(value)
            for key, value in (metadata.get("annotations") or {}).items()
        }
        service_accounts[(namespace, name)] = annotations

    configs: List[WorkloadIdentityConfig] = []
    for manifest in manifests:
        if not isinstance(manifest, dict):
            continue
        kind = manifest.get("kind", "")
        if kind not in _SUPPORTED_WORKLOAD_KINDS:
            continue

        metadata = manifest.get("metadata") or {}
        pod_metadata, pod_spec = _extract_pod_metadata_and_spec(manifest)
        namespace = str(metadata.get("namespace") or "default")
        service_account = str(pod_spec.get("serviceAccountName") or "default")
        annotations: Dict[str, str] = {}
        annotations.update(service_accounts.get((namespace, service_account), {}))
        annotations.update(
            {
                str(key): str(value)
                for key, value in (pod_metadata.get("annotations") or {}).items()
            }
        )
        audiences, expiry = _collect_projected_token_settings(pod_spec)

        configs.append(
            WorkloadIdentityConfig(
                workload_name=str(metadata.get("name") or "unnamed"),
                workload_kind=str(kind),
                namespace=namespace,
                service_account=service_account,
                annotations=annotations,
                env_var_names=_collect_env_var_names(pod_spec),
                projected_token_audiences=audiences,
                projected_token_expiry_seconds=expiry,
            )
        )
    return configs


def load_configs_from_file(path: Path) -> List[WorkloadIdentityConfig]:
    """Load a multi-document Kubernetes YAML file into workload identity configs."""
    with path.open("r", encoding="utf-8") as handle:
        manifests = [doc for doc in yaml.safe_load_all(handle) if isinstance(doc, dict)]
    return load_configs_from_manifests(manifests)


# ---------------------------------------------------------------------------
# Individual check implementations
# ---------------------------------------------------------------------------


def _check_wid001(config: WorkloadIdentityConfig) -> Optional[WIDFinding]:
    """WID-001: Cloud env vars present but no workload-identity annotation."""
    if not _has_cloud_env_var(config.env_var_names):
        return None
    if _has_workload_identity_annotation(config.annotations):
        return None
    matched = sorted(
        {v.upper() for v in config.env_var_names} & _CLOUD_ENV_VARS
    )
    return _make_finding(
        "WID-001",
        "Cloud credential env vars without Workload Identity annotation",
        (
            f"Workload '{config.workload_name}' sets cloud-provider env vars "
            f"({', '.join(matched)}) but has no IRSA/GCP-WI/Azure-WI annotation. "
            "Credentials may be injected manually or via insecure means."
        ),
    )


def _check_wid002(config: WorkloadIdentityConfig) -> Optional[WIDFinding]:
    """WID-002: IRSA role ARN annotation suggests overly broad AWS access."""
    role_arn = config.annotations.get(_IRSA_ANNOTATION)
    if not role_arn:
        return None

    # Extract role name — the segment after the last '/' in the ARN resource.
    role_name = role_arn.split("/")[-1]
    role_arn_lower = role_arn.lower()
    role_name_lower = role_name.lower()

    # Check for wildcard resource in the ARN itself.
    overly_broad = "*" in role_arn
    # Check for well-known overly-permissive name substrings.
    if not overly_broad:
        for pattern in _OVERLY_BROAD_ROLE_PATTERNS:
            if pattern in role_name_lower or pattern in role_arn_lower:
                overly_broad = True
                break

    if not overly_broad:
        return None

    return _make_finding(
        "WID-002",
        "IRSA role ARN suggests overly broad AWS permissions",
        (
            f"Workload '{config.workload_name}' uses IRSA with role ARN "
            f"'{role_arn}'. The role name or ARN indicates overly permissive "
            "access (matches: Admin/FullAccess/PowerUser/AdministratorAccess or wildcard)."
        ),
    )


def _check_wid003(config: WorkloadIdentityConfig) -> Optional[WIDFinding]:
    """WID-003: GCP Workload Identity bound to owner/editor project role."""
    gcp_sa = config.annotations.get(_GCP_WI_ANNOTATION)
    if not gcp_sa:
        return None

    # Inspect all annotation values for dangerous GCP roles.
    dangerous_roles: List[str] = []
    for key, value in config.annotations.items():
        for role in ("roles/owner", "roles/editor"):
            if role in value:
                dangerous_roles.append(f"{key}={value!r}")
                break

    if not dangerous_roles:
        return None

    return _make_finding(
        "WID-003",
        "GCP Workload Identity bound to owner/editor project role",
        (
            f"Workload '{config.workload_name}' uses GCP Workload Identity "
            f"(SA: {gcp_sa}) and has annotations indicating project-level "
            f"owner/editor role grants: {'; '.join(dangerous_roles)}."
        ),
    )


def _check_wid004(config: WorkloadIdentityConfig) -> Optional[WIDFinding]:
    """WID-004: Default ServiceAccount combined with cloud credential env vars."""
    if config.service_account not in ("default", ""):
        return None
    if not _has_cloud_env_var(config.env_var_names):
        return None

    matched = sorted(
        {v.upper() for v in config.env_var_names} & _CLOUD_ENV_VARS
    )
    return _make_finding(
        "WID-004",
        "Default ServiceAccount used with cloud credential env vars",
        (
            f"Workload '{config.workload_name}' runs under the default "
            "ServiceAccount and exposes cloud-provider credential env vars "
            f"({', '.join(matched)}). Credentials should be scoped to a "
            "dedicated ServiceAccount with least-privilege Workload Identity."
        ),
    )


def _check_wid005(config: WorkloadIdentityConfig) -> Optional[WIDFinding]:
    """WID-005: Projected token volume missing a specific audience restriction."""
    # Only relevant when a workload-identity annotation is present.
    if not _has_workload_identity_annotation(config.annotations):
        return None

    audiences = config.projected_token_audiences
    if not audiences or "*" in audiences or "" in audiences:
        return _make_finding(
            "WID-005",
            "Workload Identity token volume lacks specific audience restriction",
            (
                f"Workload '{config.workload_name}' uses Workload Identity but "
                "the projected ServiceAccountToken volume has no specific "
                f"audience set (audiences={audiences!r}). Without a scoped "
                "audience the token is accepted by any service."
            ),
        )
    return None


def _check_wid007(config: WorkloadIdentityConfig) -> Optional[WIDFinding]:
    """WID-007: Projected token volume missing or excessive expirationSeconds."""
    # Only relevant when a workload-identity annotation is present.
    if not _has_workload_identity_annotation(config.annotations):
        return None

    expiry = config.projected_token_expiry_seconds
    if expiry is None or expiry > 86400:
        effective = expiry if expiry is not None else "not set"
        return _make_finding(
            "WID-007",
            "Projected ServiceAccountToken has no expiration or exceeds 24 hours",
            (
                f"Workload '{config.workload_name}' uses Workload Identity but "
                f"projected token expirationSeconds={effective}. "
                "Tokens should expire within 3600–86400 seconds to limit "
                "the blast radius of a leaked token."
            ),
        )
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check(config: WorkloadIdentityConfig) -> WIDResult:
    """Check a workload's identity configuration for security issues.

    Runs WID-001 through WID-005 and WID-007 against *config*.
    WID-006 (cross-workload shared ARN) is handled separately in
    :func:`check_many`.

    Returns a :class:`WIDResult` with all triggered findings and a
    capped risk score.
    """
    findings: List[WIDFinding] = []

    # Run each single-workload check and collect non-None findings.
    for checker in (
        _check_wid001,
        _check_wid002,
        _check_wid003,
        _check_wid004,
        _check_wid005,
        _check_wid007,
    ):
        result = checker(config)
        if result is not None:
            findings.append(result)

    return WIDResult(
        workload_name=config.workload_name,
        workload_kind=config.workload_kind,
        namespace=config.namespace,
        findings=findings,
        risk_score=_compute_risk_score(findings),
    )


def check_many(configs: List[WorkloadIdentityConfig]) -> List[WIDResult]:
    """Check multiple workloads, including cross-workload WID-006 analysis.

    Steps:
    1. Run :func:`check` for every config individually.
    2. Collect the annotation value used for identity (IRSA ARN or GCP/Azure
       annotation) from each config.
    3. Any annotation value shared by more than one workload triggers WID-006
       on all workloads that share it.
    4. Recalculate risk scores for workloads that received new findings.
    """
    # Step 1 — individual checks.
    results: List[WIDResult] = [check(cfg) for cfg in configs]

    # Step 2 — build a map: identity_annotation_value -> list of result indices.
    _annotation_keys = (_IRSA_ANNOTATION, _GCP_WI_ANNOTATION, _AZURE_WI_ANNOTATION)
    annotation_to_indices: Dict[str, List[int]] = {}

    for idx, cfg in enumerate(configs):
        for ann_key in _annotation_keys:
            ann_val = cfg.annotations.get(ann_key)
            if ann_val:
                annotation_to_indices.setdefault(ann_val, []).append(idx)
                break  # use the first matching annotation per workload

    # Step 3 — for each shared annotation value, add WID-006 to all sharers.
    for ann_val, indices in annotation_to_indices.items():
        if len(indices) < 2:
            continue  # not shared; no finding

        sharing_names = [configs[i].workload_name for i in indices]
        for idx in indices:
            cfg = configs[idx]
            finding = _make_finding(
                "WID-006",
                "Multiple workloads share the same cloud identity annotation",
                (
                    f"Workload '{cfg.workload_name}' shares annotation value "
                    f"'{ann_val}' with: "
                    f"{', '.join(n for n in sharing_names if n != cfg.workload_name)}. "
                    "Compromise of this identity affects all sharing workloads "
                    "(single point of failure)."
                ),
            )
            results[idx].findings.append(finding)

    # Step 4 — recalculate risk scores for all results (simpler than tracking
    # only changed ones and avoids stale scores).
    for result in results:
        result.risk_score = _compute_risk_score(result.findings)

    return results
