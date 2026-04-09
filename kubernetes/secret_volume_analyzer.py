# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International License.
# https://creativecommons.org/licenses/by/4.0/
"""
Kubernetes Secret Volume & Secret Reference Security Analyzer
=============================================================
Analyzes Kubernetes pod manifests for risky secret usage patterns: volumes
mounted at dangerous paths, secrets exposed via environment variables, service
account token auto-mounting, shared secret volumes, and default service account
misuse.

Operates entirely offline on Python dicts / dataclass objects — no live
Kubernetes API calls are required.

Check IDs
----------
SV-001  Secret mounted as all env vars via envFrom        (MEDIUM,   w=15)
SV-002  Secret volume mounted at sensitive path           (HIGH,     w=25)
SV-003  Secret referenced in container command / args     (HIGH,     w=25)
SV-004  Service account token auto-mounted                (MEDIUM,   w=15)
SV-005  Secret volume shared across multiple containers   (MEDIUM,   w=15)
SV-006  Default service account used with secrets         (HIGH,     w=20)
SV-007  Secret volume at root or home directory           (CRITICAL, w=35)

Usage::

    from kubernetes.secret_volume_analyzer import (
        K8sSecretRef, K8sContainer, K8sPodSpec,
        SecretVolumeAnalyzer,
    )

    pod = K8sPodSpec(
        name="web",
        namespace="production",
        containers=[
            K8sContainer(
                name="app",
                image="nginx:latest",
                env_from_secrets=[K8sSecretRef(secret_name="db-creds")],
            )
        ],
        secret_volumes=[],
        service_account_name="web-sa",
        automount_service_account_token=False,
    )
    analyzer = SecretVolumeAnalyzer()
    result = analyzer.analyze(pod)
    print(result.summary())
    for finding in result.findings:
        print(finding.to_dict())
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Weight table — each check ID maps to its integer contribution to risk_score.
# risk_score = min(100, sum of weights for each *unique* fired check ID).
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "SV-001": 15,  # envFrom secret — all keys exposed as env vars
    "SV-002": 25,  # secret volume at sensitive path (/etc/, /root/, etc.)
    "SV-003": 25,  # secret value interpolated in command or args
    "SV-004": 15,  # service account token auto-mounted (default or explicit)
    "SV-005": 15,  # same secret shared across multiple containers
    "SV-006": 20,  # default service account combined with secret access
    "SV-007": 35,  # secret volume at root or home directory
}

# Paths whose prefix makes a secret-volume mount HIGH risk (SV-002).
_SENSITIVE_PATH_PREFIXES = (
    "/etc/",
    "/root/",
    "/proc/",
    "/sys/",
    "/var/run/",
)

# Regex matching secret/credential variable names interpolated in
# container command or args (SV-003).  Matches patterns like:
#   $SECRET_VALUE  ${DB_PASSWORD}  $(TOKEN)  $MY_CREDENTIAL
_SECRET_ARG_RE = re.compile(
    r"\$\{?\w*(SECRET|KEY|TOKEN|PASSWORD|PASSWD|CREDENTIAL)\w*\}?",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class K8sSecretRef:
    """
    Reference to a Kubernetes Secret (or a specific key within one).

    Attributes:
        secret_name: Name of the Kubernetes Secret resource.
        key:         Specific key inside the secret to expose, or None to
                     expose all keys (used with envFrom secretRef).
    """
    secret_name: str
    key:         Optional[str] = None  # None → all keys exposed

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "secret_name": self.secret_name,
            "key":         self.key,
        }


@dataclass
class K8sContainer:
    """
    Simplified representation of a Kubernetes container spec.

    Attributes:
        name:             Container name.
        image:            Container image reference.
        env_from_secrets: Secrets mounted as all env vars via envFrom
                          secretRef — exposes every key in the secret.
        env_secrets:      Individual secret keys exposed as named env vars
                          via env[].valueFrom.secretKeyRef.
        command:          Overridden container ENTRYPOINT tokens.
        args:             CMD tokens passed to the entrypoint.
    """
    name:             str
    image:            str
    env_from_secrets: List[K8sSecretRef] = field(default_factory=list)
    env_secrets:      List[K8sSecretRef] = field(default_factory=list)
    command:          List[str]          = field(default_factory=list)
    args:             List[str]          = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "name":             self.name,
            "image":            self.image,
            "env_from_secrets": [r.to_dict() for r in self.env_from_secrets],
            "env_secrets":      [r.to_dict() for r in self.env_secrets],
            "command":          list(self.command),
            "args":             list(self.args),
        }


@dataclass
class K8sPodSpec:
    """
    Simplified representation of a Kubernetes Pod (or Deployment's pod
    template) specification.

    Attributes:
        name:                           Pod / Deployment name used in findings.
        namespace:                      Kubernetes namespace.
        containers:                     List of container specs.
        secret_volumes:                 Volumes backed by Secrets; each dict
                                        must contain ``name``, ``mount_path``,
                                        and ``secret_name``.
        automount_service_account_token: Tri-state — True/False/None.
                                        None means the cluster default applies
                                        (True in Kubernetes < 1.24).
        service_account_name:           ServiceAccount used by the pod.
    """
    name:                            str
    containers:                      List[K8sContainer]
    secret_volumes:                  List[dict]
    namespace:                       str           = "default"
    automount_service_account_token: Optional[bool] = None
    service_account_name:            str           = "default"

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "name":                            self.name,
            "namespace":                       self.namespace,
            "containers":                      [c.to_dict() for c in self.containers],
            "secret_volumes":                  list(self.secret_volumes),
            "automount_service_account_token": self.automount_service_account_token,
            "service_account_name":            self.service_account_name,
        }


@dataclass
class SecretVolumeFinding:
    """
    A single secret-volume security finding.

    Attributes:
        check_id:        SV-XXX identifier.
        severity:        "CRITICAL", "HIGH", or "MEDIUM".
        pod_name:        Name of the analysed pod / deployment.
        namespace:       Kubernetes namespace of the pod.
        container_name:  Specific container involved, if applicable.
        secret_name:     Secret name involved, if applicable.
        mount_path:      Volume mount path involved, if applicable.
        message:         Human-readable description of the finding.
        recommendation:  Actionable remediation guidance.
    """
    check_id:        str
    severity:        str
    pod_name:        str
    namespace:       str
    container_name:  Optional[str] = None
    secret_name:     Optional[str] = None
    mount_path:      Optional[str] = None
    message:         str           = ""
    recommendation:  str           = ""

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "check_id":       self.check_id,
            "severity":       self.severity,
            "pod_name":       self.pod_name,
            "namespace":      self.namespace,
            "container_name": self.container_name,
            "secret_name":    self.secret_name,
            "mount_path":     self.mount_path,
            "message":        self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class SecretVolumeResult:
    """
    Aggregated result of a single pod-spec secret-volume analysis run.

    Attributes:
        findings:    All SecretVolumeFinding objects produced by the analysis.
        risk_score:  Integer 0–100 computed from unique fired check IDs.
    """
    findings:   List[SecretVolumeFinding] = field(default_factory=list)
    risk_score: int                        = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """
        Return a one-line human-readable summary.

        Example::
            "Secret Volume Analysis: 3 finding(s) | Risk Score: 65/100 | CRITICAL: 1, HIGH: 1, MEDIUM: 1"
        """
        by_sev = self.by_severity()
        parts = ", ".join(
            f"{sev}: {len(findings)}"
            for sev, findings in sorted(by_sev.items())
        )
        total = len(self.findings)
        return (
            f"Secret Volume Analysis: {total} finding(s) | "
            f"Risk Score: {self.risk_score}/100 | {parts}"
        )

    def by_severity(self) -> Dict[str, List[SecretVolumeFinding]]:
        """
        Return findings grouped by severity string.

        Returns a dict whose keys are the severity labels that appear in the
        findings list; an empty analysis returns an empty dict.
        """
        result: Dict[str, List[SecretVolumeFinding]] = {}
        for finding in self.findings:
            result.setdefault(finding.severity, []).append(finding)
        return result

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "risk_score": self.risk_score,
            "findings":   [f.to_dict() for f in self.findings],
            "summary":    self.summary(),
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class SecretVolumeAnalyzer:
    """
    Offline Kubernetes secret-volume security analyzer.

    Instantiate once and call :meth:`analyze` (or :meth:`analyze_many`) to
    evaluate one or more :class:`K8sPodSpec` objects.  No Kubernetes API
    connectivity is required.
    """

    # ------------------------------------------------------------------
    # SV-001: Secret mounted as all env vars (envFrom)
    # ------------------------------------------------------------------

    def _check_001(self, pod: K8sPodSpec) -> List[SecretVolumeFinding]:
        """
        Flag any container that uses ``envFrom`` with a SecretRef.
        This exposes every key in the secret as an environment variable;
        any process running in the container can read them via ``/proc/self/environ``
        or ``os.environ``.
        """
        findings: List[SecretVolumeFinding] = []
        for container in pod.containers:
            if not container.env_from_secrets:
                continue  # no envFrom secrets — safe
            # One finding per container per secret reference
            for ref in container.env_from_secrets:
                findings.append(SecretVolumeFinding(
                    check_id="SV-001",
                    severity="MEDIUM",
                    pod_name=pod.name,
                    namespace=pod.namespace,
                    container_name=container.name,
                    secret_name=ref.secret_name,
                    message=(
                        f"Container '{container.name}' in pod '{pod.name}' mounts "
                        f"all keys of Secret '{ref.secret_name}' as environment "
                        "variables via envFrom. Any process inside the container "
                        "can enumerate every secret key through the process "
                        "environment."
                    ),
                    recommendation=(
                        "Prefer mounting only the specific secret keys required "
                        "via env[].valueFrom.secretKeyRef, or use a projected "
                        "volume with a read-once file instead of env vars."
                    ),
                ))
        return findings

    # ------------------------------------------------------------------
    # SV-002: Secret volume mounted at sensitive path
    # ------------------------------------------------------------------

    def _check_002(self, pod: K8sPodSpec) -> List[SecretVolumeFinding]:
        """
        Flag secret volumes mounted under high-risk filesystem paths such as
        /etc/, /root/, /proc/, /sys/, or /var/run/.
        Mounting secrets here can interfere with system configuration, expose
        them to unrelated system tooling, or make them world-readable.
        """
        findings: List[SecretVolumeFinding] = []
        for vol in pod.secret_volumes:
            mount_path: str = vol.get("mount_path", "")
            secret_name: str = vol.get("secret_name", "")
            # Check SV-002 sensitive prefixes (exclude the exact paths caught
            # by SV-007; both checks may fire on the same volume, which is
            # intentional — they represent distinct risks).
            if any(mount_path.startswith(prefix) for prefix in _SENSITIVE_PATH_PREFIXES):
                findings.append(SecretVolumeFinding(
                    check_id="SV-002",
                    severity="HIGH",
                    pod_name=pod.name,
                    namespace=pod.namespace,
                    secret_name=secret_name,
                    mount_path=mount_path,
                    message=(
                        f"Pod '{pod.name}' mounts Secret '{secret_name}' at "
                        f"'{mount_path}', which is a sensitive system path. "
                        "Secrets placed under /etc/, /root/, /proc/, /sys/, or "
                        "/var/run/ may be accessed by unintended system processes "
                        "or override critical configuration files."
                    ),
                    recommendation=(
                        "Mount secrets at application-owned paths (e.g., "
                        "/app/secrets/ or /run/secrets/) that are not shared with "
                        "system processes. Use subPath mounts to avoid clobbering "
                        "existing directory contents."
                    ),
                ))
        return findings

    # ------------------------------------------------------------------
    # SV-003: Secret referenced in container command or args
    # ------------------------------------------------------------------

    def _check_003(self, pod: K8sPodSpec) -> List[SecretVolumeFinding]:
        """
        Flag containers that interpolate secret-like variable names directly
        into their command or args strings (e.g. ``--password=$DB_PASSWORD``).
        These values appear in ``/proc/<pid>/cmdline`` and are often logged by
        orchestration layers.
        """
        findings: List[SecretVolumeFinding] = []
        for container in pod.containers:
            all_tokens = list(container.command) + list(container.args)
            matched_tokens = [t for t in all_tokens if _SECRET_ARG_RE.search(t)]
            if not matched_tokens:
                continue
            findings.append(SecretVolumeFinding(
                check_id="SV-003",
                severity="HIGH",
                pod_name=pod.name,
                namespace=pod.namespace,
                container_name=container.name,
                message=(
                    f"Container '{container.name}' in pod '{pod.name}' references "
                    "secret-like variable(s) directly in command/args: "
                    f"{matched_tokens}. Command-line arguments are visible in "
                    "the process list (/proc/<pid>/cmdline) and may be captured "
                    "by orchestration logs."
                ),
                recommendation=(
                    "Pass secrets to containers via environment variables or "
                    "mounted secret files rather than interpolating them directly "
                    "into command/args. Use a wrapper entrypoint that reads "
                    "secrets at runtime if CLI arguments are unavoidable."
                ),
            ))
        return findings

    # ------------------------------------------------------------------
    # SV-004: Service account token auto-mounted
    # ------------------------------------------------------------------

    def _check_004(self, pod: K8sPodSpec) -> List[SecretVolumeFinding]:
        """
        Flag pods where the service account token is (or may be) auto-mounted.
        When ``automountServiceAccountToken`` is None the cluster default applies,
        which is True for Kubernetes < 1.24. When set to True it is explicit.
        In both cases the token is available at
        /var/run/secrets/kubernetes.io/serviceaccount/ and grants API access.
        """
        # Fire when the value is None (implicit default=True) or explicitly True
        if pod.automount_service_account_token is False:
            return []  # explicitly disabled — safe

        reason = (
            "is set to True (explicitly enabled)"
            if pod.automount_service_account_token is True
            else "is not set (defaults to True in Kubernetes < 1.24)"
        )
        return [SecretVolumeFinding(
            check_id="SV-004",
            severity="MEDIUM",
            pod_name=pod.name,
            namespace=pod.namespace,
            message=(
                f"Pod '{pod.name}' has automountServiceAccountToken which {reason}. "
                "The service account token is mounted at "
                "/var/run/secrets/kubernetes.io/serviceaccount/ and can be used "
                "by any process in the pod to authenticate to the Kubernetes API."
            ),
            recommendation=(
                "Set automountServiceAccountToken: false on the pod spec (or on "
                "the ServiceAccount) unless the workload explicitly needs to call "
                "the Kubernetes API. Use projected volumes with a short-lived "
                "bound token if API access is required."
            ),
        )]

    # ------------------------------------------------------------------
    # SV-005: Secret volume shared across multiple containers
    # ------------------------------------------------------------------

    def _check_005(self, pod: K8sPodSpec) -> List[SecretVolumeFinding]:
        """
        Flag pods where the same Secret name is referenced by more than one
        container.  Sharing a secret across containers violates the principle
        of least privilege — a compromised container can read secrets that
        were only intended for a sibling.
        """
        if len(pod.containers) < 2:
            return []  # cannot share if there's only one container

        # Build a map: secret_name → list of container names that reference it
        secret_to_containers: Dict[str, List[str]] = {}
        for container in pod.containers:
            # Collect all secret names referenced by this container
            referenced: set = set()
            for ref in container.env_from_secrets:
                referenced.add(ref.secret_name)
            for ref in container.env_secrets:
                referenced.add(ref.secret_name)
            for sname in referenced:
                secret_to_containers.setdefault(sname, []).append(container.name)

        findings: List[SecretVolumeFinding] = []
        for secret_name, container_names in secret_to_containers.items():
            if len(container_names) > 1:
                findings.append(SecretVolumeFinding(
                    check_id="SV-005",
                    severity="MEDIUM",
                    pod_name=pod.name,
                    namespace=pod.namespace,
                    secret_name=secret_name,
                    message=(
                        f"Secret '{secret_name}' in pod '{pod.name}' is referenced "
                        f"by {len(container_names)} containers: "
                        f"{container_names}. Sharing a secret across containers "
                        "means that a compromise of any one of them exposes the "
                        "secret to all others."
                    ),
                    recommendation=(
                        "Provision a separate secret (or secret key) per container "
                        "so that a breach of one container does not automatically "
                        "expose secrets intended for its siblings."
                    ),
                ))
        return findings

    # ------------------------------------------------------------------
    # SV-006: Default service account used with secrets
    # ------------------------------------------------------------------

    def _check_006(self, pod: K8sPodSpec) -> List[SecretVolumeFinding]:
        """
        Flag pods that use the 'default' ServiceAccount while also accessing
        secrets (via volumes or env vars).  The default SA has no RBAC
        restrictions applied by convention and is shared across all workloads
        in the namespace; granting it implicit secret access is high risk.
        """
        if pod.service_account_name != "default":
            return []  # dedicated SA — not this check's concern

        # Determine whether the pod references any secrets at all
        has_secret_volumes = len(pod.secret_volumes) > 0
        has_env_secrets = any(
            container.env_from_secrets or container.env_secrets
            for container in pod.containers
        )
        if not (has_secret_volumes or has_env_secrets):
            return []  # default SA but no secret access — not risky by this check

        return [SecretVolumeFinding(
            check_id="SV-006",
            severity="HIGH",
            pod_name=pod.name,
            namespace=pod.namespace,
            message=(
                f"Pod '{pod.name}' uses the 'default' ServiceAccount while "
                "accessing Kubernetes Secrets. The default ServiceAccount is "
                "shared by all workloads in the namespace that do not specify "
                "a dedicated account, making it an overly broad identity for "
                "any workload that handles sensitive credentials."
            ),
            recommendation=(
                "Create a dedicated ServiceAccount for this workload with only "
                "the permissions it requires. Set automountServiceAccountToken: "
                "false on the default ServiceAccount to prevent it from being "
                "used implicitly."
            ),
        )]

    # ------------------------------------------------------------------
    # SV-007: Secret volume at root or home directory
    # ------------------------------------------------------------------

    def _check_007(self, pod: K8sPodSpec) -> List[SecretVolumeFinding]:
        """
        Flag secret volumes mounted at the filesystem root ("/"), at "/root",
        or under any "/home/" path.  Mounting at these locations risks
        overwriting system binaries, shell configuration files, or user home
        directories, potentially enabling privilege escalation or data
        exfiltration.
        """
        findings: List[SecretVolumeFinding] = []
        for vol in pod.secret_volumes:
            mount_path: str = vol.get("mount_path", "")
            secret_name: str = vol.get("secret_name", "")
            # Match: exact "/" or "/root" or anything under "/home/"
            is_root_or_home = (
                mount_path == "/"
                or mount_path == "/root"
                or mount_path.startswith("/home/")
            )
            if is_root_or_home:
                findings.append(SecretVolumeFinding(
                    check_id="SV-007",
                    severity="CRITICAL",
                    pod_name=pod.name,
                    namespace=pod.namespace,
                    secret_name=secret_name,
                    mount_path=mount_path,
                    message=(
                        f"Pod '{pod.name}' mounts Secret '{secret_name}' at "
                        f"'{mount_path}', which is the root filesystem, the root "
                        "user's home directory, or a user home directory. This can "
                        "overwrite shell startup files, SSH keys, or system "
                        "binaries, enabling privilege escalation."
                    ),
                    recommendation=(
                        "Never mount secrets at '/', '/root', or '/home/*'. "
                        "Use an isolated application path such as /app/secrets/ "
                        "and ensure the directory is owned by the container's "
                        "non-root user."
                    ),
                ))
        return findings

    # ------------------------------------------------------------------
    # Core analysis engine
    # ------------------------------------------------------------------

    def _compute_risk_score(self, findings: List[SecretVolumeFinding]) -> int:
        """
        Compute risk_score = min(100, sum of weights for each *unique* fired
        check ID).  Each check ID contributes its weight at most once,
        regardless of how many individual findings it produced.
        """
        fired_ids = {f.check_id for f in findings}
        total = sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_ids)
        return min(100, total)

    def analyze(self, pod_spec: K8sPodSpec) -> SecretVolumeResult:
        """
        Run all secret-volume checks against the supplied pod spec.

        Parameters
        ----------
        pod_spec:
            A :class:`K8sPodSpec` representing the pod / deployment template
            to analyse.

        Returns
        -------
        SecretVolumeResult
            Aggregated result containing all findings and a risk score.
        """
        all_findings: List[SecretVolumeFinding] = []

        # Run each check and accumulate findings
        all_findings.extend(self._check_001(pod_spec))  # envFrom secrets
        all_findings.extend(self._check_002(pod_spec))  # sensitive mount paths
        all_findings.extend(self._check_003(pod_spec))  # secrets in cmd/args
        all_findings.extend(self._check_004(pod_spec))  # SA token auto-mount
        all_findings.extend(self._check_005(pod_spec))  # shared secrets
        all_findings.extend(self._check_006(pod_spec))  # default SA + secrets
        all_findings.extend(self._check_007(pod_spec))  # root/home mount path

        risk_score = self._compute_risk_score(all_findings)
        return SecretVolumeResult(findings=all_findings, risk_score=risk_score)

    def analyze_many(
        self,
        pod_specs: List[K8sPodSpec],
    ) -> List[SecretVolumeResult]:
        """
        Run :meth:`analyze` on a list of pod specs.

        Parameters
        ----------
        pod_specs:
            List of :class:`K8sPodSpec` objects to analyse.

        Returns
        -------
        List[SecretVolumeResult]
            One result per input pod spec, in the same order.
        """
        return [self.analyze(spec) for spec in pod_specs]
