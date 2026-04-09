# Copyright 2024 hiagokinlevi
#
# Licensed under the Creative Commons Attribution 4.0 International License
# (CC BY 4.0). You may obtain a copy of the License at:
#   https://creativecommons.org/licenses/by/4.0/
#
# Unless required by applicable law or agreed to in writing, this work is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

"""
cis_benchmark_scanner.py
------------------------
CIS Kubernetes Benchmark compliance scanner.

Evaluates a Kubernetes cluster configuration against the CIS Kubernetes
Benchmark security guidelines — entirely offline, operating on plain Python
dataclass objects derived from cluster config files or API objects.

Supported CIS checks (v1.8):
    CIS-K8S-001  API server anonymous authentication enabled          CRITICAL
    CIS-K8S-002  Etcd data not encrypted at rest                      HIGH
    CIS-K8S-003  Kubelet read-only port enabled                       HIGH
    CIS-K8S-004  API server audit logging not configured              HIGH
    CIS-K8S-005  API server TLS not configured                        CRITICAL
    CIS-K8S-006  PodSecurity admission not enabled                    HIGH
    CIS-K8S-007  kube-system SA token auto-mounting                   MEDIUM

Usage:
    from shared.compliance.cis_benchmark_scanner import (
        ClusterConfig, APIServerConfig, EtcdConfig, KubeletConfig,
        CISBenchmarkScanner,
    )

    config = ClusterConfig(
        name="prod-cluster",
        api_server=APIServerConfig(anonymous_auth_enabled=False, ...),
        etcd=EtcdConfig(encryption_config_file="/etc/k8s/enc.yaml"),
        kubelet=KubeletConfig(read_only_port=0),
    )

    scanner = CISBenchmarkScanner()
    result  = scanner.scan(config)
    print(result.summary())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Per-check risk weights used to compute the overall risk score.
# risk_score = min(100, sum of weights for each unique fired check ID).
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "CIS-K8S-001": 45,  # CRITICAL — anonymous auth on API server
    "CIS-K8S-002": 25,  # HIGH     — etcd not encrypted at rest
    "CIS-K8S-003": 20,  # HIGH     — kubelet read-only port open
    "CIS-K8S-004": 20,  # HIGH     — audit logging not configured
    "CIS-K8S-005": 40,  # CRITICAL — API server TLS missing
    "CIS-K8S-006": 25,  # HIGH     — PodSecurity admission disabled
    "CIS-K8S-007": 15,  # MEDIUM   — kube-system SA automount enabled
}

# ---------------------------------------------------------------------------
# Config dataclasses
# ---------------------------------------------------------------------------


@dataclass
class APIServerConfig:
    """Represents the security-relevant flags for the kube-apiserver process."""

    # Whether --anonymous-auth is enabled (CIS 1.2.1 requires it disabled).
    anonymous_auth_enabled: bool = False

    # Path to the TLS serving certificate (CIS 1.2.26).
    tls_cert_file: Optional[str] = None

    # Path to the TLS private key (CIS 1.2.26).
    tls_private_key_file: Optional[str] = None

    # Destination path for audit logs (CIS 3.2.1).
    audit_log_path: Optional[str] = None

    # Path to the audit policy manifest (CIS 3.2.2).
    audit_policy_file: Optional[str] = None

    # Authorization mode string, e.g. "RBAC", "Node,RBAC", "AlwaysAllow".
    authorization_mode: str = "RBAC"

    # Insecure HTTP port; 0 means disabled (CIS 1.2.18).
    insecure_port: int = 0

    # Whether the PodSecurity admission controller is active (CIS 5.2).
    pod_security_admission_enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict for JSON output or logging."""
        return {
            "anonymous_auth_enabled": self.anonymous_auth_enabled,
            "tls_cert_file": self.tls_cert_file,
            "tls_private_key_file": self.tls_private_key_file,
            "audit_log_path": self.audit_log_path,
            "audit_policy_file": self.audit_policy_file,
            "authorization_mode": self.authorization_mode,
            "insecure_port": self.insecure_port,
            "pod_security_admission_enabled": self.pod_security_admission_enabled,
        }


@dataclass
class EtcdConfig:
    """Represents security settings for the etcd key-value store."""

    # Path to an EncryptionConfiguration manifest; None means no encryption (CIS 1.2.31).
    encryption_config_file: Optional[str] = None

    # Path to the etcd TLS client certificate.
    tls_cert_file: Optional[str] = None

    # Path to the etcd TLS private key.
    tls_key_file: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "encryption_config_file": self.encryption_config_file,
            "tls_cert_file": self.tls_cert_file,
            "tls_key_file": self.tls_key_file,
        }


@dataclass
class KubeletConfig:
    """Represents the security-relevant kubelet configuration flags."""

    # Read-only port; 0 = disabled (CIS 4.2.4 requires 0).
    read_only_port: int = 0

    # Whether anonymous requests to the Kubelet API are allowed (CIS 4.2.1).
    anonymous_auth_enabled: bool = False

    # Kubelet authorization mode; "Webhook" delegates to the API server (CIS 4.2.2).
    authorization_mode: str = "Webhook"

    # Whether kubelet rotates client certificates automatically (CIS 4.2.11).
    rotate_certificates: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "read_only_port": self.read_only_port,
            "anonymous_auth_enabled": self.anonymous_auth_enabled,
            "authorization_mode": self.authorization_mode,
            "rotate_certificates": self.rotate_certificates,
        }


@dataclass
class ClusterConfig:
    """Top-level cluster configuration aggregating all component configs."""

    # Human-readable cluster identifier (used in reports and logs).
    name: str

    # Configuration for the kube-apiserver.
    api_server: APIServerConfig = field(default_factory=APIServerConfig)

    # Configuration for etcd.
    etcd: EtcdConfig = field(default_factory=EtcdConfig)

    # Configuration for the kubelet.
    kubelet: KubeletConfig = field(default_factory=KubeletConfig)

    # Whether service account tokens are auto-mounted in kube-system (CIS 5.1.5).
    kube_system_sa_automount: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "api_server": self.api_server.to_dict(),
            "etcd": self.etcd.to_dict(),
            "kubelet": self.kubelet.to_dict(),
            "kube_system_sa_automount": self.kube_system_sa_automount,
        }


# ---------------------------------------------------------------------------
# Finding / result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class CISFinding:
    """A single CIS benchmark violation detected during a scan."""

    # Canonical check identifier, e.g. "CIS-K8S-001".
    check_id: str

    # CIS Benchmark section reference, e.g. "CIS 1.2.1".
    cis_reference: str

    # Severity level: "CRITICAL", "HIGH", or "MEDIUM".
    severity: str

    # Short human-readable title for the finding.
    title: str

    # Detailed description of what was detected.
    message: str

    # Concrete remediation steps for the operator.
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "cis_reference": self.cis_reference,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "remediation": self.remediation,
        }


@dataclass
class CISBenchmarkResult:
    """Aggregated result of a CIS benchmark scan for a single cluster."""

    # Cluster name, copied from ClusterConfig for traceability.
    cluster_name: str

    # All policy violations found during the scan.
    findings: List[CISFinding] = field(default_factory=list)

    # Weighted risk score in the range [0, 100].
    risk_score: int = 0

    # ---------------------------------------------------------------------------
    # Derived property: compliance_score is always computed from risk_score so
    # that the two values stay in sync even when findings change after creation.
    # ---------------------------------------------------------------------------

    @property
    def compliance_score(self) -> int:
        """Inverse of risk_score; clamped to [0, 100]."""
        return max(0, 100 - self.risk_score)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a one-line human-readable summary of the scan result."""
        total = len(self.findings)
        by_sev = self.by_severity()
        critical = by_sev.get("CRITICAL", [])
        high = by_sev.get("HIGH", [])
        medium = by_sev.get("MEDIUM", [])
        return (
            f"Cluster '{self.cluster_name}': {total} finding(s) — "
            f"CRITICAL={len(critical)}, HIGH={len(high)}, MEDIUM={len(medium)} | "
            f"risk_score={self.risk_score}/100, compliance_score={self.compliance_score}/100"
        )

    def by_severity(self) -> Dict[str, List[CISFinding]]:
        """Group findings by severity label and return as a dict of lists."""
        result: Dict[str, List[CISFinding]] = {}
        for finding in self.findings:
            result.setdefault(finding.severity, []).append(finding)
        return result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_name": self.cluster_name,
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "compliance_score": self.compliance_score,
            "summary": self.summary(),
        }


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class CISBenchmarkScanner:
    """
    Offline CIS Kubernetes Benchmark compliance scanner.

    Evaluates a ClusterConfig against 7 CIS checks and returns a
    CISBenchmarkResult with findings, a weighted risk score, and a
    derived compliance score.

    All checks are deterministic and stateless — no network or filesystem
    access is required.
    """

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def scan(self, cluster: ClusterConfig) -> CISBenchmarkResult:
        """
        Scan a single ClusterConfig and return a CISBenchmarkResult.

        Args:
            cluster: The cluster configuration to evaluate.

        Returns:
            A CISBenchmarkResult containing all detected findings and
            computed risk / compliance scores.
        """
        findings: List[CISFinding] = []

        # Run every check; each appends a CISFinding on violation.
        self._check_001_anonymous_auth(cluster, findings)
        self._check_002_etcd_encryption(cluster, findings)
        self._check_003_kubelet_readonly_port(cluster, findings)
        self._check_004_audit_logging(cluster, findings)
        self._check_005_api_server_tls(cluster, findings)
        self._check_006_pod_security_admission(cluster, findings)
        self._check_007_kube_system_sa_automount(cluster, findings)

        # Compute risk score: sum weights for each unique fired check ID,
        # capped at 100 to keep the scale bounded.
        fired_ids = {f.check_id for f in findings}
        raw_score = sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_ids)
        risk_score = min(100, raw_score)

        return CISBenchmarkResult(
            cluster_name=cluster.name,
            findings=findings,
            risk_score=risk_score,
        )

    def scan_many(self, clusters: List[ClusterConfig]) -> List[CISBenchmarkResult]:
        """
        Scan a list of ClusterConfig objects.

        Args:
            clusters: Iterable of cluster configurations to evaluate.

        Returns:
            A list of CISBenchmarkResult objects in the same order as input.
        """
        return [self.scan(c) for c in clusters]

    # ------------------------------------------------------------------
    # Individual CIS checks (private)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_001_anonymous_auth(
        cluster: ClusterConfig, findings: List[CISFinding]
    ) -> None:
        """CIS 1.2.1 — Disable anonymous-auth on the API server."""
        if cluster.api_server.anonymous_auth_enabled:
            findings.append(
                CISFinding(
                    check_id="CIS-K8S-001",
                    cis_reference="CIS 1.2.1",
                    severity="CRITICAL",
                    title="API server anonymous authentication enabled",
                    message=(
                        "The kube-apiserver is configured with --anonymous-auth=true. "
                        "Unauthenticated requests are served, potentially exposing "
                        "sensitive cluster APIs to unauthorized callers."
                    ),
                    remediation=(
                        "Set --anonymous-auth=false in the kube-apiserver manifest "
                        "or configuration file and restart the API server. Verify "
                        "no existing clients rely on anonymous access before making "
                        "this change."
                    ),
                )
            )

    @staticmethod
    def _check_002_etcd_encryption(
        cluster: ClusterConfig, findings: List[CISFinding]
    ) -> None:
        """CIS 1.2.31 — Encrypt etcd data at rest."""
        enc = cluster.etcd.encryption_config_file
        if enc is None or enc == "":
            findings.append(
                CISFinding(
                    check_id="CIS-K8S-002",
                    cis_reference="CIS 1.2.31",
                    severity="HIGH",
                    title="Etcd data not encrypted at rest",
                    message=(
                        "No EncryptionConfiguration file is referenced for etcd. "
                        "Secrets and other sensitive resources stored in etcd are "
                        "written in plaintext, making them readable to anyone with "
                        "direct etcd access."
                    ),
                    remediation=(
                        "Create an EncryptionConfiguration manifest that enables "
                        "AES-GCM or AES-CBC encryption for the 'secrets' resource, "
                        "then pass --encryption-provider-config=<path> to the "
                        "kube-apiserver and restart it."
                    ),
                )
            )

    @staticmethod
    def _check_003_kubelet_readonly_port(
        cluster: ClusterConfig, findings: List[CISFinding]
    ) -> None:
        """CIS 4.2.4 — Disable the kubelet read-only port."""
        if cluster.kubelet.read_only_port != 0:
            findings.append(
                CISFinding(
                    check_id="CIS-K8S-003",
                    cis_reference="CIS 4.2.4",
                    severity="HIGH",
                    title="Kubelet read-only port enabled",
                    message=(
                        f"The kubelet read-only port is set to "
                        f"{cluster.kubelet.read_only_port} (expected 0 / disabled). "
                        "This unauthenticated endpoint exposes pod, node, and "
                        "metric information to any network-adjacent attacker."
                    ),
                    remediation=(
                        "Set readOnlyPort: 0 in the kubelet configuration file "
                        "(or pass --read-only-port=0) and restart the kubelet on "
                        "all nodes."
                    ),
                )
            )

    @staticmethod
    def _check_004_audit_logging(
        cluster: ClusterConfig, findings: List[CISFinding]
    ) -> None:
        """CIS 3.2.1 and 3.2.2 — Enable API server audit logging."""
        log_missing = cluster.api_server.audit_log_path is None
        policy_missing = cluster.api_server.audit_policy_file is None
        if log_missing or policy_missing:
            missing_parts: List[str] = []
            if log_missing:
                missing_parts.append("audit-log-path")
            if policy_missing:
                missing_parts.append("audit-policy-file")
            findings.append(
                CISFinding(
                    check_id="CIS-K8S-004",
                    cis_reference="CIS 3.2.1, CIS 3.2.2",
                    severity="HIGH",
                    title="API server audit logging not configured",
                    message=(
                        f"The following audit logging parameter(s) are not set: "
                        f"{', '.join(missing_parts)}. Without audit logs, "
                        "security-relevant API server activity cannot be reviewed "
                        "or alerted on."
                    ),
                    remediation=(
                        "Create an audit policy file (--audit-policy-file=<path>) "
                        "and set a destination log path (--audit-log-path=<path>) "
                        "in the kube-apiserver manifest. Restart the API server "
                        "after applying the changes."
                    ),
                )
            )

    @staticmethod
    def _check_005_api_server_tls(
        cluster: ClusterConfig, findings: List[CISFinding]
    ) -> None:
        """CIS 1.2.26 — Ensure the API server TLS cert and key are set."""
        cert_missing = cluster.api_server.tls_cert_file is None
        key_missing = cluster.api_server.tls_private_key_file is None
        if cert_missing or key_missing:
            missing_parts: List[str] = []
            if cert_missing:
                missing_parts.append("tls-cert-file")
            if key_missing:
                missing_parts.append("tls-private-key-file")
            findings.append(
                CISFinding(
                    check_id="CIS-K8S-005",
                    cis_reference="CIS 1.2.26",
                    severity="CRITICAL",
                    title="API server TLS not configured",
                    message=(
                        f"The following TLS parameter(s) are missing on the "
                        f"kube-apiserver: {', '.join(missing_parts)}. Without TLS, "
                        "all API traffic is transmitted in plaintext and is "
                        "vulnerable to interception and tampering."
                    ),
                    remediation=(
                        "Provision a valid TLS certificate and key for the API "
                        "server, then set --tls-cert-file=<path> and "
                        "--tls-private-key-file=<path> in the kube-apiserver "
                        "manifest. Restart the API server to apply."
                    ),
                )
            )

    @staticmethod
    def _check_006_pod_security_admission(
        cluster: ClusterConfig, findings: List[CISFinding]
    ) -> None:
        """CIS 5.2 — Enable the PodSecurity admission controller."""
        if not cluster.api_server.pod_security_admission_enabled:
            findings.append(
                CISFinding(
                    check_id="CIS-K8S-006",
                    cis_reference="CIS 5.2",
                    severity="HIGH",
                    title="PodSecurity admission controller not enabled",
                    message=(
                        "The PodSecurity admission controller is disabled. Without "
                        "it, pods can request privileged access, host namespaces, or "
                        "other dangerous capabilities that violate the principle of "
                        "least privilege."
                    ),
                    remediation=(
                        "Enable the PodSecurity admission controller by adding "
                        "'PodSecurity' to --enable-admission-plugins in the "
                        "kube-apiserver manifest, then configure namespace-level "
                        "labels (pod-security.kubernetes.io/enforce) to enforce "
                        "the 'restricted' or 'baseline' policy."
                    ),
                )
            )

    @staticmethod
    def _check_007_kube_system_sa_automount(
        cluster: ClusterConfig, findings: List[CISFinding]
    ) -> None:
        """CIS 5.1.5 — Disable automounting of service account tokens in kube-system."""
        if cluster.kube_system_sa_automount:
            findings.append(
                CISFinding(
                    check_id="CIS-K8S-007",
                    cis_reference="CIS 5.1.5",
                    severity="MEDIUM",
                    title="kube-system service account token auto-mounting enabled",
                    message=(
                        "Service accounts in the kube-system namespace are "
                        "configured to automatically mount tokens into pods. A "
                        "compromised pod in kube-system could use its mounted token "
                        "to escalate privileges within the cluster."
                    ),
                    remediation=(
                        "Set automountServiceAccountToken: false on all service "
                        "accounts in the kube-system namespace that do not "
                        "explicitly require API server access. Audit existing "
                        "workloads before disabling to avoid breaking controllers."
                    ),
                )
            )
