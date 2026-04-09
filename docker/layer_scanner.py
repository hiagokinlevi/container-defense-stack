"""
Container Image Layer Security Scanner
=========================================
Analyzes Docker/OCI image layer metadata to detect security anti-patterns
that are introduced across build layers — secret exposure in history,
large attack-surface installs, layer bloat, and suspicious modifications.

The scanner works on layer metadata (history entries and file manifests)
rather than live container inspection, making it suitable for CI/CD
pipeline integration without requiring a running daemon.

Checks Performed
-----------------
LAY-001  Secret-like value in build command history
         A layer's CreatedBy command contains a token that looks like an
         API key, password, or private key. Secrets baked into history are
         permanently visible via ``docker history --no-trunc``.

LAY-002  Package manager run without cache clean
         A layer runs apt-get/apk/yum without clearing the package cache
         in the same layer. Cached package indexes bloat the image and may
         contain stale metadata useful to attackers enumerating installed
         software.

LAY-003  Sensitive file path modified in layer
         A layer's file list contains paths matching sensitive system files
         (sudoers, passwd, shadow, sshd_config, crontab, authorized_keys).
         Unexpected modification of these files in a build layer may
         indicate supply-chain compromise or misconfiguration.

LAY-004  Layer adds SUID/SGID binary
         A file added in a layer has SUID or SGID permission bits set.
         SUID binaries can be exploited for local privilege escalation.

LAY-005  Excessive layer count
         The image has more layers than the recommended maximum. Each layer
         increases attack surface (more history to leak), slows pulls, and
         makes supply-chain auditing harder.

LAY-006  Large layer size
         A single layer exceeds the size threshold (default 500 MB).
         Large layers often contain unnecessary build artifacts, dev tools,
         or cached data that should be excluded.

LAY-007  Curl / wget in non-verification layer
         A layer runs curl or wget without a subsequent checksum
         verification command in the same layer. Remote content is
         fetched without integrity checking.

Usage::

    from docker.layer_scanner import (
        LayerScanner,
        LayerScanReport,
        LayerMetadata,
    )

    scanner = LayerScanner()
    layers = [
        LayerMetadata(
            layer_id="sha256:abc123",
            created_by="RUN apt-get install -y curl && rm -rf /var/lib/apt/lists/*",
            size_bytes=52_000_000,
        )
    ]
    report = scanner.scan(layers)
    print(report.summary())
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class LayerSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CHECK_META: dict[str, tuple[LayerSeverity, str]] = {
    "LAY-001": (LayerSeverity.CRITICAL, "Secret-like value in layer history"),
    "LAY-002": (LayerSeverity.LOW,      "Package cache not cleaned in layer"),
    "LAY-003": (LayerSeverity.HIGH,     "Sensitive file modified in layer"),
    "LAY-004": (LayerSeverity.HIGH,     "SUID/SGID binary added in layer"),
    "LAY-005": (LayerSeverity.MEDIUM,   "Excessive layer count"),
    "LAY-006": (LayerSeverity.MEDIUM,   "Oversized layer"),
    "LAY-007": (LayerSeverity.HIGH,     "Remote fetch without integrity check"),
}

_CHECK_WEIGHTS: dict[str, int] = {
    "LAY-001": 40,
    "LAY-002": 5,
    "LAY-003": 25,
    "LAY-004": 25,
    "LAY-005": 10,
    "LAY-006": 10,
    "LAY-007": 20,
}

# Secret patterns in build commands
_SECRET_CMD_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|"
        r"access[_-]?key|auth[_-]?key|credentials?)\s*[=:]\s*\S+",
        r"AKIA[0-9A-Z]{16}",               # AWS access key
        r"(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{36}",  # GitHub token
        r"-----BEGIN (?:RSA |EC )?PRIVATE KEY",
    ]
]

# Package manager calls without cache cleanup
_PKG_INSTALL_RE = re.compile(
    r"(apt-get\s+install|apk\s+add|yum\s+install|dnf\s+install|pip\s+install)",
    re.IGNORECASE,
)

_CACHE_CLEAN_PATTERNS = [
    "rm -rf /var/lib/apt/lists",
    "apt-get clean",
    "apk --no-cache",
    "apk add --no-cache",
    "--no-cache",
    "rm -rf /var/cache/apk",
    "yum clean all",
    "dnf clean all",
]

# Sensitive file paths
_SENSITIVE_FILE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"/etc/passwd$",
        r"/etc/shadow$",
        r"/etc/sudoers",
        r"/etc/ssh/sshd_config",
        r"\.ssh/authorized_keys",
        r"/etc/crontab$",
        r"/etc/cron\.d/",
        r"/root/\.ssh/",
        r"/etc/security/",
    ]
]

# SUID/SGID octal permission bits (4xxx = SUID, 2xxx = SGID, 6xxx = both)
_SUID_SGID_MODES = {0o4000, 0o2000, 0o6000}

# Default thresholds
_DEFAULT_MAX_LAYERS    = 20
_DEFAULT_MAX_LAYER_MB  = 500
_DEFAULT_MAX_LAYER_BYTES = _DEFAULT_MAX_LAYER_MB * 1024 * 1024

# Curl/wget fetch without checksum verification in same command
_FETCH_RE = re.compile(r"\b(curl|wget)\b", re.IGNORECASE)
_CHECKSUM_RE = re.compile(
    r"\b(sha256sum|sha512sum|md5sum|openssl\s+dgst|gpg\s+--verify|"
    r"echo\s+[0-9a-f]{40,}|rhash)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class LayerFile:
    """
    A file entry within a layer's file manifest.

    Attributes:
        path:   Absolute file path.
        mode:   Unix permission mode as integer (e.g. 0o755).
        size:   File size in bytes.
    """
    path: str
    mode: int = 0o644
    size: int = 0

    @property
    def is_suid(self) -> bool:
        return bool(self.mode & 0o4000)

    @property
    def is_sgid(self) -> bool:
        return bool(self.mode & 0o2000)


@dataclass
class LayerMetadata:
    """
    Metadata for a single image layer.

    Attributes:
        layer_id:    Layer digest or ID (e.g. sha256:abc...).
        created_by:  The Dockerfile command that created this layer.
        size_bytes:  Layer compressed size in bytes.
        files:       List of LayerFile entries in this layer.
        layer_index: 0-based position in the layer stack (0 = base).
    """
    layer_id:    str = ""
    created_by:  str = ""
    size_bytes:  int = 0
    files:       list[LayerFile] = field(default_factory=list)
    layer_index: int = 0


@dataclass
class LayerFinding:
    """
    A single layer security finding.

    Attributes:
        check_id:    Check identifier (LAY-001 … LAY-007).
        severity:    Finding severity.
        title:       Short description.
        detail:      Detailed explanation.
        remediation: Step to fix the issue.
        layer_id:    The layer where the finding was detected.
        layer_index: Index of the layer (0 = base).
        evidence:    Supporting evidence string.
    """
    check_id:    str
    severity:    LayerSeverity
    title:       str
    detail:      str
    remediation: str
    layer_id:    str = ""
    layer_index: int = 0
    evidence:    str = ""

    def summary(self) -> str:
        return (
            f"[{self.severity.value}] {self.check_id} "
            f"layer[{self.layer_index}]: {self.title}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id":    self.check_id,
            "severity":    self.severity.value,
            "title":       self.title,
            "detail":      self.detail,
            "remediation": self.remediation,
            "layer_id":    self.layer_id,
            "layer_index": self.layer_index,
            "evidence":    self.evidence,
        }


@dataclass
class LayerScanReport:
    """
    Aggregated layer scan report for an image.

    Attributes:
        findings:       All findings across all layers.
        total_layers:   Total number of layers analyzed.
        total_size_bytes: Sum of all layer sizes.
        risk_score:     Aggregate 0–100 risk score.
        image_tag:      Tag of the image scanned (informational).
    """
    findings:         list[LayerFinding] = field(default_factory=list)
    total_layers:     int = 0
    total_size_bytes: int = 0
    risk_score:       int = 0
    image_tag:        str = ""

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> list[LayerFinding]:
        return [f for f in self.findings if f.severity == LayerSeverity.CRITICAL]

    @property
    def high_findings(self) -> list[LayerFinding]:
        return [f for f in self.findings if f.severity == LayerSeverity.HIGH]

    def findings_by_check(self, check_id: str) -> list[LayerFinding]:
        return [f for f in self.findings if f.check_id == check_id]

    def findings_by_layer(self, layer_index: int) -> list[LayerFinding]:
        return [f for f in self.findings if f.layer_index == layer_index]

    def summary(self) -> str:
        tag_str = f" [{self.image_tag}]" if self.image_tag else ""
        mb = self.total_size_bytes // (1024 * 1024)
        return (
            f"LayerScanReport{tag_str}: {self.total_layers} layer(s) "
            f"{mb}MB | risk={self.risk_score} | "
            f"{self.total_findings} finding(s) "
            f"[CRITICAL={len(self.critical_findings)} "
            f"HIGH={len(self.high_findings)}]"
        )


# ---------------------------------------------------------------------------
# LayerScanner
# ---------------------------------------------------------------------------

class LayerScanner:
    """
    Scans image layer metadata for security anti-patterns.

    Args:
        max_layers:      Maximum recommended layer count before LAY-005 fires
                         (default 20).
        max_layer_bytes: Maximum layer size in bytes before LAY-006 fires
                         (default 500 MB).
    """

    def __init__(
        self,
        max_layers: int = _DEFAULT_MAX_LAYERS,
        max_layer_bytes: int = _DEFAULT_MAX_LAYER_BYTES,
    ) -> None:
        self._max_layers      = max_layers
        self._max_layer_bytes = max_layer_bytes

    def scan(
        self,
        layers: list[LayerMetadata],
        image_tag: str = "",
    ) -> LayerScanReport:
        """
        Scan a list of LayerMetadata objects.

        Returns a LayerScanReport.
        """
        findings: list[LayerFinding] = []
        fired_checks: set[str] = set()

        total_size = sum(lyr.size_bytes for lyr in layers)

        for layer in layers:
            layer_findings = self._check_layer(layer)
            for f in layer_findings:
                findings.append(f)
                fired_checks.add(f.check_id)

        # LAY-005: Excessive layer count (image-level)
        if len(layers) > self._max_layers:
            f = self._make_finding(
                "LAY-005", "", -1,
                detail=(
                    f"Image has {len(layers)} layers, exceeding the recommended "
                    f"maximum of {self._max_layers}. Excessive layers increase "
                    "history exposure and image pull times."
                ),
                remediation=(
                    "Combine RUN commands with && and use multi-stage builds "
                    "to reduce final layer count."
                ),
                evidence=f"layer_count={len(layers)}",
            )
            findings.append(f)
            fired_checks.add("LAY-005")

        risk_score = min(100, sum(
            _CHECK_WEIGHTS.get(cid, 5) for cid in fired_checks
        ))

        return LayerScanReport(
            findings=findings,
            total_layers=len(layers),
            total_size_bytes=total_size,
            risk_score=risk_score,
            image_tag=image_tag,
        )

    def _check_layer(self, layer: LayerMetadata) -> list[LayerFinding]:
        findings: list[LayerFinding] = []
        cmd = layer.created_by

        # LAY-001: Secret in history
        for pattern in _SECRET_CMD_PATTERNS:
            m = pattern.search(cmd)
            if m:
                # Redact value for safety
                excerpt = cmd[:120]
                findings.append(self._make_finding(
                    "LAY-001", layer.layer_id, layer.layer_index,
                    detail=(
                        f"Layer {layer.layer_index} command contains a "
                        "secret-like value. Secrets in build history are "
                        "visible to anyone with pull access to the image."
                    ),
                    remediation=(
                        "Pass secrets at runtime via ``--secret`` (BuildKit) "
                        "or environment variables, never in RUN/ENV/ARG."
                    ),
                    evidence=f"pattern='{pattern.pattern[:40]}' in cmd",
                ))
                break  # one finding per layer per check

        # LAY-002: Package manager without cache clean
        if _PKG_INSTALL_RE.search(cmd):
            has_clean = any(p.lower() in cmd.lower() for p in _CACHE_CLEAN_PATTERNS)
            if not has_clean:
                findings.append(self._make_finding(
                    "LAY-002", layer.layer_id, layer.layer_index,
                    detail=(
                        f"Layer {layer.layer_index} installs packages without "
                        "cleaning the package cache in the same layer. "
                        "Caches persist in the layer and bloat the image."
                    ),
                    remediation=(
                        "Add cache cleanup in the same RUN command: "
                        "``&& rm -rf /var/lib/apt/lists/*`` "
                        "or use ``apk add --no-cache``."
                    ),
                    evidence=f"cmd contains package install without cleanup",
                ))

        # LAY-007: Remote fetch without checksum
        if _FETCH_RE.search(cmd) and not _CHECKSUM_RE.search(cmd):
            findings.append(self._make_finding(
                "LAY-007", layer.layer_id, layer.layer_index,
                detail=(
                    f"Layer {layer.layer_index} fetches remote content via "
                    "curl/wget without a checksum verification step in the "
                    "same command. Integrity of the downloaded content cannot "
                    "be verified."
                ),
                remediation=(
                    "Add sha256sum verification: "
                    "``RUN curl -o /tmp/f.tar.gz URL && "
                    "echo 'HASH  /tmp/f.tar.gz' | sha256sum -c``"
                ),
                evidence="fetch without checksum in same RUN",
            ))

        # LAY-006: Large layer
        if layer.size_bytes > self._max_layer_bytes:
            mb = layer.size_bytes // (1024 * 1024)
            limit_mb = self._max_layer_bytes // (1024 * 1024)
            findings.append(self._make_finding(
                "LAY-006", layer.layer_id, layer.layer_index,
                detail=(
                    f"Layer {layer.layer_index} is {mb} MB, exceeding the "
                    f"{limit_mb} MB threshold. Large layers often contain "
                    "build artifacts, development tools, or unnecessary caches."
                ),
                remediation=(
                    "Use multi-stage builds to copy only production artifacts. "
                    "Remove build dependencies and caches in the same RUN layer."
                ),
                evidence=f"size={mb}MB",
            ))

        # File-level checks
        for lf in layer.files:
            # LAY-003: Sensitive file modified
            for pattern in _SENSITIVE_FILE_PATTERNS:
                if pattern.search(lf.path):
                    findings.append(self._make_finding(
                        "LAY-003", layer.layer_id, layer.layer_index,
                        detail=(
                            f"Layer {layer.layer_index} modifies sensitive "
                            f"system file '{lf.path}'. Unexpected changes to "
                            "these files may indicate misconfiguration or "
                            "supply-chain tampering."
                        ),
                        remediation=(
                            "Audit the necessity of modifying this file and "
                            "verify its contents match the expected state."
                        ),
                        evidence=f"file='{lf.path}'",
                    ))
                    break

            # LAY-004: SUID/SGID binary
            if lf.is_suid or lf.is_sgid:
                bit = "SUID" if lf.is_suid else "SGID"
                if lf.is_suid and lf.is_sgid:
                    bit = "SUID+SGID"
                findings.append(self._make_finding(
                    "LAY-004", layer.layer_id, layer.layer_index,
                    detail=(
                        f"Layer {layer.layer_index} adds a {bit} binary at "
                        f"'{lf.path}'. {bit} binaries can be exploited for "
                        "local privilege escalation."
                    ),
                    remediation=(
                        f"Remove the {bit} bit unless strictly required: "
                        f"``chmod u-s {lf.path}``"
                    ),
                    evidence=f"path='{lf.path}' mode={oct(lf.mode)}",
                ))

        return findings

    @staticmethod
    def _make_finding(
        check_id: str,
        layer_id: str,
        layer_index: int,
        detail: str,
        remediation: str,
        evidence: str = "",
    ) -> LayerFinding:
        severity, title = _CHECK_META[check_id]
        return LayerFinding(
            check_id=check_id,
            severity=severity,
            title=title,
            detail=detail,
            remediation=remediation,
            layer_id=layer_id,
            layer_index=layer_index,
            evidence=evidence,
        )
