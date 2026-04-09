# CC BY 4.0 — Cyber Port Portfolio
# https://creativecommons.org/licenses/by/4.0/
#
# image_security_scanner.py
# Analyze container image metadata and configuration for security risks:
#   - Root user execution
#   - Unpinned / latest base image tags
#   - Sensitive ports exposed
#   - Secrets leaked in environment variables
#   - Outdated images (> 365 days old)
#   - Missing HEALTHCHECK
#   - Oversized images (> 1 GB)
#
# Python 3.9 compatible — uses typing.List / Optional / Dict, not X | Y syntax.

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Check weights used to compute risk_score (capped at 100).
# Keys are check IDs; values are the point weights.
_CHECK_WEIGHTS: Dict[str, int] = {
    "IMG-001": 25,  # Runs as root
    "IMG-002": 20,  # Unpinned / latest tag
    "IMG-003": 15,  # Sensitive port exposed
    "IMG-004": 40,  # Secret leaked in env var
    "IMG-005": 15,  # Image older than 365 days
    "IMG-006": 5,   # No HEALTHCHECK defined
    "IMG-007": 5,   # Image size > 1 GB
}

# Ports considered sensitive — exposure is a high-risk signal.
_SENSITIVE_PORTS = {22, 23, 2375, 2376, 3389, 5900, 6379, 27017}

# Substrings that indicate an env var may contain a credential.
# Comparison is done against the uppercased env var name.
_SECRET_KEYWORDS = {
    "PASSWORD",
    "SECRET",
    "KEY",
    "TOKEN",
    "CREDENTIAL",
    "PRIVATE",
    "API_KEY",
    "AUTH",
}

# Port-to-service mapping used in finding detail messages.
_PORT_SERVICES: Dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    2375: "Docker API (unauthenticated)",
    2376: "Docker API (TLS)",
    3389: "RDP",
    5900: "VNC",
    6379: "Redis (unauthenticated)",
    27017: "MongoDB",
}

# Size threshold for IMG-007 (1 GiB in bytes).
_ONE_GIB: int = 1_073_741_824

# Age threshold for IMG-005 (days).
_MAX_IMAGE_AGE_DAYS: int = 365


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ImageEnvVar:
    """A single environment variable defined in a container image."""

    name: str
    value: str  # may be an empty string


@dataclass
class ContainerImage:
    """Full metadata snapshot for a single container image."""

    image_id: str
    name: str
    tag: str          # "" if no tag was specified
    base_image: str   # e.g. "ubuntu:20.04" or "scratch"
    user: str         # "" means the image runs as root by default
    exposed_ports: List[int]
    env_vars: List[ImageEnvVar]
    created_at: Optional[date]  # None if creation date is unknown
    size_bytes: int
    health_check: Optional[str]  # None if no HEALTHCHECK instruction is present


@dataclass
class IMGFinding:
    """A single security finding produced by a check."""

    check_id: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int


@dataclass
class IMGResult:
    """Aggregated scan result for one container image."""

    image_name: str
    image_tag: str
    findings: List[IMGFinding]
    # Capped at 100; weights for duplicate check IDs are counted only once.
    risk_score: int

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a plain dictionary representation of the result."""
        return {
            "image_name": self.image_name,
            "image_tag": self.image_tag,
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
        """Return a human-readable one-line summary of the scan result."""
        tag_display = self.image_tag if self.image_tag else "<no tag>"
        return (
            f"{self.image_name}:{tag_display} — "
            f"risk_score={self.risk_score}/100, "
            f"{len(self.findings)} finding(s)"
        )

    def by_severity(self) -> Dict[str, List[IMGFinding]]:
        """Return findings grouped by severity level.

        Returns a dict whose keys are severity strings (CRITICAL, HIGH,
        MEDIUM, LOW, INFO) and whose values are lists of matching findings.
        Only severities with at least one finding are included.
        """
        groups: Dict[str, List[IMGFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups


# ---------------------------------------------------------------------------
# Internal check implementations
# ---------------------------------------------------------------------------


def _check_img001(image: ContainerImage) -> Optional[IMGFinding]:
    """IMG-001: Image runs as root (user is '', 'root', or '0')."""
    if image.user.strip() in ("", "root", "0"):
        return IMGFinding(
            check_id="IMG-001",
            severity="HIGH",
            title="Image runs as root user",
            detail=(
                f"The image user is set to {image.user!r}. "
                "Running containers as root increases the blast radius of "
                "any container escape or application compromise. "
                "Use a non-root UID (e.g. 1000) in the Dockerfile USER instruction."
            ),
            weight=_CHECK_WEIGHTS["IMG-001"],
        )
    return None


def _check_img002(image: ContainerImage) -> Optional[IMGFinding]:
    """IMG-002: Base image tag is 'latest' or image uses no tag (unpinned)."""
    tag_is_unpinned = image.tag in ("", "latest")
    base_has_no_tag = ":" not in image.base_image
    base_is_latest = image.base_image.endswith(":latest")

    if tag_is_unpinned or base_has_no_tag or base_is_latest:
        reasons: List[str] = []
        if tag_is_unpinned:
            reasons.append(
                f"image tag is {image.tag!r} (unpinned)"
            )
        if base_has_no_tag:
            reasons.append(
                f"base image {image.base_image!r} has no tag"
            )
        if base_is_latest:
            reasons.append(
                f"base image {image.base_image!r} uses ':latest'"
            )
        return IMGFinding(
            check_id="IMG-002",
            severity="HIGH",
            title="Unpinned or latest base image tag",
            detail=(
                "Unpinned images may silently receive breaking or malicious "
                "updates. Reasons: " + "; ".join(reasons) + ". "
                "Pin both the image tag and the base image to a specific "
                "digest or immutable version."
            ),
            weight=_CHECK_WEIGHTS["IMG-002"],
        )
    return None


def _check_img003(image: ContainerImage) -> List[IMGFinding]:
    """IMG-003: One finding per sensitive port exposed by the image."""
    findings: List[IMGFinding] = []
    for port in sorted(image.exposed_ports):  # sorted for deterministic order
        if port in _SENSITIVE_PORTS:
            service = _PORT_SERVICES.get(port, "unknown service")
            findings.append(
                IMGFinding(
                    check_id="IMG-003",
                    severity="MEDIUM",
                    title=f"Sensitive port {port} ({service}) exposed",
                    detail=(
                        f"Port {port} ({service}) is listed in the image's "
                        "EXPOSE instructions. Exposing this port increases "
                        "the attack surface. Remove or restrict access to "
                        f"port {port} unless strictly required."
                    ),
                    weight=_CHECK_WEIGHTS["IMG-003"],
                )
            )
    return findings


def _check_img004(image: ContainerImage) -> List[IMGFinding]:
    """IMG-004: One finding per env var whose name suggests a secret."""
    findings: List[IMGFinding] = []
    for env_var in image.env_vars:
        # Only flag if the value is non-empty (empty value = placeholder).
        if env_var.value.strip() == "":
            continue
        upper_name = env_var.name.upper()
        # Check whether any secret keyword appears as a substring of the name.
        for keyword in _SECRET_KEYWORDS:
            if keyword in upper_name:
                findings.append(
                    IMGFinding(
                        check_id="IMG-004",
                        severity="CRITICAL",
                        title=f"Potential secret in environment variable '{env_var.name}'",
                        detail=(
                            f"Environment variable '{env_var.name}' contains "
                            f"the keyword '{keyword}' and has a non-empty value. "
                            "Embedding secrets in image environment variables "
                            "exposes them to anyone who can inspect the image. "
                            "Use a secrets manager or runtime secret injection "
                            "instead. (Value redacted for security.)"
                        ),
                        weight=_CHECK_WEIGHTS["IMG-004"],
                    )
                )
                break  # One finding per env var — stop after first keyword match
    return findings


def _check_img005(
    image: ContainerImage, reference_date: date
) -> Optional[IMGFinding]:
    """IMG-005: Image creation date is more than 365 days before reference_date."""
    if image.created_at is None:
        # Cannot determine age — skip the check rather than false-positive.
        return None
    age_days = (reference_date - image.created_at).days
    if age_days > _MAX_IMAGE_AGE_DAYS:
        return IMGFinding(
            check_id="IMG-005",
            severity="MEDIUM",
            title="Image is outdated (older than 365 days)",
            detail=(
                f"Image was created on {image.created_at.isoformat()} "
                f"({age_days} days ago). Outdated images likely contain "
                "unpatched vulnerabilities. Rebuild from an up-to-date base image."
            ),
            weight=_CHECK_WEIGHTS["IMG-005"],
        )
    return None


def _check_img006(image: ContainerImage) -> Optional[IMGFinding]:
    """IMG-006: No HEALTHCHECK instruction is defined in the image."""
    if image.health_check is None:
        return IMGFinding(
            check_id="IMG-006",
            severity="LOW",
            title="No HEALTHCHECK defined",
            detail=(
                "The image does not define a HEALTHCHECK instruction. "
                "Without a health check, orchestrators cannot detect "
                "unhealthy containers automatically. "
                "Add a HEALTHCHECK to the Dockerfile."
            ),
            weight=_CHECK_WEIGHTS["IMG-006"],
        )
    return None


def _check_img007(image: ContainerImage) -> Optional[IMGFinding]:
    """IMG-007: Image size exceeds 1 GiB."""
    if image.size_bytes > _ONE_GIB:
        size_mib = image.size_bytes / (1024 * 1024)
        return IMGFinding(
            check_id="IMG-007",
            severity="LOW",
            title="Image size exceeds 1 GB",
            detail=(
                f"Image size is {size_mib:.1f} MiB "
                f"({image.size_bytes:,} bytes), which exceeds the 1 GiB "
                "threshold. Large images increase pull latency, registry "
                "storage costs, and attack surface. "
                "Use multi-stage builds and minimal base images."
            ),
            weight=_CHECK_WEIGHTS["IMG-007"],
        )
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan(
    image: ContainerImage,
    reference_date: Optional[date] = None,
) -> IMGResult:
    """Scan a container image for security risks.

    Runs all seven checks (IMG-001 through IMG-007) against the supplied
    image metadata and returns an IMGResult with all findings and a
    risk_score capped at 100.

    Args:
        image: The container image metadata to analyse.
        reference_date: The date used as 'today' for age calculations.
            Defaults to date.today() when not specified.

    Returns:
        An IMGResult instance containing all findings and a risk_score.
    """
    if reference_date is None:
        reference_date = date.today()

    all_findings: List[IMGFinding] = []

    # IMG-001 — root user
    finding = _check_img001(image)
    if finding:
        all_findings.append(finding)

    # IMG-002 — unpinned / latest tag
    finding = _check_img002(image)
    if finding:
        all_findings.append(finding)

    # IMG-003 — sensitive ports (may produce multiple findings)
    all_findings.extend(_check_img003(image))

    # IMG-004 — secrets in env vars (may produce multiple findings)
    all_findings.extend(_check_img004(image))

    # IMG-005 — image age
    finding = _check_img005(image, reference_date)
    if finding:
        all_findings.append(finding)

    # IMG-006 — missing HEALTHCHECK
    finding = _check_img006(image)
    if finding:
        all_findings.append(finding)

    # IMG-007 — image size
    finding = _check_img007(image)
    if finding:
        all_findings.append(finding)

    # Compute risk_score: sum weights for each *unique* check ID that fired,
    # then cap at 100.
    fired_check_ids = {f.check_id for f in all_findings}
    raw_score = sum(_CHECK_WEIGHTS[cid] for cid in fired_check_ids)
    risk_score = min(100, raw_score)

    return IMGResult(
        image_name=image.name,
        image_tag=image.tag,
        findings=all_findings,
        risk_score=risk_score,
    )


def scan_many(
    images: List[ContainerImage],
    reference_date: Optional[date] = None,
) -> List[IMGResult]:
    """Scan multiple container images and return a result for each.

    Args:
        images: List of ContainerImage instances to scan.
        reference_date: Passed unchanged to each individual scan() call.

    Returns:
        A list of IMGResult instances in the same order as the input list.
    """
    return [scan(image, reference_date=reference_date) for image in images]
