"""
Dockerfile security validator.

Checks common Dockerfile misconfigurations: running as root, using latest tag,
ADD instead of COPY, secrets in ENV, no HEALTHCHECK.
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import re


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class DockerFinding:
    rule_id: str
    severity: Severity
    line: int
    message: str
    remediation: str


def validate_dockerfile(dockerfile_path: Path) -> list[DockerFinding]:
    """Parse a Dockerfile and return a list of security findings."""
    findings: list[DockerFinding] = []
    lines = dockerfile_path.read_text().splitlines()
    has_user = False
    has_healthcheck = False

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue

        if stripped.upper().startswith("USER"):
            user_val = stripped.split(None, 1)[1] if len(stripped.split()) > 1 else ""
            # Only count USER instructions that switch to a non-root identity.
            if user_val not in ("root", "0", "0:0", "root:root"):
                has_user = True

        if stripped.upper().startswith("FROM") and ":latest" in stripped.lower():
            findings.append(DockerFinding(
                rule_id="DF001", severity=Severity.MEDIUM, line=i,
                message="FROM uses :latest tag — non-deterministic builds",
                remediation="Pin to a specific image digest or version tag",
            ))

        # ADD with a local source path has implicit tar-extraction behaviour,
        # which can be surprising. Prefer COPY for local files.
        if stripped.upper().startswith("ADD ") and not re.search(r'https?://', stripped):
            findings.append(DockerFinding(
                rule_id="DF002", severity=Severity.LOW, line=i,
                message="ADD used instead of COPY — ADD has implicit tar extraction behavior",
                remediation="Use COPY unless you specifically need ADD's tar-extraction or URL-fetch features",
            ))

        # Detect environment variables whose names suggest they hold secrets.
        if re.match(r'^ENV\s+\S*(SECRET|PASSWORD|TOKEN|KEY|PASS)\S*\s*=', stripped, re.IGNORECASE):
            findings.append(DockerFinding(
                rule_id="DF003", severity=Severity.HIGH, line=i,
                message="Possible secret embedded in ENV instruction",
                remediation="Use build-time secrets (--secret) or runtime environment injection, never bake secrets into layers",
            ))

        if stripped.upper().startswith("HEALTHCHECK"):
            has_healthcheck = True

    # File-level checks: missing USER or HEALTHCHECK anywhere in the file.
    if not has_user:
        findings.append(DockerFinding(
            rule_id="DF004", severity=Severity.HIGH, line=0,
            message="No non-root USER instruction found — container runs as root by default",
            remediation="Add USER <non-root-uid> before the final CMD/ENTRYPOINT",
        ))

    if not has_healthcheck:
        findings.append(DockerFinding(
            rule_id="DF005", severity=Severity.LOW, line=0,
            message="No HEALTHCHECK instruction",
            remediation="Add HEALTHCHECK to enable container health monitoring",
        ))

    return findings
