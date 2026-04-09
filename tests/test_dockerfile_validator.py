"""
Tests for validators.dockerfile_validator.

Each test writes a Dockerfile string to a temporary file,
runs validate_dockerfile(), and asserts the expected rule IDs are (or are not)
present in the findings.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from validators.dockerfile_validator import validate_dockerfile, Severity


def _write_dockerfile(tmp_path: Path, content: str) -> Path:
    """Helper: write Dockerfile content to a temp file and return its path."""
    p = tmp_path / "Dockerfile"
    p.write_text(textwrap.dedent(content))
    return p


# ---------------------------------------------------------------------------
# DF001 — :latest tag
# ---------------------------------------------------------------------------
def test_latest_tag_detected(tmp_path: Path) -> None:
    """DF001 is raised when FROM uses the :latest tag."""
    dockerfile = _write_dockerfile(tmp_path, """\
        FROM python:latest
        WORKDIR /app
        COPY . .
        USER 10001
        HEALTHCHECK CMD python -c "import sys; sys.exit(0)"
        CMD ["python", "app.py"]
    """)
    findings = validate_dockerfile(dockerfile)
    rule_ids = [f.rule_id for f in findings]
    assert "DF001" in rule_ids, "Expected DF001 for :latest tag"


# ---------------------------------------------------------------------------
# DF004 — no non-root USER
# ---------------------------------------------------------------------------
def test_no_user_detected(tmp_path: Path) -> None:
    """DF004 is raised when there is no non-root USER instruction."""
    dockerfile = _write_dockerfile(tmp_path, """\
        FROM python:3.11-slim
        WORKDIR /app
        COPY . .
        HEALTHCHECK CMD python -c "import sys; sys.exit(0)"
        CMD ["python", "app.py"]
    """)
    findings = validate_dockerfile(dockerfile)
    rule_ids = [f.rule_id for f in findings]
    assert "DF004" in rule_ids, "Expected DF004 when no non-root USER is present"


# ---------------------------------------------------------------------------
# DF003 — secret in ENV
# ---------------------------------------------------------------------------
def test_secret_env_detected(tmp_path: Path) -> None:
    """DF003 is raised when an ENV instruction contains a secret-like variable name."""
    dockerfile = _write_dockerfile(tmp_path, """\
        FROM python:3.11-slim
        ENV PASSWORD=supersecret
        WORKDIR /app
        COPY . .
        USER 10001
        HEALTHCHECK CMD python -c "import sys; sys.exit(0)"
        CMD ["python", "app.py"]
    """)
    findings = validate_dockerfile(dockerfile)
    rule_ids = [f.rule_id for f in findings]
    assert "DF003" in rule_ids, "Expected DF003 for ENV with PASSWORD"


# ---------------------------------------------------------------------------
# Secure Dockerfile — no HIGH or CRITICAL findings
# ---------------------------------------------------------------------------
def test_secure_dockerfile_passes(tmp_path: Path) -> None:
    """A well-formed Dockerfile with pinned tag, non-root USER, and HEALTHCHECK
    produces no HIGH or CRITICAL severity findings."""
    dockerfile = _write_dockerfile(tmp_path, """\
        FROM python:3.11-slim AS builder
        WORKDIR /build
        COPY requirements.txt .
        RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

        FROM python:3.11-slim AS runtime
        WORKDIR /app
        COPY --from=builder /install /usr/local
        COPY --chown=10001:10001 . .
        USER 10001
        HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import sys; sys.exit(0)"
        CMD ["python", "-m", "app"]
    """)
    findings = validate_dockerfile(dockerfile)
    # No HIGH or CRITICAL findings are acceptable.
    bad = [f for f in findings if f.severity == Severity.HIGH]
    assert bad == [], (
        f"Expected no HIGH findings for secure Dockerfile, got: {[(f.rule_id, f.message) for f in bad]}"
    )


# ---------------------------------------------------------------------------
# DF006 — broad runtime base image
# ---------------------------------------------------------------------------
def test_broad_runtime_base_detected(tmp_path: Path) -> None:
    """DF006 is raised when the final runtime stage uses a broad OS base."""
    dockerfile = _write_dockerfile(tmp_path, """\
        FROM golang:1.24 AS builder
        WORKDIR /src
        COPY . .
        RUN go build -o app ./cmd/server

        FROM ubuntu:22.04 AS runtime
        WORKDIR /app
        COPY --from=builder /src/app /app/app
        USER 10001
        HEALTHCHECK CMD ["/app/app", "--healthcheck"]
        CMD ["/app/app"]
    """)
    findings = validate_dockerfile(dockerfile)
    rule_ids = [f.rule_id for f in findings]
    assert "DF006" in rule_ids, "Expected DF006 for a broad ubuntu runtime base"


def test_distroless_runtime_not_flagged(tmp_path: Path) -> None:
    """DF006 is not raised when the final stage already uses distroless."""
    dockerfile = _write_dockerfile(tmp_path, """\
        FROM golang:1.24 AS builder
        WORKDIR /src
        COPY . .
        RUN go build -o app ./cmd/server

        FROM gcr.io/distroless/static:nonroot
        COPY --from=builder /src/app /app/app
        USER 65532
        HEALTHCHECK CMD ["/app/app", "--healthcheck"]
        CMD ["/app/app"]
    """)
    findings = validate_dockerfile(dockerfile)
    rule_ids = [f.rule_id for f in findings]
    assert "DF006" not in rule_ids


def test_slim_runtime_not_flagged(tmp_path: Path) -> None:
    """DF006 is not raised for already-minimal slim runtime images."""
    dockerfile = _write_dockerfile(tmp_path, """\
        FROM python:3.11-slim AS runtime
        WORKDIR /app
        COPY . .
        USER 10001
        HEALTHCHECK CMD python -c "import sys; sys.exit(0)"
        CMD ["python", "app.py"]
    """)
    findings = validate_dockerfile(dockerfile)
    rule_ids = [f.rule_id for f in findings]
    assert "DF006" not in rule_ids
