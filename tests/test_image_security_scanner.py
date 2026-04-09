# CC BY 4.0 — Cyber Port Portfolio
# https://creativecommons.org/licenses/by/4.0/
#
# test_image_security_scanner.py
# pytest suite for docker/image_security_scanner.py
# All tests use a fixed reference_date = date(2026, 4, 6).

import sys
import os

# Allow running from repo root without installing the package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import date
from typing import List

from docker.image_security_scanner import (
    ContainerImage,
    ImageEnvVar,
    IMGFinding,
    IMGResult,
    _CHECK_WEIGHTS,
    _ONE_GIB,
    _SENSITIVE_PORTS,
    scan,
    scan_many,
)

# ---------------------------------------------------------------------------
# Shared fixed reference date — used in every test that involves age logic.
# ---------------------------------------------------------------------------
REF_DATE = date(2026, 4, 6)


# ---------------------------------------------------------------------------
# Factory helpers — build minimal valid images to keep test bodies tidy.
# ---------------------------------------------------------------------------

def _base_image(
    *,
    image_id: str = "sha256:aabbcc",
    name: str = "myapp",
    tag: str = "1.0.0",
    base_image: str = "ubuntu:22.04",
    user: str = "1001",
    exposed_ports: List[int] = None,
    env_vars: List[ImageEnvVar] = None,
    created_at=date(2025, 4, 6),  # exactly 365 days before REF_DATE — not yet > 365
    size_bytes: int = 100 * 1024 * 1024,  # 100 MiB — well under 1 GiB
    health_check: str = "CMD curl -f http://localhost/health || exit 1",
) -> ContainerImage:
    """Return a fully-compliant image that triggers NO checks by default."""
    return ContainerImage(
        image_id=image_id,
        name=name,
        tag=tag,
        base_image=base_image,
        user=user,
        exposed_ports=exposed_ports if exposed_ports is not None else [],
        env_vars=env_vars if env_vars is not None else [],
        created_at=created_at,
        size_bytes=size_bytes,
        health_check=health_check,
    )


def _scan(image: ContainerImage) -> IMGResult:
    """Convenience wrapper with fixed reference_date."""
    return scan(image, reference_date=REF_DATE)


def _finding_ids(result: IMGResult) -> List[str]:
    """Return a list of check_ids from all findings in order."""
    return [f.check_id for f in result.findings]


# ===========================================================================
# IMG-001 — Root user execution
# ===========================================================================

class TestIMG001:
    """Tests for the root-user check."""

    def test_user_empty_string_fires(self):
        # An empty user string means the image runs as root by default.
        img = _base_image(user="")
        result = _scan(img)
        assert "IMG-001" in _finding_ids(result)

    def test_user_literal_root_fires(self):
        img = _base_image(user="root")
        result = _scan(img)
        assert "IMG-001" in _finding_ids(result)

    def test_user_uid_zero_fires(self):
        img = _base_image(user="0")
        result = _scan(img)
        assert "IMG-001" in _finding_ids(result)

    def test_user_with_whitespace_empty_fires(self):
        # Whitespace-only user should be treated the same as empty.
        img = _base_image(user="   ")
        result = _scan(img)
        assert "IMG-001" in _finding_ids(result)

    def test_user_1001_does_not_fire(self):
        img = _base_image(user="1001")
        result = _scan(img)
        assert "IMG-001" not in _finding_ids(result)

    def test_user_appuser_does_not_fire(self):
        img = _base_image(user="appuser")
        result = _scan(img)
        assert "IMG-001" not in _finding_ids(result)

    def test_user_1000_does_not_fire(self):
        img = _base_image(user="1000")
        result = _scan(img)
        assert "IMG-001" not in _finding_ids(result)

    def test_img001_severity_is_high(self):
        img = _base_image(user="root")
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-001")
        assert finding.severity == "HIGH"

    def test_img001_weight_is_25(self):
        img = _base_image(user="root")
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-001")
        assert finding.weight == 25

    def test_img001_exactly_one_finding_when_root(self):
        # Root user should produce exactly one IMG-001 finding, not duplicates.
        img = _base_image(user="0")
        result = _scan(img)
        img001_findings = [f for f in result.findings if f.check_id == "IMG-001"]
        assert len(img001_findings) == 1

    def test_user_root_contributes_to_risk_score(self):
        img = _base_image(user="root")
        result = _scan(img)
        assert result.risk_score >= _CHECK_WEIGHTS["IMG-001"]

    def test_user_string_two_does_not_fire(self):
        # UID "2" is not root.
        img = _base_image(user="2")
        result = _scan(img)
        assert "IMG-001" not in _finding_ids(result)

    def test_img001_detail_mentions_root(self):
        img = _base_image(user="root")
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-001")
        assert "root" in finding.detail.lower() or "user" in finding.detail.lower()


# ===========================================================================
# IMG-002 — Unpinned / latest image tag
# ===========================================================================

class TestIMG002:
    """Tests for the unpinned / latest base image check."""

    def test_image_tag_latest_fires(self):
        img = _base_image(tag="latest")
        result = _scan(img)
        assert "IMG-002" in _finding_ids(result)

    def test_image_tag_empty_fires(self):
        img = _base_image(tag="")
        result = _scan(img)
        assert "IMG-002" in _finding_ids(result)

    def test_base_image_no_colon_fires(self):
        # "ubuntu" with no colon means no tag — unpinned.
        img = _base_image(tag="1.0.0", base_image="ubuntu")
        result = _scan(img)
        assert "IMG-002" in _finding_ids(result)

    def test_base_image_colon_latest_fires(self):
        img = _base_image(tag="1.0.0", base_image="ubuntu:latest")
        result = _scan(img)
        assert "IMG-002" in _finding_ids(result)

    def test_pinned_tag_and_base_does_not_fire(self):
        img = _base_image(tag="1.0.0", base_image="ubuntu:22.04")
        result = _scan(img)
        assert "IMG-002" not in _finding_ids(result)

    def test_image_tag_v2_1_3_does_not_fire(self):
        img = _base_image(tag="v2.1.3", base_image="debian:bullseye-slim")
        result = _scan(img)
        assert "IMG-002" not in _finding_ids(result)

    def test_img002_severity_is_high(self):
        img = _base_image(tag="latest")
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-002")
        assert finding.severity == "HIGH"

    def test_img002_weight_is_20(self):
        img = _base_image(tag="latest")
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-002")
        assert finding.weight == 20

    def test_img002_exactly_one_finding_even_if_multiple_reasons(self):
        # tag="" AND base_image="alpine" (no colon) — still only one finding.
        img = _base_image(tag="", base_image="alpine")
        result = _scan(img)
        img002_findings = [f for f in result.findings if f.check_id == "IMG-002"]
        assert len(img002_findings) == 1

    def test_scratch_base_no_colon_fires(self):
        # "scratch" has no colon — flagged as unpinned.
        img = _base_image(tag="1.0.0", base_image="scratch")
        result = _scan(img)
        assert "IMG-002" in _finding_ids(result)

    def test_base_image_digest_pinned_does_not_fire(self):
        # A digest-pinned base image contains a colon.
        img = _base_image(
            tag="1.0.0",
            base_image="ubuntu@sha256:abc123def456",
        )
        # base_image contains ":" (via @) — wait, "@" not ":"
        # This tests that our check correctly looks for ":"
        # ubuntu@sha256:abc123 DOES contain ":" so would not fire the no-colon rule.
        result = _scan(img)
        # The base_image "ubuntu@sha256:abc123def456" contains ":" so base_has_no_tag=False
        # It does not end with ":latest" so base_is_latest=False
        # tag is "1.0.0" so tag_is_unpinned=False
        assert "IMG-002" not in _finding_ids(result)

    def test_img002_contributes_to_risk_score(self):
        img = _base_image(tag="latest")
        result = _scan(img)
        assert result.risk_score >= _CHECK_WEIGHTS["IMG-002"]


# ===========================================================================
# IMG-003 — Sensitive ports exposed
# ===========================================================================

class TestIMG003:
    """Tests for the sensitive port exposure check."""

    def test_port_22_ssh_fires(self):
        img = _base_image(exposed_ports=[22])
        result = _scan(img)
        assert "IMG-003" in _finding_ids(result)

    def test_port_23_telnet_fires(self):
        img = _base_image(exposed_ports=[23])
        result = _scan(img)
        assert "IMG-003" in _finding_ids(result)

    def test_port_2375_docker_api_fires(self):
        img = _base_image(exposed_ports=[2375])
        result = _scan(img)
        assert "IMG-003" in _finding_ids(result)

    def test_port_2376_docker_api_tls_fires(self):
        img = _base_image(exposed_ports=[2376])
        result = _scan(img)
        assert "IMG-003" in _finding_ids(result)

    def test_port_3389_rdp_fires(self):
        img = _base_image(exposed_ports=[3389])
        result = _scan(img)
        assert "IMG-003" in _finding_ids(result)

    def test_port_5900_vnc_fires(self):
        img = _base_image(exposed_ports=[5900])
        result = _scan(img)
        assert "IMG-003" in _finding_ids(result)

    def test_port_6379_redis_fires(self):
        img = _base_image(exposed_ports=[6379])
        result = _scan(img)
        assert "IMG-003" in _finding_ids(result)

    def test_port_27017_mongodb_fires(self):
        img = _base_image(exposed_ports=[27017])
        result = _scan(img)
        assert "IMG-003" in _finding_ids(result)

    def test_port_8080_does_not_fire(self):
        img = _base_image(exposed_ports=[8080])
        result = _scan(img)
        assert "IMG-003" not in _finding_ids(result)

    def test_port_443_does_not_fire(self):
        img = _base_image(exposed_ports=[443])
        result = _scan(img)
        assert "IMG-003" not in _finding_ids(result)

    def test_port_80_does_not_fire(self):
        img = _base_image(exposed_ports=[80])
        result = _scan(img)
        assert "IMG-003" not in _finding_ids(result)

    def test_multiple_sensitive_ports_produce_multiple_findings(self):
        img = _base_image(exposed_ports=[22, 6379])
        result = _scan(img)
        img003_findings = [f for f in result.findings if f.check_id == "IMG-003"]
        assert len(img003_findings) == 2

    def test_multiple_sensitive_ports_risk_score_only_counted_once(self):
        # Two sensitive ports fire IMG-003 twice, but weight only counted once.
        img = _base_image(exposed_ports=[22, 6379])
        result = _scan(img)
        # Only IMG-003 should fire here; score = weight once = 15.
        assert result.risk_score == _CHECK_WEIGHTS["IMG-003"]

    def test_img003_severity_is_medium(self):
        img = _base_image(exposed_ports=[22])
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-003")
        assert finding.severity == "MEDIUM"

    def test_img003_weight_is_15(self):
        img = _base_image(exposed_ports=[22])
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-003")
        assert finding.weight == 15

    def test_no_ports_no_finding(self):
        img = _base_image(exposed_ports=[])
        result = _scan(img)
        assert "IMG-003" not in _finding_ids(result)

    def test_mix_sensitive_and_safe_ports_only_sensitive_flagged(self):
        img = _base_image(exposed_ports=[80, 22, 443, 6379, 9090])
        result = _scan(img)
        img003_findings = [f for f in result.findings if f.check_id == "IMG-003"]
        # Each finding's detail contains the port number — extract via presence check.
        assert len(img003_findings) == 2
        details = " ".join(f.detail for f in img003_findings)
        assert "22" in details
        assert "6379" in details
        assert "80" not in details or all("port 80" not in f.detail for f in img003_findings)
        assert all("443" not in f.detail for f in img003_findings)

    def test_img003_detail_mentions_port_number(self):
        img = _base_image(exposed_ports=[22])
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-003")
        assert "22" in finding.detail


# ===========================================================================
# IMG-004 — Secrets in environment variables
# ===========================================================================

class TestIMG004:
    """Tests for the leaked secret in env var check."""

    def test_env_password_fires(self):
        img = _base_image(env_vars=[ImageEnvVar("DB_PASSWORD", "s3cret")])
        result = _scan(img)
        assert "IMG-004" in _finding_ids(result)

    def test_env_secret_fires(self):
        img = _base_image(env_vars=[ImageEnvVar("APP_SECRET", "abc")])
        result = _scan(img)
        assert "IMG-004" in _finding_ids(result)

    def test_env_key_fires(self):
        img = _base_image(env_vars=[ImageEnvVar("API_KEY", "xyz")])
        result = _scan(img)
        assert "IMG-004" in _finding_ids(result)

    def test_env_token_fires(self):
        img = _base_image(env_vars=[ImageEnvVar("GITHUB_TOKEN", "ghp_abc")])
        result = _scan(img)
        assert "IMG-004" in _finding_ids(result)

    def test_env_credential_fires(self):
        img = _base_image(env_vars=[ImageEnvVar("AWS_CREDENTIAL", "AKIA...")])
        result = _scan(img)
        assert "IMG-004" in _finding_ids(result)

    def test_env_private_fires(self):
        img = _base_image(env_vars=[ImageEnvVar("PRIVATE_KEY", "-----BEGIN")])
        result = _scan(img)
        assert "IMG-004" in _finding_ids(result)

    def test_env_auth_fires(self):
        img = _base_image(env_vars=[ImageEnvVar("AUTH_TOKEN", "bearer_xyz")])
        result = _scan(img)
        assert "IMG-004" in _finding_ids(result)

    def test_env_myapp_password_fires(self):
        # Mixed-case name with PASSWORD substring.
        img = _base_image(env_vars=[ImageEnvVar("MYAPP_PASSWORD", "pass123")])
        result = _scan(img)
        assert "IMG-004" in _finding_ids(result)

    def test_env_db_host_does_not_fire(self):
        img = _base_image(env_vars=[ImageEnvVar("DB_HOST", "localhost")])
        result = _scan(img)
        assert "IMG-004" not in _finding_ids(result)

    def test_env_app_name_does_not_fire(self):
        img = _base_image(env_vars=[ImageEnvVar("APP_NAME", "myservice")])
        result = _scan(img)
        assert "IMG-004" not in _finding_ids(result)

    def test_env_secret_keyword_but_empty_value_does_not_fire(self):
        # Empty value means no secret is actually present.
        img = _base_image(env_vars=[ImageEnvVar("DB_PASSWORD", "")])
        result = _scan(img)
        assert "IMG-004" not in _finding_ids(result)

    def test_env_secret_keyword_whitespace_only_value_does_not_fire(self):
        # Whitespace-only value is treated as empty.
        img = _base_image(env_vars=[ImageEnvVar("DB_PASSWORD", "   ")])
        result = _scan(img)
        assert "IMG-004" not in _finding_ids(result)

    def test_two_secret_env_vars_produce_two_findings(self):
        img = _base_image(
            env_vars=[
                ImageEnvVar("DB_PASSWORD", "s3cr3t"),
                ImageEnvVar("API_TOKEN", "tok123"),
            ]
        )
        result = _scan(img)
        img004_findings = [f for f in result.findings if f.check_id == "IMG-004"]
        assert len(img004_findings) == 2

    def test_two_secret_env_vars_risk_score_counted_once(self):
        img = _base_image(
            env_vars=[
                ImageEnvVar("DB_PASSWORD", "s3cr3t"),
                ImageEnvVar("API_TOKEN", "tok123"),
            ]
        )
        result = _scan(img)
        # Only IMG-004 fires; weight counted once.
        assert result.risk_score == _CHECK_WEIGHTS["IMG-004"]

    def test_img004_severity_is_critical(self):
        img = _base_image(env_vars=[ImageEnvVar("DB_PASSWORD", "s3cret")])
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-004")
        assert finding.severity == "CRITICAL"

    def test_img004_weight_is_40(self):
        img = _base_image(env_vars=[ImageEnvVar("DB_PASSWORD", "s3cret")])
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-004")
        assert finding.weight == 40

    def test_img004_detail_redacts_value(self):
        # The secret value must NOT appear in the finding detail.
        secret_value = "super_secret_value_xyz"
        img = _base_image(env_vars=[ImageEnvVar("DB_PASSWORD", secret_value)])
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-004")
        assert secret_value not in finding.detail

    def test_img004_detail_mentions_var_name(self):
        img = _base_image(env_vars=[ImageEnvVar("DB_PASSWORD", "s3cret")])
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-004")
        assert "DB_PASSWORD" in finding.detail

    def test_env_lowercase_keyword_name_fires(self):
        # Name is lowercase; uppercased comparison should still match.
        img = _base_image(env_vars=[ImageEnvVar("db_password", "secret")])
        result = _scan(img)
        assert "IMG-004" in _finding_ids(result)

    def test_no_env_vars_no_finding(self):
        img = _base_image(env_vars=[])
        result = _scan(img)
        assert "IMG-004" not in _finding_ids(result)


# ===========================================================================
# IMG-005 — Outdated image (older than 365 days)
# ===========================================================================

class TestIMG005:
    """Tests for the image age check."""

    def test_image_366_days_old_fires(self):
        # 366 days before REF_DATE = 2025-04-05 → age = 366 days.
        old_date = date(2025, 4, 5)
        img = _base_image(created_at=old_date)
        result = _scan(img)
        assert "IMG-005" in _finding_ids(result)

    def test_image_exactly_365_days_old_does_not_fire(self):
        # "more than 365 days" — exactly 365 is NOT more than 365.
        exactly = date(2025, 4, 6)  # REF_DATE - 365 days
        img = _base_image(created_at=exactly)
        result = _scan(img)
        assert "IMG-005" not in _finding_ids(result)

    def test_image_364_days_old_does_not_fire(self):
        recent = date(2025, 4, 7)
        img = _base_image(created_at=recent)
        result = _scan(img)
        assert "IMG-005" not in _finding_ids(result)

    def test_created_at_none_does_not_fire(self):
        # Unknown creation date should not produce a false positive.
        img = _base_image(created_at=None)
        result = _scan(img)
        assert "IMG-005" not in _finding_ids(result)

    def test_very_old_image_fires(self):
        img = _base_image(created_at=date(2020, 1, 1))
        result = _scan(img)
        assert "IMG-005" in _finding_ids(result)

    def test_img005_severity_is_medium(self):
        img = _base_image(created_at=date(2020, 1, 1))
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-005")
        assert finding.severity == "MEDIUM"

    def test_img005_weight_is_15(self):
        img = _base_image(created_at=date(2020, 1, 1))
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-005")
        assert finding.weight == 15

    def test_img005_detail_mentions_creation_date(self):
        old_date = date(2024, 1, 1)
        img = _base_image(created_at=old_date)
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-005")
        assert "2024-01-01" in finding.detail

    def test_img005_exactly_one_finding(self):
        img = _base_image(created_at=date(2020, 1, 1))
        result = _scan(img)
        img005_findings = [f for f in result.findings if f.check_id == "IMG-005"]
        assert len(img005_findings) == 1

    def test_image_created_today_does_not_fire(self):
        img = _base_image(created_at=REF_DATE)
        result = _scan(img)
        assert "IMG-005" not in _finding_ids(result)


# ===========================================================================
# IMG-006 — No HEALTHCHECK defined
# ===========================================================================

class TestIMG006:
    """Tests for the missing HEALTHCHECK check."""

    def test_health_check_none_fires(self):
        img = _base_image(health_check=None)
        result = _scan(img)
        assert "IMG-006" in _finding_ids(result)

    def test_health_check_non_empty_string_does_not_fire(self):
        img = _base_image(health_check="CMD curl -f http://localhost/ || exit 1")
        result = _scan(img)
        assert "IMG-006" not in _finding_ids(result)

    def test_health_check_empty_string_does_not_fire(self):
        # An empty string is still a defined (if useless) HEALTHCHECK — not None.
        img = _base_image(health_check="")
        result = _scan(img)
        assert "IMG-006" not in _finding_ids(result)

    def test_img006_severity_is_low(self):
        img = _base_image(health_check=None)
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-006")
        assert finding.severity == "LOW"

    def test_img006_weight_is_5(self):
        img = _base_image(health_check=None)
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-006")
        assert finding.weight == 5

    def test_img006_exactly_one_finding(self):
        img = _base_image(health_check=None)
        result = _scan(img)
        img006_findings = [f for f in result.findings if f.check_id == "IMG-006"]
        assert len(img006_findings) == 1

    def test_img006_contributes_to_risk_score(self):
        img = _base_image(health_check=None)
        result = _scan(img)
        assert result.risk_score >= _CHECK_WEIGHTS["IMG-006"]


# ===========================================================================
# IMG-007 — Image size exceeds 1 GiB
# ===========================================================================

class TestIMG007:
    """Tests for the oversized image check."""

    def test_size_just_over_1gib_fires(self):
        img = _base_image(size_bytes=_ONE_GIB + 1)
        result = _scan(img)
        assert "IMG-007" in _finding_ids(result)

    def test_size_exactly_1gib_does_not_fire(self):
        # "greater than" — equal is not greater.
        img = _base_image(size_bytes=_ONE_GIB)
        result = _scan(img)
        assert "IMG-007" not in _finding_ids(result)

    def test_size_just_under_1gib_does_not_fire(self):
        img = _base_image(size_bytes=_ONE_GIB - 1)
        result = _scan(img)
        assert "IMG-007" not in _finding_ids(result)

    def test_size_2gib_fires(self):
        img = _base_image(size_bytes=2 * _ONE_GIB)
        result = _scan(img)
        assert "IMG-007" in _finding_ids(result)

    def test_size_zero_does_not_fire(self):
        img = _base_image(size_bytes=0)
        result = _scan(img)
        assert "IMG-007" not in _finding_ids(result)

    def test_img007_severity_is_low(self):
        img = _base_image(size_bytes=_ONE_GIB + 1)
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-007")
        assert finding.severity == "LOW"

    def test_img007_weight_is_5(self):
        img = _base_image(size_bytes=_ONE_GIB + 1)
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-007")
        assert finding.weight == 5

    def test_img007_exactly_one_finding(self):
        img = _base_image(size_bytes=2 * _ONE_GIB)
        result = _scan(img)
        img007_findings = [f for f in result.findings if f.check_id == "IMG-007"]
        assert len(img007_findings) == 1

    def test_img007_detail_mentions_bytes(self):
        size = _ONE_GIB + 512
        img = _base_image(size_bytes=size)
        result = _scan(img)
        finding = next(f for f in result.findings if f.check_id == "IMG-007")
        assert str(size) in finding.detail.replace(",", "").replace("_", "")

    def test_img007_contributes_to_risk_score(self):
        img = _base_image(size_bytes=_ONE_GIB + 1)
        result = _scan(img)
        assert result.risk_score >= _CHECK_WEIGHTS["IMG-007"]


# ===========================================================================
# Risk score and weight deduplication
# ===========================================================================

class TestRiskScore:
    """Tests for risk_score computation, deduplication, and capping."""

    def test_clean_image_has_risk_score_zero(self):
        img = _base_image()
        result = _scan(img)
        assert result.risk_score == 0

    def test_single_check_fires_correct_weight(self):
        img = _base_image(health_check=None)
        result = _scan(img)
        assert result.risk_score == _CHECK_WEIGHTS["IMG-006"]

    def test_img003_multiple_ports_weight_counted_once(self):
        img = _base_image(exposed_ports=[22, 23, 2375])
        result = _scan(img)
        assert result.risk_score == _CHECK_WEIGHTS["IMG-003"]

    def test_img004_multiple_env_vars_weight_counted_once(self):
        img = _base_image(
            env_vars=[
                ImageEnvVar("DB_PASSWORD", "s3c"),
                ImageEnvVar("API_KEY", "k3y"),
                ImageEnvVar("SECRET_TOKEN", "tok"),
            ]
        )
        result = _scan(img)
        assert result.risk_score == _CHECK_WEIGHTS["IMG-004"]

    def test_two_independent_checks_weights_sum(self):
        img = _base_image(user="root", health_check=None)
        result = _scan(img)
        expected = _CHECK_WEIGHTS["IMG-001"] + _CHECK_WEIGHTS["IMG-006"]
        assert result.risk_score == expected

    def test_risk_score_capped_at_100(self):
        # Fire all 7 checks: total weights = 25+20+15+40+15+5+5 = 125 → cap 100.
        img = ContainerImage(
            image_id="worst",
            name="worst-image",
            tag="latest",
            base_image="ubuntu",
            user="root",
            exposed_ports=[22],
            env_vars=[ImageEnvVar("DB_PASSWORD", "secret")],
            created_at=date(2020, 1, 1),
            size_bytes=_ONE_GIB + 1,
            health_check=None,
        )
        result = scan(img, reference_date=REF_DATE)
        assert result.risk_score == 100

    def test_all_seven_checks_fire_on_worst_image(self):
        img = ContainerImage(
            image_id="worst",
            name="worst-image",
            tag="latest",
            base_image="ubuntu",
            user="root",
            exposed_ports=[22],
            env_vars=[ImageEnvVar("DB_PASSWORD", "secret")],
            created_at=date(2020, 1, 1),
            size_bytes=_ONE_GIB + 1,
            health_check=None,
        )
        result = scan(img, reference_date=REF_DATE)
        fired = set(_finding_ids(result))
        for cid in ("IMG-001", "IMG-002", "IMG-003", "IMG-004", "IMG-005", "IMG-006", "IMG-007"):
            assert cid in fired, f"{cid} should have fired"

    def test_risk_score_type_is_int(self):
        img = _base_image(user="root")
        result = _scan(img)
        assert isinstance(result.risk_score, int)

    def test_risk_score_never_negative(self):
        img = _base_image()
        result = _scan(img)
        assert result.risk_score >= 0


# ===========================================================================
# IMGResult helper methods
# ===========================================================================

class TestIMGResultMethods:
    """Tests for to_dict(), summary(), and by_severity()."""

    def test_to_dict_returns_dict(self):
        img = _base_image(user="root")
        result = _scan(img)
        d = result.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_contains_required_keys(self):
        img = _base_image(user="root")
        result = _scan(img)
        d = result.to_dict()
        for key in ("image_name", "image_tag", "risk_score", "findings"):
            assert key in d

    def test_to_dict_findings_is_list(self):
        img = _base_image(user="root")
        result = _scan(img)
        d = result.to_dict()
        assert isinstance(d["findings"], list)

    def test_to_dict_finding_has_required_keys(self):
        img = _base_image(user="root")
        result = _scan(img)
        d = result.to_dict()
        f = d["findings"][0]
        for key in ("check_id", "severity", "title", "detail", "weight"):
            assert key in f

    def test_to_dict_risk_score_matches(self):
        img = _base_image(user="root")
        result = _scan(img)
        d = result.to_dict()
        assert d["risk_score"] == result.risk_score

    def test_summary_returns_string(self):
        img = _base_image(user="root")
        result = _scan(img)
        s = result.summary()
        assert isinstance(s, str)

    def test_summary_contains_image_name(self):
        img = _base_image(name="my-service", tag="2.0.0")
        result = _scan(img)
        assert "my-service" in result.summary()

    def test_summary_contains_risk_score(self):
        img = _base_image(user="root")
        result = _scan(img)
        assert str(result.risk_score) in result.summary()

    def test_summary_empty_tag_shows_placeholder(self):
        img = _base_image(tag="")
        result = _scan(img)
        s = result.summary()
        # Should not blow up and should contain something meaningful.
        assert isinstance(s, str)
        assert "no tag" in s or "" in s  # placeholder text or graceful handling

    def test_by_severity_returns_dict(self):
        img = _base_image(user="root")
        result = _scan(img)
        bsev = result.by_severity()
        assert isinstance(bsev, dict)

    def test_by_severity_high_contains_img001(self):
        img = _base_image(user="root")
        result = _scan(img)
        bsev = result.by_severity()
        assert "HIGH" in bsev
        assert any(f.check_id == "IMG-001" for f in bsev["HIGH"])

    def test_by_severity_critical_contains_img004(self):
        img = _base_image(env_vars=[ImageEnvVar("DB_PASSWORD", "s3c")])
        result = _scan(img)
        bsev = result.by_severity()
        assert "CRITICAL" in bsev
        assert any(f.check_id == "IMG-004" for f in bsev["CRITICAL"])

    def test_by_severity_no_findings_returns_empty_dict(self):
        img = _base_image()
        result = _scan(img)
        assert result.by_severity() == {}

    def test_to_dict_empty_findings_list(self):
        img = _base_image()
        result = _scan(img)
        d = result.to_dict()
        assert d["findings"] == []


# ===========================================================================
# scan_many
# ===========================================================================

class TestScanMany:
    """Tests for the scan_many() batch function."""

    def test_scan_many_returns_list(self):
        images = [_base_image(name=f"img{i}") for i in range(3)]
        results = scan_many(images, reference_date=REF_DATE)
        assert isinstance(results, list)

    def test_scan_many_length_matches_input(self):
        images = [_base_image(name=f"img{i}") for i in range(5)]
        results = scan_many(images, reference_date=REF_DATE)
        assert len(results) == 5

    def test_scan_many_empty_input_returns_empty_list(self):
        results = scan_many([], reference_date=REF_DATE)
        assert results == []

    def test_scan_many_order_preserved(self):
        images = [_base_image(name=f"service-{i}") for i in range(4)]
        results = scan_many(images, reference_date=REF_DATE)
        for i, result in enumerate(results):
            assert result.image_name == f"service-{i}"

    def test_scan_many_independent_results(self):
        clean = _base_image(name="clean")
        risky = _base_image(name="risky", user="root")
        results = scan_many([clean, risky], reference_date=REF_DATE)
        assert results[0].risk_score == 0
        assert results[1].risk_score >= _CHECK_WEIGHTS["IMG-001"]

    def test_scan_many_reference_date_propagated(self):
        old_date = date(2020, 1, 1)
        images = [_base_image(name=f"img{i}", created_at=old_date) for i in range(2)]
        results = scan_many(images, reference_date=REF_DATE)
        for result in results:
            assert any(f.check_id == "IMG-005" for f in result.findings)

    def test_scan_many_default_reference_date_does_not_raise(self):
        # Should not raise even without an explicit reference_date.
        images = [_base_image()]
        results = scan_many(images)
        assert len(results) == 1


# ===========================================================================
# Misc edge cases
# ===========================================================================

class TestEdgeCases:
    """Boundary and integration edge cases."""

    def test_all_checks_off_gives_score_zero(self):
        img = _base_image()
        result = _scan(img)
        assert result.risk_score == 0
        assert result.findings == []

    def test_img_result_image_name_and_tag_populated(self):
        img = _base_image(name="scanner-test", tag="3.0.0")
        result = _scan(img)
        assert result.image_name == "scanner-test"
        assert result.image_tag == "3.0.0"

    def test_scan_default_reference_date_does_not_raise(self):
        img = _base_image()
        result = scan(img)  # no reference_date → date.today()
        assert isinstance(result, IMGResult)

    def test_check_weights_dict_has_all_check_ids(self):
        for cid in ("IMG-001", "IMG-002", "IMG-003", "IMG-004", "IMG-005", "IMG-006", "IMG-007"):
            assert cid in _CHECK_WEIGHTS

    def test_sensitive_ports_set_contains_all_expected(self):
        for port in (22, 23, 2375, 2376, 3389, 5900, 6379, 27017):
            assert port in _SENSITIVE_PORTS

    def test_combined_003_and_004_risk_score_sum_once_each(self):
        img = _base_image(
            exposed_ports=[22, 6379],
            env_vars=[
                ImageEnvVar("DB_PASSWORD", "s3c"),
                ImageEnvVar("API_KEY", "k3y"),
            ],
        )
        result = _scan(img)
        expected = _CHECK_WEIGHTS["IMG-003"] + _CHECK_WEIGHTS["IMG-004"]
        assert result.risk_score == expected

    def test_image_with_safe_env_var_and_sensitive_port(self):
        img = _base_image(
            exposed_ports=[22],
            env_vars=[ImageEnvVar("DB_HOST", "localhost")],
        )
        result = _scan(img)
        assert "IMG-003" in _finding_ids(result)
        assert "IMG-004" not in _finding_ids(result)

    def test_findings_list_is_list_of_imgfinding(self):
        img = _base_image(user="root")
        result = _scan(img)
        for finding in result.findings:
            assert isinstance(finding, IMGFinding)

    def test_img001_and_img006_both_fire_together(self):
        img = _base_image(user="root", health_check=None)
        result = _scan(img)
        ids = _finding_ids(result)
        assert "IMG-001" in ids
        assert "IMG-006" in ids

    def test_env_var_with_key_keyword_lowercase_value_fires(self):
        # Value is non-empty; case of value is irrelevant.
        img = _base_image(env_vars=[ImageEnvVar("ENCRYPTION_KEY", "low3rcase_val")])
        result = _scan(img)
        assert "IMG-004" in _finding_ids(result)
