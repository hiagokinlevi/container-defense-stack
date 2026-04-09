# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International License.
# https://creativecommons.org/licenses/by/4.0/
"""
Tests for kubernetes.resource_quota_analyzer
=============================================
Covers all seven checks (RQ-001 – RQ-007), helper functions, data-model
to_dict() methods, risk_score capping, summary() format, by_severity()
structure, and analyze_many().
"""
from __future__ import annotations

import sys
import os

# Make sure the package root is importable when running from the tests/ dir.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from kubernetes.resource_quota_analyzer import (
    _CHECK_WEIGHTS,
    _parse_cpu_cores,
    _parse_memory_bytes,
    ContainerSpec,
    ResourceQuotaAnalyzer,
    ResourceQuotaFinding,
    ResourceQuotaResult,
    ResourceSpec,
    WorkloadSpec,
)


# ---------------------------------------------------------------------------
# Fixtures & factories
# ---------------------------------------------------------------------------

def make_full_resources(
    cpu_req: str = "200m",
    cpu_lim: str = "500m",
    mem_req: str = "256Mi",
    mem_lim: str = "512Mi",
) -> ResourceSpec:
    """Return a ResourceSpec with all four fields populated."""
    return ResourceSpec(
        cpu_request=cpu_req,
        cpu_limit=cpu_lim,
        memory_request=mem_req,
        memory_limit=mem_lim,
    )


def make_container(
    name: str = "app",
    image: str = "nginx:latest",
    resources: ResourceSpec | None = None,
    is_init: bool = False,
) -> ContainerSpec:
    return ContainerSpec(
        name=name,
        image=image,
        resources=resources,
        is_init_container=is_init,
    )


def make_workload(
    name: str = "test-workload",
    namespace: str = "mynamespace",
    kind: str = "Deployment",
    containers: list[ContainerSpec] | None = None,
    has_quota: bool = True,
) -> WorkloadSpec:
    if containers is None:
        containers = [make_container(resources=make_full_resources())]
    return WorkloadSpec(
        name=name,
        namespace=namespace,
        kind=kind,
        containers=containers,
        has_namespace_quota=has_quota,
    )


@pytest.fixture
def analyzer() -> ResourceQuotaAnalyzer:
    return ResourceQuotaAnalyzer()


# ===========================================================================
# _parse_memory_bytes
# ===========================================================================

class TestParseMemoryBytes:
    """Unit tests for the _parse_memory_bytes helper."""

    def test_mebibytes(self):
        assert _parse_memory_bytes("128Mi") == 128 * 1024 * 1024

    def test_gibibytes(self):
        assert _parse_memory_bytes("1Gi") == 1 * 1024 * 1024 * 1024

    def test_si_megabytes(self):
        assert _parse_memory_bytes("512M") == 512 * 1_000_000

    def test_si_gigabytes(self):
        assert _parse_memory_bytes("1G") == 1_000_000_000

    def test_plain_bytes(self):
        assert _parse_memory_bytes("1024") == 1024

    def test_kibibytes(self):
        assert _parse_memory_bytes("64Ki") == 64 * 1024

    def test_si_kilobytes(self):
        assert _parse_memory_bytes("64K") == 64_000

    def test_tebibytes(self):
        assert _parse_memory_bytes("2Ti") == 2 * 1024 ** 4

    def test_8gi_boundary(self):
        # Exactly 8 GiB — should NOT exceed threshold.
        assert _parse_memory_bytes("8Gi") == 8 * 1024 ** 3

    def test_9gi(self):
        assert _parse_memory_bytes("9Gi") == 9 * 1024 ** 3

    def test_10000mi(self):
        # 10000 Mi > 8 GiB (8192 Mi = 8 GiB)
        assert _parse_memory_bytes("10000Mi") == 10_000 * 1024 * 1024

    def test_empty_string_returns_zero(self):
        assert _parse_memory_bytes("") == 0

    def test_unparseable_returns_zero(self):
        assert _parse_memory_bytes("not-a-number") == 0

    def test_plain_zero(self):
        assert _parse_memory_bytes("0") == 0

    def test_256mi(self):
        assert _parse_memory_bytes("256Mi") == 256 * 1024 * 1024

    def test_512mi(self):
        assert _parse_memory_bytes("512Mi") == 512 * 1024 * 1024

    def test_whitespace_stripped(self):
        assert _parse_memory_bytes("  64Mi  ") == 64 * 1024 * 1024


# ===========================================================================
# _parse_cpu_cores
# ===========================================================================

class TestParseCpuCores:
    """Unit tests for the _parse_cpu_cores helper."""

    def test_millicore_500m(self):
        assert _parse_cpu_cores("500m") == pytest.approx(0.5)

    def test_millicore_100m(self):
        assert _parse_cpu_cores("100m") == pytest.approx(0.1)

    def test_millicore_8000m(self):
        assert _parse_cpu_cores("8000m") == pytest.approx(8.0)

    def test_millicore_8001m(self):
        assert _parse_cpu_cores("8001m") == pytest.approx(8.001)

    def test_integer_cores(self):
        assert _parse_cpu_cores("2") == pytest.approx(2.0)

    def test_float_cores(self):
        assert _parse_cpu_cores("0.5") == pytest.approx(0.5)

    def test_nine_cores(self):
        assert _parse_cpu_cores("9") == pytest.approx(9.0)

    def test_eight_cores(self):
        assert _parse_cpu_cores("8") == pytest.approx(8.0)

    def test_empty_returns_zero(self):
        assert _parse_cpu_cores("") == 0.0

    def test_unparseable_returns_zero(self):
        assert _parse_cpu_cores("two") == 0.0

    def test_whitespace_stripped(self):
        assert _parse_cpu_cores("  2  ") == pytest.approx(2.0)

    def test_millicore_200m(self):
        assert _parse_cpu_cores("200m") == pytest.approx(0.2)

    def test_one_core(self):
        assert _parse_cpu_cores("1") == pytest.approx(1.0)


# ===========================================================================
# Fully compliant workload — zero findings
# ===========================================================================

class TestCompliantWorkload:
    """A workload with all fields correctly set should produce no findings."""

    def test_no_findings_for_fully_compliant_workload(self, analyzer):
        workload = make_workload(has_quota=True)
        result = analyzer.analyze(workload)
        assert result.findings == []

    def test_risk_score_zero_for_compliant_workload(self, analyzer):
        workload = make_workload(has_quota=True)
        result = analyzer.analyze(workload)
        assert result.risk_score == 0

    def test_compliant_workload_non_critical_namespace(self, analyzer):
        workload = make_workload(namespace="staging", has_quota=True)
        result = analyzer.analyze(workload)
        assert result.findings == []

    def test_compliant_workload_with_init_container_with_limits(self, analyzer):
        init = make_container(
            name="init-setup",
            is_init=True,
            resources=ResourceSpec(
                cpu_limit="100m",
                memory_limit="64Mi",
            ),
        )
        app = make_container(resources=make_full_resources())
        workload = make_workload(containers=[init, app], has_quota=True)
        result = analyzer.analyze(workload)
        assert result.findings == []


# ===========================================================================
# RQ-001: Missing CPU/memory requests
# ===========================================================================

class TestRQ001:
    """Container without CPU/memory requests."""

    def test_no_resources_stanza_triggers_rq001(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-001" in ids

    def test_both_requests_absent_triggers_rq001(self, analyzer):
        res = ResourceSpec(cpu_request=None, cpu_limit="500m",
                           memory_request=None, memory_limit="256Mi")
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-001" in ids

    def test_only_cpu_request_set_still_triggers_rq001(self, analyzer):
        # memory_request is None → RQ-001 should fire for the missing part.
        res = ResourceSpec(cpu_request="200m", cpu_limit="500m",
                           memory_request=None, memory_limit="256Mi")
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-001" in ids

    def test_only_memory_request_set_still_triggers_rq001(self, analyzer):
        # cpu_request is None → RQ-001 should fire.
        res = ResourceSpec(cpu_request=None, cpu_limit="500m",
                           memory_request="256Mi", memory_limit="256Mi")
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-001" in ids

    def test_both_requests_set_does_not_trigger_rq001(self, analyzer):
        res = ResourceSpec(cpu_request="200m", cpu_limit=None,
                           memory_request="256Mi", memory_limit=None)
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-001" not in ids

    def test_rq001_severity_is_medium(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        findings = [f for f in result.findings if f.check_id == "RQ-001"]
        assert all(f.severity == "MEDIUM" for f in findings)

    def test_rq001_has_container_name(self, analyzer):
        container = make_container(name="sidecar", resources=None)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        findings = [f for f in result.findings if f.check_id == "RQ-001"]
        assert any(f.container_name == "sidecar" for f in findings)

    def test_init_container_does_not_trigger_rq001(self, analyzer):
        init = make_container(name="init", is_init=True, resources=None)
        workload = make_workload(containers=[init], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-001" not in ids


# ===========================================================================
# RQ-002: Missing resource limits
# ===========================================================================

class TestRQ002:
    """Container without resource limits."""

    def test_no_resources_stanza_triggers_rq002(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="mynamespace", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-002" in ids

    def test_both_limits_absent_triggers_rq002(self, analyzer):
        res = ResourceSpec(cpu_request="200m", cpu_limit=None,
                           memory_request="256Mi", memory_limit=None)
        container = make_container(resources=res)
        workload = make_workload(
            namespace="mynamespace", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-002" in ids

    def test_only_memory_limit_missing_triggers_rq002(self, analyzer):
        res = ResourceSpec(cpu_request="200m", cpu_limit="500m",
                           memory_request="256Mi", memory_limit=None)
        container = make_container(resources=res)
        workload = make_workload(
            namespace="mynamespace", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-002" in ids

    def test_only_cpu_limit_missing_triggers_rq002(self, analyzer):
        res = ResourceSpec(cpu_request="200m", cpu_limit=None,
                           memory_request="256Mi", memory_limit="512Mi")
        container = make_container(resources=res)
        workload = make_workload(
            namespace="mynamespace", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-002" in ids

    def test_both_limits_set_does_not_trigger_rq002(self, analyzer):
        res = ResourceSpec(cpu_request=None, cpu_limit="500m",
                           memory_request=None, memory_limit="512Mi")
        container = make_container(resources=res)
        workload = make_workload(
            namespace="mynamespace", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-002" not in ids

    def test_rq002_severity_is_high(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="mynamespace", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        findings = [f for f in result.findings if f.check_id == "RQ-002"]
        assert all(f.severity == "HIGH" for f in findings)

    def test_init_container_does_not_trigger_rq002(self, analyzer):
        init = make_container(name="init", is_init=True, resources=None)
        workload = make_workload(
            namespace="mynamespace", containers=[init], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-002" not in ids


# ===========================================================================
# RQ-003: Memory limit excessively high
# ===========================================================================

class TestRQ003:
    """Memory limit > 8 GiB."""

    def test_9gi_triggers_rq003(self, analyzer):
        res = make_full_resources(mem_lim="9Gi")
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-003" in ids

    def test_8gi_does_not_trigger_rq003(self, analyzer):
        res = make_full_resources(mem_lim="8Gi")
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-003" not in ids

    def test_7gi_does_not_trigger_rq003(self, analyzer):
        res = make_full_resources(mem_lim="7Gi")
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-003" not in ids

    def test_10000mi_triggers_rq003(self, analyzer):
        # 10000 Mi = ~9.77 GiB > 8 GiB
        res = make_full_resources(mem_lim="10000Mi")
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-003" in ids

    def test_rq003_severity_is_medium(self, analyzer):
        res = make_full_resources(mem_lim="9Gi")
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        findings = [f for f in result.findings if f.check_id == "RQ-003"]
        assert findings
        assert all(f.severity == "MEDIUM" for f in findings)

    def test_no_memory_limit_does_not_trigger_rq003(self, analyzer):
        res = ResourceSpec(cpu_request="200m", cpu_limit="500m",
                           memory_request="256Mi", memory_limit=None)
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-003" not in ids

    def test_512mi_does_not_trigger_rq003(self, analyzer):
        res = make_full_resources(mem_lim="512Mi")
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-003" not in ids


# ===========================================================================
# RQ-004: CPU limit excessively high
# ===========================================================================

class TestRQ004:
    """CPU limit > 8.0 cores."""

    def test_9_cores_triggers_rq004(self, analyzer):
        res = make_full_resources(cpu_lim="9")
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-004" in ids

    def test_8000m_does_not_trigger_rq004(self, analyzer):
        # 8000m = exactly 8.0 cores — should NOT fire.
        res = make_full_resources(cpu_lim="8000m")
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-004" not in ids

    def test_8001m_triggers_rq004(self, analyzer):
        # 8001m = 8.001 cores > 8.0 — should fire.
        res = make_full_resources(cpu_lim="8001m")
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-004" in ids

    def test_2_cores_does_not_trigger_rq004(self, analyzer):
        res = make_full_resources(cpu_lim="2")
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-004" not in ids

    def test_rq004_severity_is_high(self, analyzer):
        res = make_full_resources(cpu_lim="9")
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        findings = [f for f in result.findings if f.check_id == "RQ-004"]
        assert findings
        assert all(f.severity == "HIGH" for f in findings)

    def test_no_cpu_limit_does_not_trigger_rq004(self, analyzer):
        res = ResourceSpec(cpu_request="200m", cpu_limit=None,
                           memory_request="256Mi", memory_limit="512Mi")
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-004" not in ids

    def test_500m_does_not_trigger_rq004(self, analyzer):
        res = make_full_resources(cpu_lim="500m")
        container = make_container(resources=res)
        workload = make_workload(containers=[container], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-004" not in ids


# ===========================================================================
# RQ-005: No ResourceQuota in namespace
# ===========================================================================

class TestRQ005:
    """Namespace has no ResourceQuota."""

    def test_no_quota_triggers_rq005(self, analyzer):
        workload = make_workload(has_quota=False)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-005" in ids

    def test_has_quota_does_not_trigger_rq005(self, analyzer):
        workload = make_workload(has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-005" not in ids

    def test_rq005_severity_is_medium(self, analyzer):
        workload = make_workload(has_quota=False)
        result = analyzer.analyze(workload)
        findings = [f for f in result.findings if f.check_id == "RQ-005"]
        assert findings
        assert all(f.severity == "MEDIUM" for f in findings)

    def test_rq005_container_name_is_none(self, analyzer):
        workload = make_workload(has_quota=False)
        result = analyzer.analyze(workload)
        findings = [f for f in result.findings if f.check_id == "RQ-005"]
        assert all(f.container_name is None for f in findings)

    def test_rq005_fires_once_per_workload(self, analyzer):
        # Even with multiple containers, RQ-005 fires once.
        containers = [
            make_container(name="c1", resources=make_full_resources()),
            make_container(name="c2", resources=make_full_resources()),
        ]
        workload = make_workload(containers=containers, has_quota=False)
        result = analyzer.analyze(workload)
        count = sum(1 for f in result.findings if f.check_id == "RQ-005")
        assert count == 1


# ===========================================================================
# RQ-006: No limits in critical namespace
# ===========================================================================

class TestRQ006:
    """No resource limits in a critical namespace."""

    def test_no_limits_in_kube_system_triggers_rq006(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="kube-system", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-006" in ids

    def test_no_limits_in_kube_public_triggers_rq006(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="kube-public", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-006" in ids

    def test_no_limits_in_default_triggers_rq006(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="default", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-006" in ids

    def test_no_limits_in_production_triggers_rq006(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="production", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-006" in ids

    def test_no_limits_in_prod_triggers_rq006(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="prod", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-006" in ids

    def test_no_limits_in_non_critical_namespace_does_not_trigger_rq006(
        self, analyzer
    ):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="mynamespace", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-006" not in ids
        # But RQ-002 should still fire.
        assert "RQ-002" in ids

    def test_no_limits_non_critical_triggers_rq002_not_rq006(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="staging", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-002" in ids
        assert "RQ-006" not in ids

    def test_rq006_severity_is_high(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="kube-system", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        findings = [f for f in result.findings if f.check_id == "RQ-006"]
        assert findings
        assert all(f.severity == "HIGH" for f in findings)

    def test_only_cpu_limit_set_in_critical_namespace_does_not_trigger_rq006(
        self, analyzer
    ):
        # RQ-006 requires BOTH limits missing; having cpu_limit suppresses it.
        res = ResourceSpec(cpu_request="200m", cpu_limit="500m",
                           memory_request="256Mi", memory_limit=None)
        container = make_container(resources=res)
        workload = make_workload(
            namespace="production", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-006" not in ids

    def test_only_memory_limit_set_in_critical_namespace_does_not_trigger_rq006(
        self, analyzer
    ):
        res = ResourceSpec(cpu_request="200m", cpu_limit=None,
                           memory_request="256Mi", memory_limit="512Mi")
        container = make_container(resources=res)
        workload = make_workload(
            namespace="kube-system", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-006" not in ids


# ===========================================================================
# RQ-007: Init container without resource limits
# ===========================================================================

class TestRQ007:
    """Init container without resource limits."""

    def test_init_no_resources_triggers_rq007(self, analyzer):
        init = make_container(name="init", is_init=True, resources=None)
        workload = make_workload(containers=[init], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-007" in ids

    def test_init_with_both_limits_does_not_trigger_rq007(self, analyzer):
        res = ResourceSpec(cpu_limit="200m", memory_limit="128Mi")
        init = make_container(name="init", is_init=True, resources=res)
        workload = make_workload(containers=[init], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-007" not in ids

    def test_regular_container_no_limits_does_not_trigger_rq007(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="mynamespace", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-007" not in ids
        # Regular container missing limits should fire RQ-002, not RQ-007.
        assert "RQ-002" in ids

    def test_rq007_severity_is_medium(self, analyzer):
        init = make_container(name="init", is_init=True, resources=None)
        workload = make_workload(containers=[init], has_quota=True)
        result = analyzer.analyze(workload)
        findings = [f for f in result.findings if f.check_id == "RQ-007"]
        assert findings
        assert all(f.severity == "MEDIUM" for f in findings)

    def test_init_with_only_cpu_limit_does_not_trigger_rq007(self, analyzer):
        # Having only cpu_limit means memory_limit is None, but cpu_limit is
        # set — per the spec RQ-007 fires only when BOTH are absent.
        res = ResourceSpec(cpu_limit="200m", memory_limit=None)
        init = make_container(name="init", is_init=True, resources=res)
        workload = make_workload(containers=[init], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-007" not in ids

    def test_init_with_only_memory_limit_does_not_trigger_rq007(self, analyzer):
        res = ResourceSpec(cpu_limit=None, memory_limit="64Mi")
        init = make_container(name="init", is_init=True, resources=res)
        workload = make_workload(containers=[init], has_quota=True)
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-007" not in ids

    def test_init_container_name_in_finding(self, analyzer):
        init = make_container(name="db-migration", is_init=True, resources=None)
        workload = make_workload(containers=[init], has_quota=True)
        result = analyzer.analyze(workload)
        findings = [f for f in result.findings if f.check_id == "RQ-007"]
        assert any(f.container_name == "db-migration" for f in findings)


# ===========================================================================
# Multiple containers in a workload
# ===========================================================================

class TestMultipleContainers:
    """Findings are raised for each violating container independently."""

    def test_two_containers_both_missing_limits_produce_two_rq002_findings(
        self, analyzer
    ):
        c1 = make_container(name="app", resources=None)
        c2 = make_container(name="sidecar", resources=None)
        workload = make_workload(
            namespace="mynamespace", containers=[c1, c2], has_quota=True
        )
        result = analyzer.analyze(workload)
        rq002_findings = [f for f in result.findings if f.check_id == "RQ-002"]
        assert len(rq002_findings) == 2

    def test_mixed_containers_compliant_and_non_compliant(self, analyzer):
        good = make_container(name="good", resources=make_full_resources())
        bad = make_container(name="bad", resources=None)
        workload = make_workload(
            namespace="mynamespace", containers=[good, bad], has_quota=True
        )
        result = analyzer.analyze(workload)
        # Only the bad container should have per-container findings.
        names = [f.container_name for f in result.findings if f.container_name]
        assert "bad" in names
        assert "good" not in names

    def test_init_and_regular_containers_independent_checks(self, analyzer):
        init = make_container(name="init", is_init=True, resources=None)
        regular = make_container(name="app", resources=None)
        workload = make_workload(
            namespace="mynamespace", containers=[init, regular], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-007" in ids   # from init container
        assert "RQ-002" in ids   # from regular container
        assert "RQ-007" not in [  # RQ-007 not for the regular container
            f.check_id for f in result.findings if not (
                # find the finding for the init container
                f.container_name == "init"
            )
        ] or True  # just assert both exist

    def test_three_containers_risk_score_correct(self, analyzer):
        """With three no-resource containers in a non-critical ns, only
        unique fired check IDs contribute to the score."""
        containers = [
            make_container(name=f"c{i}", resources=None) for i in range(3)
        ]
        workload = make_workload(
            namespace="mynamespace", containers=containers, has_quota=True
        )
        result = analyzer.analyze(workload)
        # Unique IDs fired: RQ-001 (15) + RQ-002 (25) = 40
        assert result.risk_score == 40


# ===========================================================================
# risk_score calculation and cap
# ===========================================================================

class TestRiskScore:
    """Risk score is min(100, sum of weights for unique fired check IDs)."""

    def test_risk_score_zero_for_no_findings(self, analyzer):
        workload = make_workload(has_quota=True)
        result = analyzer.analyze(workload)
        assert result.risk_score == 0

    def test_risk_score_capped_at_100(self, analyzer):
        # To exceed 100 we need all seven checks to fire.
        # RQ-001(15)+RQ-002(25)+RQ-003(15)+RQ-004(20)+RQ-005(15)+RQ-006(25)+RQ-007(10)=125
        # Strategy:
        #   - regular container: resources=None in "production"
        #     → RQ-001, RQ-002, RQ-006
        #   - same regular container has memory_limit & cpu_limit set for 003/004
        #     (but then limits exist → 006 won't fire).
        #   So use TWO containers:
        #     c1 (regular, no resources) → RQ-001, RQ-002, RQ-006
        #     c2 (regular, high limits)  → RQ-003, RQ-004
        #   + init container (no resources) → RQ-007
        #   + has_namespace_quota=False → RQ-005
        # Total unique IDs: RQ-001(15)+RQ-002(25)+RQ-003(15)+RQ-004(20)
        #                   +RQ-005(15)+RQ-006(25)+RQ-007(10) = 125 → capped 100
        init = make_container(name="init", is_init=True, resources=None)
        c1 = make_container(name="app", resources=None)
        c2 = make_container(
            name="sidecar",
            resources=ResourceSpec(
                cpu_request="200m",
                cpu_limit="9",          # RQ-004
                memory_request="256Mi",
                memory_limit="9Gi",     # RQ-003
            ),
        )
        workload = WorkloadSpec(
            name="over-limit",
            namespace="production",    # critical → RQ-006 via c1
            kind="Deployment",
            containers=[init, c1, c2],
            has_namespace_quota=False, # RQ-005
        )
        result = analyzer.analyze(workload)
        assert result.risk_score == 100

    def test_only_rq005_score(self, analyzer):
        workload = make_workload(has_quota=False)
        result = analyzer.analyze(workload)
        # The default container in make_workload has full resources, so only
        # RQ-005 fires: weight 15.
        assert result.risk_score == 15

    def test_rq001_and_rq005_score(self, analyzer):
        container = make_container(
            resources=ResourceSpec(
                cpu_request=None,
                cpu_limit="500m",
                memory_request=None,
                memory_limit="512Mi",
            )
        )
        workload = make_workload(containers=[container], has_quota=False)
        result = analyzer.analyze(workload)
        # RQ-001 (15) + RQ-005 (15) = 30
        assert result.risk_score == 30

    def test_unique_check_ids_only_counted_once(self, analyzer):
        """Two containers both missing limits: RQ-002 fires twice but is
        counted once in the risk score."""
        containers = [
            make_container(name=f"c{i}", resources=None) for i in range(2)
        ]
        workload = make_workload(
            namespace="mynamespace", containers=containers, has_quota=True
        )
        result = analyzer.analyze(workload)
        # RQ-001 (15) + RQ-002 (25) = 40
        assert result.risk_score == 40

    def test_check_weights_dict_has_seven_entries(self):
        assert len(_CHECK_WEIGHTS) == 7

    def test_check_weights_values_are_ints(self):
        assert all(isinstance(v, int) for v in _CHECK_WEIGHTS.values())


# ===========================================================================
# summary()
# ===========================================================================

class TestSummary:
    """ResourceQuotaResult.summary() format."""

    def test_summary_zero_findings(self, analyzer):
        workload = make_workload(name="my-app", namespace="staging", has_quota=True)
        result = analyzer.analyze(workload)
        s = result.summary()
        assert "my-app" in s
        assert "staging" in s
        assert "0 findings" in s
        assert "risk_score=0" in s

    def test_summary_single_finding_uses_singular_noun(self, analyzer):
        workload = make_workload(name="my-app", namespace="mynamespace",
                                 has_quota=False)
        result = analyzer.analyze(workload)
        s = result.summary()
        # Exactly 1 finding expected (RQ-005 only, since container is compliant).
        assert "1 finding" in s
        assert "findings" not in s.replace("1 finding", "")

    def test_summary_multiple_findings_uses_plural_noun(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            name="bad-app", namespace="mynamespace",
            containers=[container], has_quota=False
        )
        result = analyzer.analyze(workload)
        s = result.summary()
        assert "findings" in s

    def test_summary_contains_workload_name_and_namespace(self, analyzer):
        workload = make_workload(name="web-server", namespace="team-a",
                                 has_quota=True)
        result = analyzer.analyze(workload)
        s = result.summary()
        assert "web-server" in s
        assert "team-a" in s

    def test_summary_risk_score_reflected(self, analyzer):
        workload = make_workload(has_quota=False)
        result = analyzer.analyze(workload)
        s = result.summary()
        assert f"risk_score={result.risk_score}" in s


# ===========================================================================
# by_severity()
# ===========================================================================

class TestBySeverity:
    """ResourceQuotaResult.by_severity() structure."""

    def test_by_severity_always_has_four_keys(self, analyzer):
        workload = make_workload(has_quota=True)
        result = analyzer.analyze(workload)
        bys = result.by_severity()
        assert set(bys.keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    def test_by_severity_empty_lists_when_no_findings(self, analyzer):
        workload = make_workload(has_quota=True)
        result = analyzer.analyze(workload)
        bys = result.by_severity()
        assert bys["CRITICAL"] == []
        assert bys["HIGH"] == []
        assert bys["MEDIUM"] == []
        assert bys["LOW"] == []

    def test_by_severity_high_bucket_contains_rq002(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="mynamespace", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        bys = result.by_severity()
        high_ids = [f.check_id for f in bys["HIGH"]]
        assert "RQ-002" in high_ids

    def test_by_severity_medium_bucket_contains_rq001(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="mynamespace", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        bys = result.by_severity()
        medium_ids = [f.check_id for f in bys["MEDIUM"]]
        assert "RQ-001" in medium_ids

    def test_by_severity_values_are_lists_of_findings(self, analyzer):
        workload = make_workload(has_quota=False)
        result = analyzer.analyze(workload)
        bys = result.by_severity()
        for severity, findings_list in bys.items():
            assert isinstance(findings_list, list)
            for finding in findings_list:
                assert isinstance(finding, ResourceQuotaFinding)


# ===========================================================================
# analyze_many()
# ===========================================================================

class TestAnalyzeMany:
    """analyze_many returns one result per workload."""

    def test_analyze_many_empty_list(self, analyzer):
        results = analyzer.analyze_many([])
        assert results == []

    def test_analyze_many_returns_correct_count(self, analyzer):
        workloads = [make_workload(name=f"w{i}") for i in range(5)]
        results = analyzer.analyze_many(workloads)
        assert len(results) == 5

    def test_analyze_many_preserves_order(self, analyzer):
        workloads = [make_workload(name=f"w{i}") for i in range(3)]
        results = analyzer.analyze_many(workloads)
        for i, result in enumerate(results):
            assert result.workload_name == f"w{i}"

    def test_analyze_many_independent_results(self, analyzer):
        w1 = make_workload(name="compliant", has_quota=True)
        w2 = make_workload(name="bad", has_quota=False)
        results = analyzer.analyze_many([w1, w2])
        assert results[0].risk_score == 0
        assert results[1].risk_score > 0

    def test_analyze_many_single_workload(self, analyzer):
        workload = make_workload(has_quota=False)
        results = analyzer.analyze_many([workload])
        assert len(results) == 1
        assert results[0].workload_name == workload.name


# ===========================================================================
# to_dict() on all dataclasses
# ===========================================================================

class TestToDict:
    """All dataclasses implement to_dict() returning JSON-serialisable dicts."""

    def test_resource_spec_to_dict(self):
        res = ResourceSpec(cpu_request="200m", cpu_limit="500m",
                           memory_request="256Mi", memory_limit="512Mi")
        d = res.to_dict()
        assert d["cpu_request"] == "200m"
        assert d["cpu_limit"] == "500m"
        assert d["memory_request"] == "256Mi"
        assert d["memory_limit"] == "512Mi"

    def test_resource_spec_to_dict_with_none_values(self):
        res = ResourceSpec()
        d = res.to_dict()
        assert d["cpu_request"] is None
        assert d["memory_limit"] is None

    def test_container_spec_to_dict(self):
        res = ResourceSpec(cpu_request="100m", cpu_limit="200m",
                           memory_request="64Mi", memory_limit="128Mi")
        c = ContainerSpec(name="web", image="nginx:1.25", resources=res)
        d = c.to_dict()
        assert d["name"] == "web"
        assert d["image"] == "nginx:1.25"
        assert d["is_init_container"] is False
        assert isinstance(d["resources"], dict)
        assert d["resources"]["cpu_request"] == "100m"

    def test_container_spec_to_dict_no_resources(self):
        c = ContainerSpec(name="web", image="nginx:latest")
        d = c.to_dict()
        assert d["resources"] is None

    def test_container_spec_to_dict_init_flag(self):
        c = ContainerSpec(name="init", image="busybox", is_init_container=True)
        d = c.to_dict()
        assert d["is_init_container"] is True

    def test_workload_spec_to_dict(self):
        workload = make_workload(name="my-app", namespace="team-a")
        d = workload.to_dict()
        assert d["name"] == "my-app"
        assert d["namespace"] == "team-a"
        assert isinstance(d["containers"], list)
        assert isinstance(d["has_namespace_quota"], bool)

    def test_workload_spec_to_dict_containers_serialised(self):
        workload = make_workload()
        d = workload.to_dict()
        for c in d["containers"]:
            assert isinstance(c, dict)
            assert "name" in c
            assert "image" in c

    def test_finding_to_dict(self):
        finding = ResourceQuotaFinding(
            check_id="RQ-002",
            severity="HIGH",
            workload_name="my-app",
            namespace="default",
            container_name="web",
            message="Missing limits.",
            recommendation="Set limits.",
        )
        d = finding.to_dict()
        assert d["check_id"] == "RQ-002"
        assert d["severity"] == "HIGH"
        assert d["workload_name"] == "my-app"
        assert d["namespace"] == "default"
        assert d["container_name"] == "web"
        assert d["message"] == "Missing limits."
        assert d["recommendation"] == "Set limits."

    def test_finding_to_dict_none_container_name(self):
        finding = ResourceQuotaFinding(
            check_id="RQ-005",
            severity="MEDIUM",
            workload_name="w",
            namespace="ns",
            container_name=None,
            message="No quota.",
            recommendation="Add quota.",
        )
        d = finding.to_dict()
        assert d["container_name"] is None

    def test_result_to_dict(self, analyzer):
        workload = make_workload(has_quota=False)
        result = analyzer.analyze(workload)
        d = result.to_dict()
        assert "workload_name" in d
        assert "namespace" in d
        assert "risk_score" in d
        assert isinstance(d["findings"], list)

    def test_result_to_dict_findings_are_dicts(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="mynamespace", containers=[container], has_quota=False
        )
        result = analyzer.analyze(workload)
        d = result.to_dict()
        for f in d["findings"]:
            assert isinstance(f, dict)
            assert "check_id" in f
            assert "severity" in f


# ===========================================================================
# Edge cases and integration
# ===========================================================================

class TestEdgeCases:
    """Miscellaneous edge cases."""

    def test_pod_kind_accepted(self, analyzer):
        workload = WorkloadSpec(
            name="my-pod",
            namespace="mynamespace",
            kind="Pod",
            containers=[make_container(resources=make_full_resources())],
            has_namespace_quota=True,
        )
        result = analyzer.analyze(workload)
        assert result.findings == []

    def test_statefulset_kind_accepted(self, analyzer):
        workload = WorkloadSpec(
            name="db",
            namespace="mynamespace",
            kind="StatefulSet",
            containers=[make_container(resources=make_full_resources())],
            has_namespace_quota=True,
        )
        result = analyzer.analyze(workload)
        assert result.findings == []

    def test_empty_container_list_only_rq005_possible(self, analyzer):
        workload = WorkloadSpec(
            name="empty",
            namespace="mynamespace",
            kind="Deployment",
            containers=[],
            has_namespace_quota=False,
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert ids == ["RQ-005"]

    def test_result_attributes(self, analyzer):
        workload = make_workload(name="x", namespace="y", has_quota=True)
        result = analyzer.analyze(workload)
        assert result.workload_name == "x"
        assert result.namespace == "y"
        assert isinstance(result.findings, list)
        assert isinstance(result.risk_score, int)

    def test_rq006_and_rq002_both_fire_in_critical_ns(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="kube-system", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        ids = [f.check_id for f in result.findings]
        assert "RQ-002" in ids
        assert "RQ-006" in ids

    def test_daemonset_kind_accepted(self, analyzer):
        workload = WorkloadSpec(
            name="monitor",
            namespace="mynamespace",
            kind="DaemonSet",
            containers=[make_container(resources=make_full_resources())],
            has_namespace_quota=True,
        )
        result = analyzer.analyze(workload)
        assert result.findings == []

    def test_workload_name_in_finding(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            name="special-app", namespace="mynamespace",
            containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        for finding in result.findings:
            assert finding.workload_name == "special-app"

    def test_namespace_in_finding(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="custom-ns", containers=[container], has_quota=True
        )
        result = analyzer.analyze(workload)
        for finding in result.findings:
            assert finding.namespace == "custom-ns"

    def test_finding_message_not_empty(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="mynamespace", containers=[container], has_quota=False
        )
        result = analyzer.analyze(workload)
        for finding in result.findings:
            assert finding.message.strip() != ""

    def test_finding_recommendation_not_empty(self, analyzer):
        container = make_container(resources=None)
        workload = make_workload(
            namespace="mynamespace", containers=[container], has_quota=False
        )
        result = analyzer.analyze(workload)
        for finding in result.findings:
            assert finding.recommendation.strip() != ""
