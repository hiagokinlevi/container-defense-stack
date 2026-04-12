from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
OPA_DIR = ROOT / "policies" / "opa"

POLICIES = [
    ("deny_privileged.rego", "SEC001"),
    ("require_non_root.rego", "SEC004"),
    ("require_read_only_root_fs.rego", "SEC003"),
    ("require_resource_limits.rego", "SEC006"),
    ("require_drop_all_capabilities.rego", "SEC005"),
    ("deny_host_namespaces.rego", "SEC010"),
    ("deny_hostpath_volumes.rego", "SEC014"),
]


def test_opa_policy_library_has_expected_files():
    for policy_name, _ in POLICIES:
        assert (OPA_DIR / policy_name).exists()


def test_opa_policies_target_pod_admission_and_carry_rule_ids():
    for policy_name, rule_id in POLICIES:
        text = (OPA_DIR / policy_name).read_text(encoding="utf-8")
        assert "input.request.kind.kind == \"Pod\"" in text
        assert rule_id in text
        assert "deny[msg]" in text
