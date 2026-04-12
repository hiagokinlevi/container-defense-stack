from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
KYVERNO_DIR = ROOT / "policies" / "kyverno"

POLICIES = [
    ("deny-privileged-containers.yaml", "deny-privileged-containers", {"SEC001"}, {"block-privileged-containers"}),
    ("require-non-root-containers.yaml", "require-non-root-containers", {"SEC004"}, {"require-run-as-non-root", "deny-uid-zero"}),
    ("require-read-only-root-fs.yaml", "require-read-only-root-fs", {"SEC003"}, {"require-read-only-root-fs"}),
    ("require-drop-all-capabilities.yaml", "require-drop-all-capabilities", {"SEC005"}, {"require-drop-all-capabilities"}),
    ("require-container-resource-limits.yaml", "require-container-resource-limits", {"SEC006", "SEC007"}, {"require-memory-limits", "require-cpu-limits"}),
    ("deny-host-namespaces.yaml", "deny-host-namespaces", {"SEC010", "SEC011", "SEC012"}, {"deny-host-pid", "deny-host-network", "deny-host-ipc"}),
    ("deny-hostpath-volumes.yaml", "deny-hostpath-volumes", {"SEC014"}, {"deny-hostpath-volumes"}),
]


def _load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def test_kyverno_policy_library_has_expected_files():
    for policy_name, _, _, _ in POLICIES:
        assert (KYVERNO_DIR / policy_name).exists()


def test_kyverno_policies_are_valid_cluster_policies():
    for policy_name, expected_name, rule_ids, expected_rules in POLICIES:
        data = _load_yaml(KYVERNO_DIR / policy_name)
        assert data["apiVersion"] == "kyverno.io/v1"
        assert data["kind"] == "ClusterPolicy"
        assert data["metadata"]["name"] == expected_name
        assert data["spec"]["validationFailureAction"] == "Enforce"
        assert data["spec"]["background"] is True

        rules = data["spec"]["rules"]
        actual_rule_names = {rule["name"] for rule in rules}
        assert actual_rule_names == expected_rules

        rule_text = yaml.safe_dump(rules, sort_keys=True)
        for rule_id in rule_ids:
            assert rule_id in rule_text


def test_kyverno_rules_target_pods_with_validate_blocks():
    for policy_name, _, _, _ in POLICIES:
        data = _load_yaml(KYVERNO_DIR / policy_name)
        for rule in data["spec"]["rules"]:
            kinds = rule["match"]["any"][0]["resources"]["kinds"]
            assert "Pod" in kinds
            validate = rule["validate"]
            assert "message" in validate
            assert "deny" in validate or "foreach" in validate
