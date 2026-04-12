from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = ROOT / "policies" / "gatekeeper" / "constrainttemplates"
CONSTRAINTS_DIR = ROOT / "policies" / "gatekeeper" / "constraints"

POLICIES = [
    (
        "k1nprivilegedcontainer_template.yaml",
        "k1nprivilegedcontainer.yaml",
        "K1nPrivilegedContainer",
        "SEC001",
    ),
    (
        "k1nnonrootcontainer_template.yaml",
        "k1nnonrootcontainer.yaml",
        "K1nNonRootContainer",
        "SEC004",
    ),
    (
        "k1nreadonlyrootfs_template.yaml",
        "k1nreadonlyrootfs.yaml",
        "K1nReadOnlyRootFS",
        "SEC003",
    ),
    (
        "k1ndropallcapabilities_template.yaml",
        "k1ndropallcapabilities.yaml",
        "K1nDropAllCapabilities",
        "SEC005",
    ),
    (
        "k1nresourcelimits_template.yaml",
        "k1nresourcelimits.yaml",
        "K1nResourceLimits",
        "SEC006",
    ),
    (
        "k1ndenyhostnamespaces_template.yaml",
        "k1ndenyhostnamespaces.yaml",
        "K1nDenyHostNamespaces",
        "SEC010",
    ),
    (
        "k1ndenyhostpathvolumes_template.yaml",
        "k1ndenyhostpathvolumes.yaml",
        "K1nDenyHostPathVolumes",
        "SEC014",
    ),
]


def _load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def test_gatekeeper_policy_library_has_expected_files():
    for template_name, constraint_name, _, _ in POLICIES:
        assert (TEMPLATES_DIR / template_name).exists()
        assert (CONSTRAINTS_DIR / constraint_name).exists()


def test_constraint_templates_are_valid_gatekeeper_documents():
    for template_name, _, expected_kind, rule_id in POLICIES:
        data = _load_yaml(TEMPLATES_DIR / template_name)
        assert data["apiVersion"] == "templates.gatekeeper.sh/v1"
        assert data["kind"] == "ConstraintTemplate"
        assert data["spec"]["crd"]["spec"]["names"]["kind"] == expected_kind

        target = data["spec"]["targets"][0]
        assert target["target"] == "admission.k8s.gatekeeper.sh"
        rego = target["rego"]
        assert "violation" in rego
        assert 'input.review.kind.kind == "Pod"' in rego
        assert rule_id in rego


def test_constraints_reference_template_kinds_and_pod_matches():
    for _, constraint_name, expected_kind, _ in POLICIES:
        data = _load_yaml(CONSTRAINTS_DIR / constraint_name)
        assert data["apiVersion"] == "constraints.gatekeeper.sh/v1beta1"
        assert data["kind"] == expected_kind
        assert data["spec"]["enforcementAction"] == "deny"
        kinds = data["spec"]["match"]["kinds"]
        assert {"apiGroups": [""], "kinds": ["Pod"]} in kinds
