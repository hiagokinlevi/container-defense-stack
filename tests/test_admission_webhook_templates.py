from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
ADMISSION_DIR = ROOT / "kubernetes" / "admission"

STACKS = [
    {
        "file": "validating-webhook-stack.yaml",
        "deployment": "pod-security-validating-webhook",
        "service_account": "pod-security-validating-webhook",
        "service_path": "/validate",
        "webhook_kind": "ValidatingWebhookConfiguration",
        "config_name": "pod-security-validating-webhook.k1n.dev",
        "annotation_value": "admission-security/pod-security-validating-webhook-cert",
        "certificate": "pod-security-validating-webhook-cert",
        "issuer": "pod-security-validating-webhook-selfsigned",
        "operations": {"CREATE", "UPDATE"},
    },
    {
        "file": "mutating-webhook-stack.yaml",
        "deployment": "metadata-hardening-mutating-webhook",
        "service_account": "metadata-hardening-mutating-webhook",
        "service_path": "/mutate",
        "webhook_kind": "MutatingWebhookConfiguration",
        "config_name": "metadata-hardening-mutating-webhook.k1n.dev",
        "annotation_value": "admission-security/metadata-hardening-mutating-webhook-cert",
        "certificate": "metadata-hardening-mutating-webhook-cert",
        "issuer": "metadata-hardening-mutating-webhook-selfsigned",
        "operations": {"CREATE"},
    },
]


def _load_documents(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return [doc for doc in yaml.safe_load_all(handle) if doc]


def _index_by_kind(documents: list[dict]) -> dict[str, dict]:
    return {document["kind"]: document for document in documents}


def test_admission_template_files_exist():
    assert (ADMISSION_DIR / "README.md").exists()
    for stack in STACKS:
        assert (ADMISSION_DIR / stack["file"]).exists()


def test_admission_templates_define_hardened_namespaces():
    for stack in STACKS:
        docs = _index_by_kind(_load_documents(ADMISSION_DIR / stack["file"]))
        namespace = docs["Namespace"]
        assert namespace["metadata"]["name"] == "admission-security"
        labels = namespace["metadata"]["labels"]
        assert labels["pod-security.kubernetes.io/enforce"] == "restricted"
        assert labels["pod-security.kubernetes.io/audit"] == "restricted"
        assert labels["pod-security.kubernetes.io/warn"] == "restricted"


def test_admission_templates_harden_webhook_deployments():
    for stack in STACKS:
        docs = _index_by_kind(_load_documents(ADMISSION_DIR / stack["file"]))
        deployment = docs["Deployment"]
        assert deployment["metadata"]["name"] == stack["deployment"]
        assert deployment["spec"]["replicas"] == 2
        pod_spec = deployment["spec"]["template"]["spec"]
        assert pod_spec["serviceAccountName"] == stack["service_account"]
        assert pod_spec["automountServiceAccountToken"] is False
        assert pod_spec["securityContext"]["runAsNonRoot"] is True
        assert pod_spec["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"

        container = pod_spec["containers"][0]
        assert container["name"] == "webhook"
        assert any(arg == "--listen=:8443" for arg in container["args"])
        assert container["securityContext"]["allowPrivilegeEscalation"] is False
        assert container["securityContext"]["readOnlyRootFilesystem"] is True
        assert container["securityContext"]["runAsNonRoot"] is True
        assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
        assert "requests" in container["resources"]
        assert "limits" in container["resources"]
        assert {"name": "tls", "mountPath": "/tls", "readOnly": True} in container["volumeMounts"]
        assert {"name": "tmp", "mountPath": "/tmp"} in container["volumeMounts"]


def test_admission_templates_include_tls_and_service_resources():
    for stack in STACKS:
        docs = _index_by_kind(_load_documents(ADMISSION_DIR / stack["file"]))
        service = docs["Service"]
        assert service["metadata"]["name"] == stack["deployment"]
        assert service["spec"]["ports"][0]["port"] == 443
        assert service["spec"]["ports"][0]["targetPort"] == "https"

        certificate = docs["Certificate"]
        assert certificate["metadata"]["name"] == stack["certificate"]
        assert certificate["spec"]["secretName"] == f"{stack['deployment']}-tls"
        assert certificate["spec"]["issuerRef"]["name"] == stack["issuer"]
        assert f"{stack['deployment']}.admission-security.svc" in certificate["spec"]["dnsNames"]

        issuer = docs["Issuer"]
        assert issuer["metadata"]["name"] == stack["issuer"]
        assert issuer["spec"]["selfSigned"] == {}


def test_admission_templates_require_safe_webhook_defaults():
    for stack in STACKS:
        docs = _index_by_kind(_load_documents(ADMISSION_DIR / stack["file"]))
        configuration = docs[stack["webhook_kind"]]
        assert configuration["metadata"]["name"] == stack["config_name"]
        assert configuration["metadata"]["annotations"]["cert-manager.io/inject-ca-from"] == stack["annotation_value"]

        webhook = configuration["webhooks"][0]
        assert webhook["sideEffects"] == "None"
        assert webhook["timeoutSeconds"] == 5
        assert webhook["failurePolicy"] == "Fail"
        assert webhook["matchPolicy"] == "Equivalent"
        assert webhook["namespaceSelector"]["matchLabels"]["admission.k1n.dev/enforce"] == "true"
        assert webhook["clientConfig"]["service"]["path"] == stack["service_path"]
        assert set(webhook["rules"][0]["operations"]) == stack["operations"]
        assert webhook["rules"][0]["resources"] == ["pods"]

        if stack["webhook_kind"] == "MutatingWebhookConfiguration":
            assert webhook["reinvocationPolicy"] == "Never"


def test_admission_templates_include_pod_disruption_budget():
    for stack in STACKS:
        docs = _index_by_kind(_load_documents(ADMISSION_DIR / stack["file"]))
        pdb = docs["PodDisruptionBudget"]
        assert pdb["metadata"]["name"] == stack["deployment"]
        assert pdb["spec"]["minAvailable"] == 1
        assert pdb["spec"]["selector"]["matchLabels"]["app.kubernetes.io/name"] == stack["deployment"]
