from validators.kubernetes_manifest_validator import validate_manifest


def test_sec041_detects_hostnetwork_true_in_deployment_template():
    docs = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "prod"},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "web"}},
                "template": {
                    "metadata": {"labels": {"app": "web"}},
                    "spec": {
                        "hostNetwork": True,
                        "containers": [{"name": "web", "image": "nginx:1.25"}],
                    },
                },
            },
        }
    ]

    findings = validate_manifest(docs)

    assert any(f.rule_id == "SEC041" for f in findings), findings
