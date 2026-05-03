from validators.k8s_manifest_validator import RULES, validate_manifest


def test_sec031_fails_on_pod_template_hostpath():
    manifest = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "bad-hostpath"},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "x"}},
            "template": {
                "metadata": {"labels": {"app": "x"}},
                "spec": {
                    "containers": [{"name": "app", "image": "nginx"}],
                    "volumes": [
                        {
                            "name": "host",
                            "hostPath": {"path": "/var/run/docker.sock", "type": "Socket"},
                        }
                    ],
                },
            },
        },
    }

    findings = validate_manifest(manifest)
    assert any(f["rule_id"] == "SEC031" for f in findings)


def test_sec031_passes_on_safe_volume_types():
    manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "good-volumes"},
        "spec": {
            "containers": [{"name": "app", "image": "nginx"}],
            "volumes": [
                {"name": "cfg", "configMap": {"name": "app-config"}},
                {"name": "cache", "emptyDir": {}},
            ],
        },
    }

    findings = validate_manifest(manifest)
    assert not any(f["rule_id"] == "SEC031" for f in findings)


def test_sec031_rule_metadata_has_expected_guidance():
    rule = RULES["SEC031"]
    assert rule["severity"] == "HIGH"
    assert "ConfigMap" in rule["remediation"]
    assert "Secret" in rule["remediation"]
    assert "PersistentVolumeClaim" in rule["remediation"]
    assert "emptyDir" in rule["remediation"]
