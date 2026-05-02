from validators.kubernetes_validator import KubernetesValidator


def test_sec027_fails_when_container_missing_drop_all():
    manifest = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "api"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "image": "nginx:1.25",
                            "securityContext": {
                                "capabilities": {"drop": ["NET_RAW"]}
                            },
                        }
                    ]
                }
            }
        },
    }

    issues = KubernetesValidator().validate_manifest(manifest)
    sec027 = [i for i in issues if i.rule_id == "SEC027"]
    assert len(sec027) == 1
    assert "drop: ['ALL']" in sec027[0].message


def test_sec027_fails_for_initcontainer_missing_drop_all():
    manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "worker"},
        "spec": {
            "initContainers": [
                {
                    "name": "init-db",
                    "image": "busybox",
                    "securityContext": {"capabilities": {"drop": []}},
                }
            ],
            "containers": [
                {
                    "name": "main",
                    "image": "busybox",
                    "securityContext": {"capabilities": {"drop": ["ALL"]}},
                }
            ],
        },
    }

    issues = KubernetesValidator().validate_manifest(manifest)
    sec027 = [i for i in issues if i.rule_id == "SEC027"]
    assert len(sec027) == 1
    assert sec027[0].container == "init-db"


def test_sec027_passes_when_all_containers_drop_all():
    manifest = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "secure-api"},
        "spec": {
            "template": {
                "spec": {
                    "initContainers": [
                        {
                            "name": "init",
                            "image": "busybox",
                            "securityContext": {"capabilities": {"drop": ["ALL"]}},
                        }
                    ],
                    "containers": [
                        {
                            "name": "app",
                            "image": "nginx:1.25",
                            "securityContext": {"capabilities": {"drop": ["ALL"]}},
                        }
                    ],
                }
            }
        },
    }

    issues = KubernetesValidator().validate_manifest(manifest)
    assert not [i for i in issues if i.rule_id == "SEC027"]
