from validators.kubernetes_manifest_validator import validate_manifest


def test_sec022_flags_missing_or_false_read_only_root_filesystem():
    manifest = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "demo"},
        "spec": {
            "selector": {"matchLabels": {"app": "demo"}},
            "template": {
                "metadata": {"labels": {"app": "demo"}},
                "spec": {
                    "initContainers": [
                        {
                            "name": "init-a",
                            "image": "busybox",
                            "securityContext": {"readOnlyRootFilesystem": False},
                        }
                    ],
                    "containers": [
                        {
                            "name": "app",
                            "image": "nginx"
                        }
                    ],
                },
            },
        },
    }

    findings = validate_manifest(manifest)
    sec022 = [f for f in findings if f.rule_id == "SEC022"]
    assert len(sec022) == 2


def test_sec022_passes_when_explicitly_true_for_all_containers():
    manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "demo-pod"},
        "spec": {
            "initContainers": [
                {
                    "name": "init-a",
                    "image": "busybox",
                    "securityContext": {"readOnlyRootFilesystem": True},
                }
            ],
            "containers": [
                {
                    "name": "app",
                    "image": "nginx",
                    "securityContext": {"readOnlyRootFilesystem": True},
                }
            ],
        },
    }

    findings = validate_manifest(manifest)
    sec022 = [f for f in findings if f.rule_id == "SEC022"]
    assert sec022 == []
