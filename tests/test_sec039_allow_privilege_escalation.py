from validators.kubernetes_validator import validate_manifest_resource


def test_sec039_pass_for_containers_and_initcontainers():
    manifest = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "ok"},
        "spec": {
            "template": {
                "spec": {
                    "initContainers": [
                        {
                            "name": "init-ok",
                            "image": "busybox",
                            "securityContext": {"allowPrivilegeEscalation": False},
                        }
                    ],
                    "containers": [
                        {
                            "name": "app-ok",
                            "image": "nginx",
                            "securityContext": {"allowPrivilegeEscalation": False},
                        }
                    ],
                }
            }
        },
    }

    findings = validate_manifest_resource(manifest)
    sec039 = [f for f in findings if f.rule_id == "SEC039"]
    assert sec039 == []


def test_sec039_fail_for_missing_and_true_values():
    manifest = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": "bad"},
        "spec": {
            "template": {
                "spec": {
                    "initContainers": [
                        {
                            "name": "init-missing",
                            "image": "busybox",
                        }
                    ],
                    "containers": [
                        {
                            "name": "app-true",
                            "image": "nginx",
                            "securityContext": {"allowPrivilegeEscalation": True},
                        }
                    ],
                }
            }
        },
    }

    findings = validate_manifest_resource(manifest)
    sec039 = [f for f in findings if f.rule_id == "SEC039"]

    assert len(sec039) == 2
    assert any("initContainers 'init-missing'" in f.message for f in sec039)
    assert any("containers 'app-true'" in f.message for f in sec039)
