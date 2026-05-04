from validators.kubernetes_validator import validate_manifest_docs


def test_sec034_detects_missing_automount_disablement_and_allows_pass_exempt():
    failing = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "api"},
        "spec": {
            "selector": {"matchLabels": {"app": "api"}},
            "template": {
                "metadata": {"labels": {"app": "api"}},
                "spec": {
                    "containers": [{"name": "api", "image": "nginx:1.27"}]
                },
            },
        },
    }

    passing = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "worker"},
        "spec": {
            "selector": {"matchLabels": {"app": "worker"}},
            "template": {
                "metadata": {"labels": {"app": "worker"}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [{"name": "worker", "image": "busybox:1.36"}],
                },
            },
        },
    }

    exempt = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": "legacy-job",
            "annotations": {"container-defense-stack.io/sec034-exempt": "true"},
        },
        "spec": {
            "template": {
                "spec": {
                    "restartPolicy": "Never",
                    "containers": [{"name": "job", "image": "busybox:1.36"}],
                }
            }
        },
    }

    issues = validate_manifest_docs([failing, passing, exempt])

    sec034 = [i for i in issues if i.rule_id == "SEC034"]
    assert len(sec034) == 1
    assert sec034[0].resource_kind == "Deployment"
    assert sec034[0].resource_name == "api"
