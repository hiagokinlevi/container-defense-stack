from validators.k8s_manifest_validator import validate_manifest


def test_sec042_fails_when_missing_on_deployment_template_spec():
    resources = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "api"},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "api"}},
                "template": {
                    "metadata": {"labels": {"app": "api"}},
                    "spec": {
                        "containers": [{"name": "api", "image": "nginx:1.27"}]
                    },
                },
            },
        }
    ]

    issues = validate_manifest(resources)
    assert any(i.rule_id == "SEC042" for i in issues)


def test_sec042_fails_when_zero_on_pod_spec():
    resources = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "worker"},
            "spec": {
                "terminationGracePeriodSeconds": 0,
                "containers": [{"name": "worker", "image": "busybox:1.36"}],
            },
        }
    ]

    issues = validate_manifest(resources)
    assert any(i.rule_id == "SEC042" for i in issues)


def test_sec042_passes_when_safe_on_cronjob_template_spec():
    resources = [
        {
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {"name": "backup"},
            "spec": {
                "schedule": "*/5 * * * *",
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": {
                                "terminationGracePeriodSeconds": 30,
                                "restartPolicy": "OnFailure",
                                "containers": [
                                    {"name": "backup", "image": "alpine:3.20"}
                                ],
                            }
                        }
                    }
                },
            },
        }
    ]

    issues = validate_manifest(resources)
    assert not any(i.rule_id == "SEC042" for i in issues)
