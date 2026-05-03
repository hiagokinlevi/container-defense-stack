from validators.manifest_validator import validate_manifest_documents


def test_sec032_deployment_and_cronjob_pass_fail_cases():
    deployment_fail = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "dep-fail"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {"name": "web", "image": "nginx:latest", "imagePullPolicy": "IfNotPresent"},
                        {"name": "api", "image": "ghcr.io/acme/api:v1.2.3"},
                    ],
                    "initContainers": [
                        {"name": "init", "image": "busybox", "imagePullPolicy": "Always"}
                    ],
                }
            }
        },
    }

    cronjob_fail = {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {"name": "cron-fail"},
        "spec": {
            "schedule": "*/5 * * * *",
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "worker",
                                    "image": "ghcr.io/acme/worker:v2.0.0",
                                    "imagePullPolicy": "Never",
                                }
                            ],
                            "initContainers": [
                                {"name": "setup", "image": "alpine:latest"}
                            ],
                            "restartPolicy": "OnFailure",
                        }
                    }
                }
            },
        },
    }

    deployment_pass = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "dep-pass"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {"name": "web", "image": "nginx:latest", "imagePullPolicy": "Always"},
                        {
                            "name": "api",
                            "image": "ghcr.io/acme/api:v1.2.3",
                            "imagePullPolicy": "IfNotPresent",
                        },
                    ],
                    "initContainers": [
                        {
                            "name": "init",
                            "image": "busybox:1.36.1",
                            "imagePullPolicy": "Always",
                        }
                    ],
                }
            }
        },
    }

    cronjob_pass = {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {"name": "cron-pass"},
        "spec": {
            "schedule": "*/10 * * * *",
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "worker",
                                    "image": "ghcr.io/acme/worker:v2.0.0",
                                    "imagePullPolicy": "Always",
                                }
                            ],
                            "initContainers": [
                                {
                                    "name": "setup",
                                    "image": "alpine:3.19",
                                    "imagePullPolicy": "IfNotPresent",
                                }
                            ],
                            "restartPolicy": "OnFailure",
                        }
                    }
                }
            },
        },
    }

    findings = validate_manifest_documents(
        [deployment_fail, cronjob_fail, deployment_pass, cronjob_pass]
    )

    sec032 = [f for f in findings if f["rule_id"] == "SEC032"]
    assert len(sec032) == 4

    fail_names = {f["resource_name"] for f in sec032}
    assert "dep-fail" in fail_names
    assert "cron-fail" in fail_names
    assert "dep-pass" not in fail_names
    assert "cron-pass" not in fail_names
