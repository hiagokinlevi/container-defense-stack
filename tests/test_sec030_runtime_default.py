from validators.kubernetes_manifest_validator import validate_sec030


def test_sec030_pass_with_pod_level_runtime_default():
    docs = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "ok-deploy"},
            "spec": {
                "template": {
                    "spec": {
                        "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [{"name": "app", "image": "nginx"}],
                        "initContainers": [{"name": "init", "image": "busybox"}],
                    }
                }
            },
        }
    ]

    issues = validate_sec030(docs)
    assert issues == []


def test_sec030_pass_with_container_overrides_runtime_default_when_pod_missing():
    docs = [
        {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {"name": "ok-job"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "image": "nginx",
                                "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                            }
                        ]
                    }
                }
            },
        }
    ]

    issues = validate_sec030(docs)
    assert issues == []


def test_sec030_fail_when_no_effective_runtime_default():
    docs = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "bad-pod"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
        }
    ]

    issues = validate_sec030(docs)
    assert len(issues) == 1
    assert issues[0].rule_id == "SEC030"
    assert "bad-pod" in issues[0].message
    assert "RuntimeDefault" in issues[0].remediation


def test_sec030_fail_when_container_overrides_pod_runtime_default_with_unconfined():
    docs = [
        {
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {"name": "bad-cron"},
            "spec": {
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": {
                                "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                                "containers": [
                                    {
                                        "name": "app",
                                        "image": "nginx",
                                        "securityContext": {"seccompProfile": {"type": "Unconfined"}},
                                    }
                                ],
                            }
                        }
                    }
                }
            },
        }
    ]

    issues = validate_sec030(docs)
    assert len(issues) == 1
    assert issues[0].rule_id == "SEC030"
    assert "app" in issues[0].message
