from validators.kubernetes_validator import validate_manifest_documents


def test_sec035_flags_missing_memory_limit_in_deployment_container_and_initcontainer():
    docs = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "api"},
            "spec": {
                "template": {
                    "spec": {
                        "initContainers": [
                            {
                                "name": "init-db",
                                "image": "busybox",
                                "resources": {"limits": {"cpu": "100m"}},
                            }
                        ],
                        "containers": [
                            {
                                "name": "app",
                                "image": "nginx",
                                "resources": {"limits": {"cpu": "250m"}},
                            }
                        ],
                    }
                }
            },
        }
    ]

    issues = validate_manifest_documents(docs)
    sec035 = [i for i in issues if i.rule_id == "SEC035"]

    assert len(sec035) == 2
    assert any("Container 'app'" in i.message for i in sec035)
    assert any("initContainer 'init-db'" in i.message for i in sec035)


def test_sec035_passes_when_memory_limits_are_set_for_all_supported_kinds():
    docs = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "pod-ok"},
            "spec": {
                "containers": [
                    {
                        "name": "c1",
                        "image": "nginx",
                        "resources": {"limits": {"memory": "256Mi"}},
                    }
                ],
                "initContainers": [
                    {
                        "name": "i1",
                        "image": "busybox",
                        "resources": {"limits": {"memory": "64Mi"}},
                    }
                ],
            },
        },
        {
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {"name": "ss-ok"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "c1",
                                "image": "redis",
                                "resources": {"limits": {"memory": "512Mi"}},
                            }
                        ]
                    }
                }
            },
        },
        {
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {"name": "cj-ok"},
            "spec": {
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    {
                                        "name": "job",
                                        "image": "alpine",
                                        "resources": {"limits": {"memory": "128Mi"}},
                                    }
                                ]
                            }
                        }
                    }
                }
            },
        },
    ]

    issues = validate_manifest_documents(docs)
    assert not [i for i in issues if i.rule_id == "SEC035"]
