from validators.kubernetes_validator import RULES, validate_manifest_docs


def _has_sec043(findings):
    return any(f.get("id") == "SEC043" for f in findings)


def test_rule_map_includes_sec043():
    assert "SEC043" in RULES
    assert "RuntimeDefault" in RULES["SEC043"]


def test_pod_passes_with_pod_level_runtimedefault():
    doc = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "ok-pod"},
        "spec": {
            "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "app", "image": "nginx"}],
        },
    }
    findings = validate_manifest_docs([doc])
    assert not _has_sec043(findings)


def test_deployment_fails_when_missing_pod_and_container_seccomp():
    doc = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "bad-deploy"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [{"name": "app", "image": "nginx"}],
                }
            }
        },
    }
    findings = validate_manifest_docs([doc])
    assert _has_sec043(findings)


def test_job_passes_with_container_level_localhost_without_pod_level():
    doc = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": "ok-job"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "worker",
                            "image": "busybox",
                            "securityContext": {"seccompProfile": {"type": "Localhost"}},
                        }
                    ]
                }
            }
        },
    }
    findings = validate_manifest_docs([doc])
    assert not _has_sec043(findings)


def test_cronjob_fails_when_any_container_missing_without_pod_default():
    doc = {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {"name": "bad-cron"},
        "spec": {
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "ok",
                                    "image": "busybox",
                                    "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                                },
                                {"name": "bad", "image": "busybox"},
                            ]
                        }
                    }
                }
            }
        },
    }
    findings = validate_manifest_docs([doc])
    assert _has_sec043(findings)
