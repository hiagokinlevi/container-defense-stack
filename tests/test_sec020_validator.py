import os

from validators.kubernetes_validator import validate_manifest


def test_sec020_pod_pass_runtimedefault():
    doc = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "ok-pod"},
        "spec": {
            "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "app", "image": "nginx"}],
        },
    }
    findings = validate_manifest(doc)
    assert findings == []


def test_sec020_deployment_fail_missing_seccomp():
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
    findings = validate_manifest(doc)
    assert any(f.rule_id == "SEC020" for f in findings)


def test_sec020_job_fail_unconfined():
    doc = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": "bad-job"},
        "spec": {
            "template": {
                "spec": {
                    "securityContext": {"seccompProfile": {"type": "Unconfined"}},
                    "containers": [{"name": "app", "image": "busybox"}],
                }
            }
        },
    }
    findings = validate_manifest(doc)
    assert any(f.rule_id == "SEC020" for f in findings)


def test_sec020_cronjob_pass_container_override():
    doc = {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {"name": "ok-cron"},
        "spec": {
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "app",
                                    "image": "busybox",
                                    "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                                }
                            ]
                        }
                    }
                }
            }
        },
    }
    findings = validate_manifest(doc)
    assert findings == []


def test_sec020_localhost_allowed_via_env():
    os.environ["K1N_ALLOW_LOCALHOST_SECCOMP"] = "true"
    try:
        doc = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "localhost-ok"},
            "spec": {
                "securityContext": {"seccompProfile": {"type": "Localhost"}},
                "containers": [{"name": "app", "image": "nginx"}],
            },
        }
        findings = validate_manifest(doc)
        assert findings == []
    finally:
        os.environ.pop("K1N_ALLOW_LOCALHOST_SECCOMP", None)
