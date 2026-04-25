from validators.kubernetes_manifest_validator import validate_manifest_documents


def _has_sec021(findings):
    return any(f.rule_id == "SEC021" for f in findings)


def test_sec021_flags_pod_when_automount_not_set():
    docs = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "api"},
            "spec": {
                "containers": [{"name": "api", "image": "nginx:1.25"}],
            },
        }
    ]

    findings = validate_manifest_documents(docs)
    assert _has_sec021(findings)


def test_sec021_passes_pod_when_automount_false():
    docs = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "api"},
            "spec": {
                "automountServiceAccountToken": False,
                "containers": [{"name": "api", "image": "nginx:1.25"}],
            },
        }
    ]

    findings = validate_manifest_documents(docs)
    assert not _has_sec021(findings)


def test_sec021_flags_deployment_when_automount_true():
    docs = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "web"}},
                "template": {
                    "metadata": {"labels": {"app": "web"}},
                    "spec": {
                        "automountServiceAccountToken": True,
                        "containers": [{"name": "web", "image": "nginx:1.25"}],
                    },
                },
            },
        }
    ]

    findings = validate_manifest_documents(docs)
    assert _has_sec021(findings)


def test_sec021_passes_cronjob_when_automount_false():
    docs = [
        {
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {"name": "nightly"},
            "spec": {
                "schedule": "0 1 * * *",
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": {
                                "automountServiceAccountToken": False,
                                "restartPolicy": "OnFailure",
                                "containers": [{"name": "job", "image": "busybox"}],
                            }
                        }
                    }
                },
            },
        }
    ]

    findings = validate_manifest_documents(docs)
    assert not _has_sec021(findings)
