from validators.manifest_validator import ManifestValidator


def test_sec040_pass_with_container_level_drop_all():
    manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "ok"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx:1.25",
                    "securityContext": {"capabilities": {"drop": ["ALL"]}},
                }
            ],
            "initContainers": [
                {
                    "name": "init",
                    "image": "busybox",
                    "securityContext": {"capabilities": {"drop": ["all"]}},
                }
            ],
        },
    }

    issues = ManifestValidator().validate(manifest, enabled_rules=["SEC040"])
    assert issues == []


def test_sec040_pass_with_pod_level_drop_all_for_both_container_types():
    manifest = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "ok-deploy"},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "x"}},
            "template": {
                "metadata": {"labels": {"app": "x"}},
                "spec": {
                    "securityContext": {"capabilities": {"drop": ["ALL"]}},
                    "containers": [{"name": "app", "image": "nginx"}],
                    "initContainers": [{"name": "init", "image": "busybox"}],
                },
            },
        },
    }

    issues = ManifestValidator().validate(manifest, enabled_rules=["SEC040"])
    assert issues == []


def test_sec040_fail_when_missing_drop_all():
    manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "bad"},
        "spec": {
            "containers": [
                {"name": "app", "image": "nginx", "securityContext": {"capabilities": {"drop": ["NET_RAW"]}}},
                {"name": "sidecar", "image": "busybox"},
            ],
            "initContainers": [
                {"name": "init", "image": "busybox", "securityContext": {"capabilities": {"drop": []}}}
            ],
        },
    }

    issues = ManifestValidator().validate(manifest, enabled_rules=["SEC040"])
    assert len(issues) == 3
    assert all(i.rule_id == "SEC040" for i in issues)
