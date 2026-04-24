from validators.k8s_manifest_validator import K8sManifestValidator


def test_sec017_passes_for_allowed_hostpath_with_readonly_mount():
    manifest = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "ok-hostpath"},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "demo"}},
            "template": {
                "metadata": {"labels": {"app": "demo"}},
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "image": "nginx:stable",
                            "volumeMounts": [
                                {
                                    "name": "runtime-meta",
                                    "mountPath": "/runtime-meta",
                                    "readOnly": True,
                                }
                            ],
                        }
                    ],
                    "volumes": [
                        {
                            "name": "runtime-meta",
                            "hostPath": {"path": "/run/containerd/io.containerd.runtime.v2.task"},
                        }
                    ],
                },
            },
        },
    }

    issues = K8sManifestValidator().validate(manifest)
    assert not [i for i in issues if i.rule_id == "SEC017"]


def test_sec017_fails_for_disallowed_or_writable_hostpath_mount():
    manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "bad-hostpath"},
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "busybox",
                    "volumeMounts": [
                        {"name": "danger", "mountPath": "/host-root"},
                    ],
                }
            ],
            "volumes": [
                {"name": "danger", "hostPath": {"path": "/"}},
            ],
        },
    }

    issues = K8sManifestValidator().validate(manifest)
    sec017 = [i for i in issues if i.rule_id == "SEC017"]

    assert sec017
    assert any("disallowed path" in i.message for i in sec017)
    assert any("readOnly: true" in i.message for i in sec017)
