from validators.manifest_validator import ManifestValidator


def _deployment_with_mount(read_only=None, use_init=False):
    mount = {"name": "cfg", "mountPath": "/etc/config"}
    if read_only is not None:
        mount["readOnly"] = read_only

    container_key = "initContainers" if use_init else "containers"

    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "demo"},
        "spec": {
            "template": {
                "spec": {
                    "volumes": [
                        {"name": "cfg", "configMap": {"name": "app-config"}},
                        {"name": "sec", "secret": {"secretName": "app-secret"}},
                    ],
                    "containers": [] if use_init else [{"name": "app", "image": "nginx", "volumeMounts": [mount]}],
                    "initContainers": [{"name": "init", "image": "busybox", "volumeMounts": [mount]}] if use_init else [],
                }
            }
        },
    }


def test_sec033_fails_when_configmap_mount_writable():
    manifest = _deployment_with_mount(read_only=False)
    findings = ManifestValidator().validate(manifest)
    codes = [f.code for f in findings]
    assert "SEC033" in codes


def test_sec033_fails_when_configmap_mount_readonly_not_set():
    manifest = _deployment_with_mount(read_only=None)
    findings = ManifestValidator().validate(manifest)
    codes = [f.code for f in findings]
    assert "SEC033" in codes


def test_sec033_passes_when_configmap_mount_readonly_true():
    manifest = _deployment_with_mount(read_only=True)
    findings = ManifestValidator().validate(manifest)
    codes = [f.code for f in findings]
    assert "SEC033" not in codes


def test_sec033_applies_to_initcontainers_too():
    manifest = _deployment_with_mount(read_only=False, use_init=True)
    findings = ManifestValidator().validate(manifest)
    sec033 = [f for f in findings if f.code == "SEC033"]
    assert len(sec033) == 1
