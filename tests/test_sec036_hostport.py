from validators.manifest_validator import ManifestValidator


def test_sec036_flags_hostport_on_deployment_template():
    manifest = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "web"},
        "spec": {
            "template": {
                "metadata": {"labels": {"app": "web"}},
                "spec": {
                    "containers": [
                        {
                            "name": "web",
                            "image": "nginx:1.25",
                            "ports": [{"containerPort": 8080, "hostPort": 8080}],
                        }
                    ]
                },
            }
        },
    }

    findings = ManifestValidator().validate(manifest)
    assert any(f["id"] == "SEC036" for f in findings)


def test_sec036_allows_explicit_annotation_exception():
    manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "web",
            "annotations": {"container-guard.io/exception-sec036": "true"},
        },
        "spec": {
            "containers": [
                {
                    "name": "web",
                    "image": "nginx:1.25",
                    "ports": [{"containerPort": 8080, "hostPort": 8080}],
                }
            ]
        },
    }

    findings = ManifestValidator().validate(manifest)
    assert not any(f["id"] == "SEC036" for f in findings)
