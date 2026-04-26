import pytest

from validators.manifest_validator import ManifestValidator


def _base_container(with_resources: bool):
    c = {"name": "app", "image": "nginx:1.25"}
    if with_resources:
        c["resources"] = {
            "requests": {"cpu": "100m", "memory": "128Mi"},
            "limits": {"cpu": "500m", "memory": "512Mi"},
        }
    return c


@pytest.mark.parametrize(
    "manifest",
    [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "ok-deploy"},
            "spec": {"template": {"spec": {"containers": [_base_container(True)]}}},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {"name": "ok-sts"},
            "spec": {"template": {"spec": {"containers": [_base_container(True)]}}},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {"name": "ok-ds"},
            "spec": {"template": {"spec": {"containers": [_base_container(True)]}}},
        },
        {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {"name": "ok-job"},
            "spec": {"template": {"spec": {"containers": [_base_container(True)]}}},
        },
        {
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {"name": "ok-cj"},
            "spec": {
                "jobTemplate": {
                    "spec": {"template": {"spec": {"containers": [_base_container(True)]}}}
                }
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "ok-pod"},
            "spec": {"containers": [_base_container(True)]},
        },
    ],
)
def test_sec023_pass_when_all_resource_fields_present(manifest):
    findings = ManifestValidator().validate(manifest)
    assert not [f for f in findings if f.rule_id == "SEC023"]


@pytest.mark.parametrize(
    "manifest",
    [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "bad-deploy"},
            "spec": {"template": {"spec": {"containers": [_base_container(False)]}}},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {"name": "bad-sts"},
            "spec": {"template": {"spec": {"containers": [_base_container(False)]}}},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {"name": "bad-ds"},
            "spec": {"template": {"spec": {"containers": [_base_container(False)]}}},
        },
        {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {"name": "bad-job"},
            "spec": {"template": {"spec": {"containers": [_base_container(False)]}}},
        },
        {
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {"name": "bad-cj"},
            "spec": {
                "jobTemplate": {
                    "spec": {"template": {"spec": {"containers": [_base_container(False)]}}}
                }
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "bad-pod"},
            "spec": {"containers": [_base_container(False)]},
        },
    ],
)
def test_sec023_fail_when_resources_missing(manifest):
    findings = ManifestValidator().validate(manifest)
    sec023 = [f for f in findings if f.rule_id == "SEC023"]
    assert sec023, "expected SEC023 finding when resources are missing"
    assert "requests.cpu" in sec023[0].message
    assert "requests.memory" in sec023[0].message
    assert "limits.cpu" in sec023[0].message
    assert "limits.memory" in sec023[0].message
