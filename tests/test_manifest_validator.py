from validators.manifest_validator import ManifestValidator


def test_sec029_fails_when_namespace_missing_enforce_label():
    docs = [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "prod",
                "labels": {
                    "environment": "production",
                },
            },
        }
    ]

    issues = ManifestValidator().validate_documents(docs)

    assert any(issue.rule_id == "SEC029" for issue in issues)


def test_sec029_passes_when_namespace_has_enforce_label():
    docs = [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "prod",
                "labels": {
                    "pod-security.kubernetes.io/enforce": "restricted",
                },
            },
        }
    ]

    issues = ManifestValidator().validate_documents(docs)

    assert all(issue.rule_id != "SEC029" for issue in issues)
