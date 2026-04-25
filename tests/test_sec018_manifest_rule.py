from validators.manifest_validator import validate_manifest


def test_sec018_fails_on_latest_tag():
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: nginx:latest
"""
    findings = validate_manifest(manifest)
    assert any(f["rule_id"] == "SEC018" for f in findings)


def test_sec018_fails_on_missing_tag():
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: api
spec:
  containers:
    - name: api
      image: ghcr.io/acme/api
"""
    findings = validate_manifest(manifest)
    assert any(f["rule_id"] == "SEC018" for f in findings)


def test_sec018_passes_on_version_tag_and_digest():
    manifest = """
apiVersion: batch/v1
kind: Job
metadata:
  name: worker
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: worker
          image: ghcr.io/acme/worker:v1.2.3
      initContainers:
        - name: init
          image: ghcr.io/acme/init@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"""
    findings = validate_manifest(manifest)
    assert not any(f["rule_id"] == "SEC018" for f in findings)
