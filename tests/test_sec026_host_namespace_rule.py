from validators.manifest_validator import ManifestValidator


def test_sec026_pass_when_host_namespace_fields_not_enabled():
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: safe-pod
spec:
  containers:
    - name: app
      image: nginx:1.25
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: safe-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: safe
  template:
    metadata:
      labels:
        app: safe
    spec:
      hostNetwork: false
      hostPID: false
      hostIPC: false
      containers:
        - name: app
          image: nginx:1.25
"""
    findings = ManifestValidator().validate(manifest)
    sec026 = [f for f in findings if f.rule_id == "SEC026"]
    assert sec026 == []


def test_sec026_fail_when_host_namespace_fields_enabled_in_pod_and_deployment():
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx:1.25
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: bad
  template:
    metadata:
      labels:
        app: bad
    spec:
      hostPID: true
      hostIPC: true
      containers:
        - name: app
          image: nginx:1.25
"""
    findings = ManifestValidator().validate(manifest)
    sec026 = [f for f in findings if f.rule_id == "SEC026"]

    assert len(sec026) == 3
    assert all(f.severity == "HIGH" for f in sec026)
    assert any("hostNetwork" in f.message for f in sec026)
    assert any("hostPID" in f.message for f in sec026)
    assert any("hostIPC" in f.message for f in sec026)
    assert all("only enable it when explicitly justified" in f.remediation for f in sec026)
