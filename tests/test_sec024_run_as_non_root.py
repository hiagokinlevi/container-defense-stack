from __future__ import annotations

from validators.manifest_validator import validate_manifest


def test_sec024_non_compliant_and_compliant(tmp_path):
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: non-compliant
spec:
  replicas: 1
  selector:
    matchLabels:
      app: non-compliant
  template:
    metadata:
      labels:
        app: non-compliant
    spec:
      containers:
        - name: app
          image: nginx:1.25
---
apiVersion: batch/v1
kind: Job
metadata:
  name: compliant
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
      restartPolicy: Never
      containers:
        - name: app
          image: busybox:1.36
          command: ["sh", "-c", "echo ok"]
"""
    p = tmp_path / "sec024.yaml"
    p.write_text(manifest, encoding="utf-8")

    findings = validate_manifest(str(p))
    sec024 = [f for f in findings if f.rule_id == "SEC024"]

    assert len(sec024) == 1
    assert sec024[0].severity == "HIGH"
    assert sec024[0].resource == "Deployment/non-compliant"
