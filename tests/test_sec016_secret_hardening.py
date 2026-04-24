from validators.manifest_validator import validate_manifest_text


def test_sec016_flags_literal_secret_env_and_rw_secret_mount():
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: insecure
  template:
    metadata:
      labels:
        app: insecure
    spec:
      containers:
        - name: app
          image: nginx:1.25
          env:
            - name: DB_PASSWORD
              value: supersecret
          volumeMounts:
            - name: app-secret
              mountPath: /var/run/secret
      volumes:
        - name: app-secret
          secret:
            secretName: app-secret
"""
    issues = validate_manifest_text(manifest)
    sec016 = [i for i in issues if i.rule_id == "SEC016"]
    assert len(sec016) >= 2
    assert any("literal value" in i.message for i in sec016)
    assert any("mounted without readOnly" in i.message for i in sec016)


def test_sec016_passes_secretkeyref_and_readonly_mount():
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: secure
  template:
    metadata:
      labels:
        app: secure
    spec:
      containers:
        - name: app
          image: nginx:1.25
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: app-secret
                  key: password
          volumeMounts:
            - name: app-secret
              mountPath: /var/run/secret
              readOnly: true
      volumes:
        - name: app-secret
          secret:
            secretName: app-secret
"""
    issues = validate_manifest_text(manifest)
    assert all(i.rule_id != "SEC016" for i in issues)
