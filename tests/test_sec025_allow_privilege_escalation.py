from validators.kubernetes_validator import KubernetesValidator


def test_sec025_fails_when_missing_or_true_on_containers_and_initcontainers():
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: 1
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      initContainers:
        - name: init-db
          image: busybox
          securityContext:
            allowPrivilegeEscalation: true
      containers:
        - name: app
          image: nginx:1.25
          securityContext:
            runAsNonRoot: true
        - name: sidecar
          image: busybox
"""
    issues = KubernetesValidator().validate_manifest(manifest)
    sec025 = [i for i in issues if i.rule_id == "SEC025"]
    assert len(sec025) == 3


def test_sec025_passes_when_all_set_false():
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  initContainers:
    - name: init
      image: busybox
      securityContext:
        allowPrivilegeEscalation: false
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        allowPrivilegeEscalation: false
"""
    issues = KubernetesValidator().validate_manifest(manifest)
    assert all(i.rule_id != "SEC025" for i in issues)
