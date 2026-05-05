import pytest

from validators.kubernetes.manifest_validator import KubernetesManifestValidator


def _run_validator(manifest: str):
    validator = KubernetesManifestValidator()
    return validator.validate(manifest)


@pytest.mark.parametrize(
    "kind, manifest",
    [
        (
            "Pod",
            """
apiVersion: v1
kind: Pod
metadata:
  name: pod-fail
spec:
  containers:
    - name: app
      image: nginx:1.25
""",
        ),
        (
            "Deployment",
            """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deploy-fail
spec:
  replicas: 1
  selector:
    matchLabels:
      app: demo
  template:
    metadata:
      labels:
        app: demo
    spec:
      containers:
        - name: app
          image: nginx:1.25
""",
        ),
        (
            "StatefulSet",
            """
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: sts-fail
spec:
  serviceName: demo
  selector:
    matchLabels:
      app: demo
  template:
    metadata:
      labels:
        app: demo
    spec:
      containers:
        - name: app
          image: nginx:1.25
""",
        ),
        (
            "DaemonSet",
            """
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ds-fail
spec:
  selector:
    matchLabels:
      app: demo
  template:
    metadata:
      labels:
        app: demo
    spec:
      containers:
        - name: app
          image: nginx:1.25
""",
        ),
        (
            "Job",
            """
apiVersion: batch/v1
kind: Job
metadata:
  name: job-fail
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: app
          image: nginx:1.25
""",
        ),
        (
            "CronJob",
            """
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cron-fail
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: app
              image: nginx:1.25
""",
        ),
    ],
)
def test_sec037_fails_when_run_as_non_root_not_enforced(kind, manifest):
    findings = _run_validator(manifest)
    sec037 = [f for f in findings if f.get("rule_id") == "SEC037"]
    assert sec037, f"Expected SEC037 finding for {kind}"


@pytest.mark.parametrize(
    "manifest",
    [
        """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deploy-pass-pod-level
spec:
  selector:
    matchLabels:
      app: demo
  template:
    metadata:
      labels:
        app: demo
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: nginx:1.25
""",
        """
apiVersion: batch/v1
kind: Job
metadata:
  name: job-pass-container-level
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: app
          image: nginx:1.25
          securityContext:
            runAsNonRoot: true
""",
    ],
)
def test_sec037_passes_when_enforced_at_pod_or_container_level(manifest):
    findings = _run_validator(manifest)
    sec037 = [f for f in findings if f.get("rule_id") == "SEC037"]
    assert not sec037
