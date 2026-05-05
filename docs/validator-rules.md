# Validator Rules Reference

## SEC037 — Missing `runAsNonRoot: true` in Pod/Container SecurityContext

**Severity:** High  
**Category:** Kubernetes Workload Hardening

### Rationale
Running containers as root increases blast radius for container escape, host-impacting misconfigurations, and privilege escalation paths. Workloads should explicitly enforce non-root execution.

### Detection Logic
Flag workload resources when **neither** of the following is true:

1. Pod-level `spec.securityContext.runAsNonRoot: true` (or pod template equivalent), OR
2. At least one container-level `securityContext.runAsNonRoot: true`

Supported resource kinds:
- `Pod`
- `Deployment`
- `StatefulSet`
- `DaemonSet`
- `Job`
- `CronJob`

### Non-Compliant Example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-api
spec:
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
        - name: api
          image: nginx:1.25
```

### Compliant Examples
Pod-level enforcement:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-api
spec:
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: api
          image: nginx:1.25
```

Container-level enforcement:
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: secure-job
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: worker
          image: busybox:1.36
          securityContext:
            runAsNonRoot: true
```

### Remediation
- Set `runAsNonRoot: true` at pod securityContext for broad enforcement.
- Optionally set `runAsNonRoot: true` on each container for explicit per-container controls.
- Ensure image USER is non-root and compatible with `runAsNonRoot: true`.
