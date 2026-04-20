# Container Runtime Capability Drop Baseline

This baseline defines a **secure default** for Linux capabilities in containers.

## Recommendation (Default)

Use:

- `drop: ["ALL"]`
- Add back only the minimum required capabilities per workload.

This aligns with least-privilege and reduces risk from container breakout and privilege escalation paths.

## Why this matters

Linux capabilities split root privileges into smaller units. Container runtimes often grant a default set that is broader than most apps need. Removing unnecessary capabilities helps prevent:

- unauthorized network reconfiguration,
- kernel/module interactions,
- filesystem and ownership abuse,
- process and namespace manipulation.

## Capability guidance

### Drop by default

Drop all capabilities unless there is a verified runtime requirement:

- `ALL`

### Common capabilities that should remain dropped for most apps

These are frequently high-risk and rarely required in standard web/API/background workloads:

- `CAP_SYS_ADMIN`
- `CAP_SYS_MODULE`
- `CAP_SYS_PTRACE`
- `CAP_NET_ADMIN`
- `CAP_NET_RAW`
- `CAP_SYS_TIME`
- `CAP_SYS_BOOT`
- `CAP_MKNOD`
- `CAP_DAC_OVERRIDE`
- `CAP_SETUID`
- `CAP_SETGID`
- `CAP_CHOWN`

> Note: If any capability must be re-added, document the reason in code review or deployment metadata.

## Kubernetes example

Use container-level `securityContext` with a strict default posture:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      containers:
        - name: app
          image: ghcr.io/example/secure-app:latest
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            capabilities:
              drop:
                - ALL
              # add:
              #   - NET_BIND_SERVICE  # only if binding to ports <1024 is required
```

## Exception handling

When a workload fails after dropping all capabilities:

1. Identify the exact missing capability from logs/runtime behavior.
2. Add back only that single capability.
3. Re-test functionality.
4. Record justification and owner.
5. Periodically review and remove if no longer needed.

## Operational note

Pair capability minimization with:

- seccomp (`RuntimeDefault` or stricter profile),
- AppArmor/SELinux confinement,
- non-root execution,
- read-only root filesystem,
- minimal base images.

Defense-in-depth is strongest when these controls are applied together.
