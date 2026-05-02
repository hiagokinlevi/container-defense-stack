# Validator Rule Reference

## Kubernetes Manifest Rules

| Rule ID | Severity | Description |
|---|---|---|
| SEC001 | MEDIUM | Disallow latest image tag |
| SEC002 | HIGH | Require non-root user |
| SEC003 | MEDIUM | Require resource limits |
| SEC004 | MEDIUM | Require resource requests |
| SEC005 | HIGH | Disallow hostNetwork |
| SEC006 | HIGH | Disallow hostPID |
| SEC007 | HIGH | Disallow hostIPC |
| SEC008 | HIGH | Disallow hostPath volumes |
| SEC009 | MEDIUM | Require readOnlyRootFilesystem |
| SEC010 | MEDIUM | Drop all Linux capabilities |
| SEC011 | HIGH | Disallow privileged escalation |
| SEC012 | HIGH | Require seccomp profile |
| SEC013 | LOW | Disallow default service account |
| SEC014 | LOW | Require imagePullPolicy |
| SEC015 | LOW | Require liveness/readiness probes |
| SEC028 | CRITICAL | Deny any container or initContainer using `securityContext.privileged: true` |

### SEC028 — Disallow privileged containers

**Intent:** prevent workloads from running with full host-equivalent privileges.

**Fail condition:** any entry in `spec.containers[]` or `spec.initContainers[]` sets:

```yaml
securityContext:
  privileged: true
```

**Pass condition:** `privileged` is omitted or explicitly `false` for all containers and initContainers.
