# Pod Security Standards Namespace Baselines

Use namespace labels to apply Kubernetes Pod Security Admission (PSA) profiles consistently.

## Restricted profile template (production)

Apply `kubernetes/baselines/namespace-pod-security-restricted.yaml` to production namespaces that should enforce the strict built-in policy:

```bash
kubectl apply -f kubernetes/baselines/namespace-pod-security-restricted.yaml
```

This template sets:
- `enforce=restricted`
- `audit=restricted`
- `warn=restricted`
- Explicit version pins for all three modes (`v1.30`)

Version pinning avoids behavior drift across cluster upgrades and makes policy intent predictable during rollout.

## How this complements baseline labels

If you already use a namespace with Pod Security **baseline** labels, keep that for less sensitive or migration namespaces. Use the **restricted** template for hardened production workloads where stronger controls are required. A common pattern is:
- baseline in shared/dev namespaces
- restricted in production namespaces

