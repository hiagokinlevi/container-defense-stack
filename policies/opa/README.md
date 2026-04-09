# OPA / Gatekeeper Admission Policies

Rego policies for enforcing Kubernetes security baselines at admission time.
Each policy is a standalone `.rego` file that can be deployed via:

- **Open Policy Agent (OPA)** — as a Validating Webhook
- **OPA Gatekeeper** — wrapped in a `ConstraintTemplate` + `Constraint` CRD pair

## Policies

| File | Rule IDs | Severity | Description |
|---|---|---|---|
| `deny_privileged.rego` | SEC001 | CRITICAL | Block containers running as privileged |
| `require_non_root.rego` | SEC004 | HIGH | Require `runAsNonRoot: true` and non-zero UID |
| `require_read_only_root_fs.rego` | SEC003 | MEDIUM | Require `readOnlyRootFilesystem: true` |
| `require_resource_limits.rego` | SEC006, SEC007 | MEDIUM/LOW | Require CPU and memory limits |
| `require_drop_all_capabilities.rego` | SEC005 | MEDIUM | Require `capabilities.drop: [ALL]` |
| `deny_host_namespaces.rego` | SEC010-012 | CRITICAL/HIGH | Block `hostPID`, `hostNetwork`, `hostIPC` |

## Quick Test with OPA CLI

```bash
# Install OPA: https://www.openpolicyagent.org/docs/latest/#running-opa
opa eval \
  --data policies/opa/deny_privileged.rego \
  --input <(echo '{"request":{"kind":{"kind":"Pod"},"object":{"spec":{"containers":[{"name":"app","securityContext":{"privileged":true}}]}}}}') \
  'data.kubernetes.admission.deny'
```

## Gatekeeper Deployment (Example)

```yaml
# ConstraintTemplate wrapping deny_privileged.rego
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k1nprivilegedcontainer
spec:
  crd:
    spec:
      names:
        kind: K1nPrivilegedContainer
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        # paste deny_privileged.rego content here
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K1nPrivilegedContainer
metadata:
  name: deny-privileged
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
```

## Rule ID Reference

Rule IDs align with the `validators/manifest_validator.py` static checker,
so findings from both runtime (OPA) and shift-left (Python validator) are
consistently numbered.

## License

CC BY 4.0 — see [LICENSE](../../LICENSE). Free to use, share, and adapt with attribution to **Hiago Kin Levi**.
