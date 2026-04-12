# Kyverno Policy Library

Deployable Kyverno `ClusterPolicy` manifests aligned to the repository's
defensive Pod security controls. Each policy is designed for deny-by-default
admission enforcement and keeps the same rule IDs used by the static validators
and Gatekeeper pack.

## Included Policies

| Policy | File | Coverage |
|---|---|---|
| Privileged containers | `deny-privileged-containers.yaml` | `SEC001` |
| Non-root execution | `require-non-root-containers.yaml` | `SEC004` |
| Read-only root filesystem | `require-read-only-root-fs.yaml` | `SEC003` |
| Drop all capabilities | `require-drop-all-capabilities.yaml` | `SEC005` |
| CPU and memory limits | `require-container-resource-limits.yaml` | `SEC006`, `SEC007` |
| Host namespace isolation | `deny-host-namespaces.yaml` | `SEC010`, `SEC011`, `SEC012` |
| HostPath volume isolation | `deny-hostpath-volumes.yaml` | `SEC014` |

## Apply

```bash
kubectl apply -f policies/kyverno/
```

Adjust the `match` or `exclude` blocks if you want to scope enforcement to
selected namespaces, labels, or service accounts.

## Relationship To Other Policy Packs

The Kyverno policies mirror the same control intent shipped in:

- `policies/opa/` for Rego-native policy review
- `policies/gatekeeper/` for Gatekeeper admission enforcement
- `validators/manifest_validator.py` for offline CI validation

This keeps shift-left and cluster-admission controls aligned across the repo.
