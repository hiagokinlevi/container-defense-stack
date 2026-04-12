# Gatekeeper Policy Library

Deployable Gatekeeper manifests built from the repository's defensive admission
policies. Each policy includes:

- a `ConstraintTemplate` that embeds the admission rule logic
- a sample `Constraint` that enforces the template against Pods

## Included Policies

| Policy | Template | Constraint | Coverage |
|---|---|---|---|
| Privileged containers | `constrainttemplates/k1nprivilegedcontainer_template.yaml` | `constraints/k1nprivilegedcontainer.yaml` | `SEC001` |
| Non-root execution | `constrainttemplates/k1nnonrootcontainer_template.yaml` | `constraints/k1nnonrootcontainer.yaml` | `SEC004` |
| Read-only root filesystem | `constrainttemplates/k1nreadonlyrootfs_template.yaml` | `constraints/k1nreadonlyrootfs.yaml` | `SEC003` |
| Drop all capabilities | `constrainttemplates/k1ndropallcapabilities_template.yaml` | `constraints/k1ndropallcapabilities.yaml` | `SEC005` |
| CPU and memory limits | `constrainttemplates/k1nresourcelimits_template.yaml` | `constraints/k1nresourcelimits.yaml` | `SEC006`, `SEC007` |
| Host namespace isolation | `constrainttemplates/k1ndenyhostnamespaces_template.yaml` | `constraints/k1ndenyhostnamespaces.yaml` | `SEC010`, `SEC011`, `SEC012` |
| HostPath volume isolation | `constrainttemplates/k1ndenyhostpathvolumes_template.yaml` | `constraints/k1ndenyhostpathvolumes.yaml` | `SEC014` |

## Apply

```bash
kubectl apply -f policies/gatekeeper/constrainttemplates/
kubectl apply -f policies/gatekeeper/constraints/
```

Adjust `spec.match` in the sample constraints if you want to scope enforcement
to selected namespaces or workload labels.

## Relationship To OPA Policies

The Gatekeeper templates mirror the Rego intent in [`../opa/`](../opa/) so the
same security controls can be enforced:

- at admission time with Gatekeeper
- in offline review with the Python validators
- in Rego-native workflows with the standalone OPA policies
