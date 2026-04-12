# container-defense-stack

Container and Kubernetes security toolkit providing Dockerfile hardening guides, secure workload manifests, RBAC baselines, network policies, manifest validators, and offline AKS/EKS/GKE cloud-provider hardening checks for DevSecOps teams.

## Objective

Provide production-ready, reusable security baselines for containerized workloads — reducing misconfigurations that lead to privilege escalation, lateral movement, or data exposure in Kubernetes clusters.

## Problem Solved

Teams frequently deploy containers with excessive privileges, missing resource limits, unsafe host mounts, and no network segmentation. This toolkit provides validated templates, validators, and documentation to establish security-by-default.

## Use Cases

- Hardening Dockerfiles for Python, Node.js, and Go applications
- Applying security context to Kubernetes workloads
- Implementing RBAC with minimum privilege
- Auditing ServiceAccounts and attached RBAC before deployment
- Segmenting namespaces with network policies
- Validating manifests before deployment
- Enforcing Pod guardrails with reusable OPA and Gatekeeper policies
- Reviewing exported AKS node-pool posture before production rollout
- Reviewing exported EKS managed node group posture before production rollout
- Reviewing exported GKE Autopilot security posture before production rollout
- Training teams on container security fundamentals

## Ethical Disclaimer

All content is defensive. Use validators and baselines on infrastructure you own or are authorized to assess. Do not use this toolkit to exploit container environments.

## Structure

```
docker/             — Secure Dockerfile examples
kubernetes/         — Secure manifest templates
validators/         — Manifest and Dockerfile validators
policies/           — Reusable security policies
docs/               — Hardening guides and architecture
training/           — Tutorials and labs
```

## How to Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Validate a Kubernetes manifest
k1n-container-guard validate-manifest deployment.yaml

# Validate a Dockerfile
k1n-container-guard validate-dockerfile Dockerfile

# Scan a Helm values file
k1n-container-guard scan-helm-values charts/api/values.yaml --chart-name api

# Scan an entire Helm chart directory
k1n-container-guard scan-helm-chart charts/api

# Scan OCI/Docker layer metadata exported as JSON
k1n-container-guard scan-image-layers image-layers.json --image-tag ghcr.io/acme/api:1.2.3

# Scan exported AKS node pool posture JSON
k1n-container-guard scan-aks-nodepools aks-nodepools.json --cluster-name prod-aks

# Scan exported EKS managed node group posture JSON
k1n-container-guard scan-eks-nodegroups eks-nodegroups.json --cluster-name prod-eks

# Scan exported GKE Autopilot cluster posture JSON
k1n-container-guard scan-gke-autopilot gke-autopilot.json --fleet-name prod-gke

# Scan Kubernetes workload identity posture from manifests
k1n-container-guard scan-workload-identity workloads.yaml

# Scan ServiceAccounts and attached RBAC from manifests
k1n-container-guard scan-serviceaccounts rbac-bundle.yaml
```

If you are working in an offline or PEP 668-managed environment, create the
virtualenv with `python3 -m venv --system-site-packages .venv` and install with
`pip install -e . --no-deps --no-build-isolation` to reuse the locally available
Python packages.

## Policy Packs

- `policies/opa/` provides standalone Rego admission controls for OPA-based review.
- `policies/gatekeeper/` provides deployable `ConstraintTemplate` and sample
  `Constraint` manifests for the same Pod security controls.
- `policies/kyverno/` provides deployable `ClusterPolicy` manifests for the
  same deny-by-default Pod security controls, including `hostPath` denial.
- `kubernetes/admission/` provides hardened validating and mutating webhook
  deployment templates with cert-manager-backed TLS, opt-in namespace scoping,
  and secure runtime defaults for teams building custom admission services.

Apply the Gatekeeper library with:

```bash
kubectl apply -f policies/gatekeeper/constrainttemplates/
kubectl apply -f policies/gatekeeper/constraints/
```

Apply the Kyverno library with:

```bash
kubectl apply -f policies/kyverno/
```

Apply the admission webhook templates with:

```bash
kubectl apply -f kubernetes/admission/validating-webhook-stack.yaml
kubectl apply -f kubernetes/admission/mutating-webhook-stack.yaml
```

Label target namespaces with `admission.k1n.dev/enforce=true` before enabling
either webhook template so enforcement is opt-in until you complete validation.

## Extended Scanners

- `scan-helm-values` checks Helm values files for pinned image tags, secure
  security context defaults, bounded resources, service account token settings,
  network exposure, and hardcoded credentials.
- `scan-helm-chart` evaluates the full chart root, combining `values.yaml`
  checks with template scanning for literal secrets in `templates/*.yaml`.
- `scan-image-layers` evaluates Docker/OCI layer metadata in JSON form so CI
  jobs can flag risky build history, oversized layers, remote fetches without
  checksum verification, and SUID/SGID binaries before release.
- `scan-workload-identity` parses Kubernetes YAML offline and analyzes Pod,
  Deployment, StatefulSet, DaemonSet, Job, and CronJob manifests for
  multi-cloud workload identity misconfigurations such as default service
  accounts paired with cloud credential env vars, overly broad IRSA roles,
  shared cloud identities across workloads, and missing projected token
  audience or expiry controls.
- `scan-serviceaccounts` parses Kubernetes YAML bundles containing
  `ServiceAccount`, `RoleBinding`, `ClusterRoleBinding`, `Role`, and
  `ClusterRole` resources so teams can catch cluster-admin bindings, wildcard
  verbs, cluster-wide secrets access, default ServiceAccount overreach, and
  exposed image pull credentials before applying RBAC changes.
- `scan-eks-nodegroups` evaluates exported EKS managed node group posture for
  SSH remote access, public subnet placement, IMDSv2 enforcement, explicit
  Kubernetes version review, workload-isolation labels or taints, and managed
  update disruption budgets.
- `scan-gke-autopilot` evaluates exported GKE Autopilot cluster posture for
  Autopilot mode evidence, private node placement, control-plane authorized
  networks, Workload Identity Federation, and Binary Authorization enforcement.

The `scan-image-layers` command accepts either a raw JSON list of layer objects
or an object with `image_tag` and `layers` keys. Each layer supports
`layer_id`, `created_by`, `size_bytes`, `layer_index`, and an optional `files`
list containing `path`, `mode`, and `size`.

`scan-aks-nodepools` accepts either a raw JSON list of node-pool objects or an
object with `node_pools` or `agentPoolProfiles` keys. This keeps the workflow
compatible with direct `az aks nodepool list` output and reduced posture
snapshots exported from `az aks show`.

## Cloud Provider Packs

- [docs/aks-node-pool-hardening.md](docs/aks-node-pool-hardening.md) documents
  the shipped AKS node-pool hardening baseline and the `scan-aks-nodepools`
  offline review workflow.
- [docs/eks-node-group-hardening.md](docs/eks-node-group-hardening.md) documents
  the shipped EKS managed node group hardening baseline and the
  `scan-eks-nodegroups` offline review workflow.
- [docs/gke-autopilot-security-baseline.md](docs/gke-autopilot-security-baseline.md)
  documents the shipped GKE Autopilot security baseline and the
  `scan-gke-autopilot` offline review workflow.

The workload identity scanner merges `ServiceAccount` annotations with workload
pod-template annotations so the same manifest bundle can be reviewed before it
ever reaches a cluster. That keeps EKS IRSA, GKE Workload Identity, and Azure
Workload Identity posture checks available in offline CI and pre-deploy review.

The ServiceAccount scanner resolves RoleBinding and ClusterRoleBinding subjects
against the ServiceAccounts in the same YAML bundle, then inspects the
referenced Role and ClusterRole rules offline. That keeps RBAC privilege review
available in CI before the manifests ever reach a cluster API server.

## License

MIT — see [LICENSE](LICENSE).
