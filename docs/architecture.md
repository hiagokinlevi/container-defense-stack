# Validator Architecture

This document describes the design of the repository's static validation and
admission policy layers: `manifest_validator` for Kubernetes YAML manifests,
`dockerfile_validator` for Dockerfiles, `helm_scanner` for Helm values/chart
hardening, `layer_scanner` for OCI image layer metadata review,
`workload_identity_checker` for multi-cloud workload identity posture review,
`aks_node_pool_analyzer` for exported AKS node-pool posture review,
`eks_node_group_analyzer` for exported EKS managed node group posture review,
`gke_autopilot_analyzer` for exported GKE Autopilot posture review, and the
reusable OPA/Gatekeeper/Kyverno policy library under `policies/`.

---

## Overview

Both validators follow the same pattern:

```
Input file
    |
    v
Parser (yaml.safe_load_all / line-by-line)
    |
    v
Rule checks (pure functions, each returns findings)
    |
    v
List[Finding]  — structured, serialisable result objects
    |
    v
CLI layer (Click + Rich table)
    |
    +--> Admission layer (OPA Rego + Gatekeeper templates + Kyverno policies)
```

No network calls, no subprocess invocations, no cluster access — the validators
are purely static analysis tools that run offline.

The Helm, layer, AKS node-pool, EKS node group, and GKE Autopilot scanners follow the same offline model. They
parse local YAML or JSON artifacts and emit structured findings without pulling
images, talking to clusters, or invoking Helm/Docker/Kubernetes CLIs.

The workload identity scanner follows the same pattern. It parses local
multi-document Kubernetes YAML, resolves supported workload kinds plus related
`ServiceAccount` documents, and emits structured findings for EKS IRSA, GKE
Workload Identity, and Azure Workload Identity anti-patterns without cluster
API access.

The AKS node-pool analyzer parses exported Azure CLI JSON and applies explicit
hardening checks for node public IP exposure, EncryptionAtHost, FIPS usage,
system-pool isolation, and explicit subnet placement without contacting Azure
APIs.

The EKS managed node group analyzer parses exported AWS CLI or reduced posture
JSON and applies explicit hardening checks for SSH remote access, public subnet
markers, IMDSv2 enforcement, version review, workload-isolation labels or
taints, and managed update disruption budgets without contacting AWS APIs.

The GKE Autopilot analyzer parses exported gcloud or reduced posture JSON and
applies explicit hardening checks for Autopilot mode evidence, private node
placement, control-plane authorized networks, Workload Identity Federation, and
Binary Authorization enforcement without contacting Google Cloud APIs.

The admission policies use the same control intent, but package it for cluster
enforcement with Gatekeeper `ConstraintTemplate` / `Constraint` manifests and
Kyverno `ClusterPolicy` manifests.

For teams building their own admission services, the repository also ships
secure webhook deployment templates under `kubernetes/admission/`. Those
templates cover the operational layer around admission logic: namespace
hardening, TLS material via cert-manager, highly constrained webhook pods, and
safe webhook configuration defaults such as `failurePolicy: Fail`,
`sideEffects: None`, short timeouts, and namespace-level opt-in labels.

---

## YAML Parsing (manifest_validator)

`validate_manifest(path)` opens the file and feeds it through `yaml.safe_load_all`,
which returns a generator of Python dicts — one per YAML document. This supports
multi-document files (documents separated by `---`).

`safe_load_all` is used instead of `load_all` to prevent arbitrary code execution
via YAML tags (`!!python/object/apply:`). This is essential because the input is
untrusted manifest content.

---

## Rule Checks

### Manifest rules

All checks live in `_check_workload(doc, findings)`. The function:

1. Extracts the container list via `_get_containers(doc)`, which handles the
   structural difference between `Deployment`, `Job`, `CronJob`, and raw `Pod`
   manifests.
2. Iterates over each container and inspects the `securityContext` and `resources`
   keys.
3. Appends a `ManifestFinding` to `findings` for each policy violation.
4. Performs one pod-level check: `automountServiceAccountToken`.

Each check is an explicit `if` statement with a direct dict key lookup — no
schema library or external rule engine. This keeps the logic readable and keeps
dependencies minimal.

### Dockerfile rules

`validate_dockerfile(path)` reads the file as plain text and processes it
line-by-line. It tracks two boolean accumulators (`has_user`, `has_healthcheck`)
that are checked after the loop for file-level findings, and it tracks the last
`FROM` instruction so the final runtime stage can be evaluated for broad base
images that should be replaced with distroless or other minimal runtimes.

Per-line checks use:
- `str.upper().startswith(...)` for instruction-type matching (case-insensitive,
  consistent with Docker's parser behaviour).
- A single `re.match` for the `ENV` secret detection rule — required because the
  pattern depends on the variable name, not just the instruction keyword.

---

## Finding Data Model

### ManifestFinding

```python
@dataclass
class ManifestFinding:
    rule_id: str       # e.g. "SEC001" — stable identifier for suppression lists.
    severity: Severity # CRITICAL | HIGH | MEDIUM | LOW | INFO
    message: str       # Human-readable description of the violation.
    path: str          # Dot-notation path to the offending field in the manifest.
    remediation: str   # Concrete fix instruction.
```

### DockerFinding

```python
@dataclass
class DockerFinding:
    rule_id: str       # e.g. "DF001"
    severity: Severity # HIGH | MEDIUM | LOW
    line: int          # 1-based line number (0 = file-level finding).
    message: str
    remediation: str
```

Both use `@dataclass` for zero-boilerplate construction, equality comparison, and
repr. The `Severity` enums inherit from `str` so they serialise naturally to JSON
without a custom encoder.

### HelmFinding / LayerFinding / AKSFinding / EKSFinding / GKEAutopilotFinding

`helm_scanner` emits `HelmFinding` objects keyed by rule IDs such as
`HELM001` and `HELM014`, `layer_scanner` emits `LayerFinding` objects keyed by
`LAY-001` through `LAY-007`, and `aks_node_pool_analyzer` emits `AKSFinding`
objects keyed by `AKS-001` through `AKS-005`. `eks_node_group_analyzer` emits
`EKSFinding` objects keyed by `EKS-001` through `EKS-006`.
`gke_autopilot_analyzer` emits `GKEAutopilotFinding` objects keyed by
`GKE-AP-001` through `GKE-AP-005`. All keep the same
design goals as the manifest and Dockerfile validators: explicit rule IDs,
human-readable remediation guidance, and deterministic serialisable results for
CI pipelines.

---

## CLI Interface

`cli/main.py` uses Click for argument parsing and Rich for terminal output.

```
cli validate-manifest  PATH
cli validate-dockerfile PATH
cli scan-helm-values  PATH [--chart-name NAME]
cli scan-helm-chart   PATH
cli scan-image-layers PATH [--image-tag TAG]
cli scan-serviceaccounts PATH
cli scan-aks-nodepools PATH [--cluster-name NAME]
cli scan-eks-nodegroups PATH [--cluster-name NAME]
cli scan-gke-autopilot PATH [--fleet-name NAME]
cli scan-workload-identity PATH
```

Both commands:
1. Call the appropriate validator function.
2. Render findings in a `rich.table.Table` with colour-coded severity cells.
3. Exit with code `1` if any HIGH or CRITICAL finding is present, so CI
   pipelines fail automatically on serious violations.
4. Exit with code `0` if no findings or only LOW/MEDIUM findings.

The CLI is intentionally thin — it contains no business logic, only presentation
and exit-code logic. This makes the validators easy to use as a library without
importing Click or Rich.

`scan-image-layers` accepts a JSON list of layer metadata objects or an object
with top-level `image_tag` and `layers` keys, making it easy to feed exported
metadata from a CI step into the scanner without shelling out from the tool.

`scan-aks-nodepools` accepts either direct `az aks nodepool list` JSON or a
reduced object containing `clusterName` and `node_pools` or
`agentPoolProfiles`. This keeps AKS posture review offline and deterministic
for CI or change-review pipelines.

`scan-eks-nodegroups` accepts direct lists, `{"nodegroup": ...}` AWS
describe-nodegroup-style payloads, and reduced objects containing `nodegroups`,
`nodeGroups`, or `node_groups` arrays. It can also consume enriched subnet and
launch-template metadata when teams add those fields to an offline posture
artifact before review.

`scan-gke-autopilot` accepts direct lists, full `gcloud container clusters
describe --format=json` cluster objects, or reduced objects containing a
`clusters` or `items` array. This supports single-cluster review and fleet-level
pull request artifacts without live Google Cloud access.

`scan-workload-identity` accepts a Kubernetes YAML bundle containing any mix of
`ServiceAccount`, `Pod`, `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, and
`CronJob` resources. The loader merges service-account annotations with
pod-template annotations, extracts env var names plus projected service account
token settings, and then runs the single-workload plus cross-workload identity
checks before rendering a CI-friendly exit code.

`scan-serviceaccounts` accepts Kubernetes YAML bundles containing any mix of
`ServiceAccount`, `RoleBinding`, `ClusterRoleBinding`, `Role`, and
`ClusterRole` resources. The loader resolves bindings and referenced RBAC rules
offline, then runs privilege-escalation checks for cluster-admin access,
wildcard verbs, cluster-wide secrets reads, default ServiceAccount reuse, and
registry credential exposure before rendering a CI-friendly exit code.

---

## Admission Policy Library

`policies/opa/` contains standalone Rego rules for security checks that align
with the manifest validator rule IDs. `policies/gatekeeper/` wraps the same
controls into deployable Gatekeeper resources, and `policies/kyverno/` ships
equivalent Kyverno `ClusterPolicy` manifests:

1. `ConstraintTemplate` manifests embed the Rego policy under the
   `admission.k8s.gatekeeper.sh` target.
2. Sample `Constraint` manifests bind each template to Pod admission.
3. Kyverno `ClusterPolicy` manifests express the same deny-by-default Pod
   controls with per-rule `validate` blocks.
4. Rule IDs such as `SEC001`, `SEC004`, and `SEC010` remain aligned across
   static validation and admission enforcement.
5. `kubernetes/admission/*.yaml` provides reusable validating and mutating
   webhook stacks for custom admission services that need a hardened deployment
   baseline beyond policy-only artifacts.

This keeps shift-left checks and cluster admission controls consistent, so a
finding discovered in CI can be enforced with the same control at deploy time.

---

## Extending the Validators

### Adding a manifest rule

1. Add a new `rule_id` constant (e.g., `SEC009`).
2. Add an `if` block inside `_check_workload` (or a new helper if the check is
   complex) that appends a `ManifestFinding` when the condition is met.
3. Add a test in `tests/test_manifest_validator.py` that asserts the new rule ID
   appears when the misconfiguration is present.

### Adding a Dockerfile rule

1. Add a new `rule_id` constant (e.g., `DF007`).
2. Add the check inside the `for i, line in enumerate(lines)` loop, or as a
   post-loop check for file-level properties.
3. Add a test in `tests/test_dockerfile_validator.py`.

### Severity conventions

| Severity | Meaning |
|---|---|
| CRITICAL | Immediate exploitation risk; blocks deployment in CI |
| HIGH | Significant risk; blocks deployment in CI |
| MEDIUM | Important but non-blocking; should be resolved before next release |
| LOW | Minor improvement; track in backlog |
| INFO | Informational only; no action required |
