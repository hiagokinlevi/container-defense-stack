# Admission Webhook Deployment Templates

This directory provides hardened Kubernetes manifest bundles for teams that are
deploying their own admission webhooks.

The templates are intentionally generic:

- `validating-webhook-stack.yaml` is a deny-by-default validating webhook
  baseline for Pod admission.
- `mutating-webhook-stack.yaml` is a guarded mutating webhook baseline for Pod
  creation.

Each bundle includes:

- a dedicated namespace labeled for restricted Pod Security Admission
- a service account with service-account token automount disabled
- a two-replica webhook deployment with non-root execution, `RuntimeDefault`
  seccomp, read-only root filesystem, dropped capabilities, and resource limits
- a ClusterIP service, a cert-manager `Issuer`, a `Certificate`, and a
  corresponding webhook configuration with CA bundle injection
- a `PodDisruptionBudget` to preserve at least one available replica during
  maintenance or node churn

## Usage

1. Replace the placeholder image reference with your approved webhook image and
   digest.
2. Confirm the container listens on `:8443` and serves the configured
   `/validate` or `/mutate` endpoint.
3. Install `cert-manager` or replace the `Issuer` / `Certificate` resources
   with your cluster's certificate management mechanism.
4. Label namespaces that should opt in:

   ```bash
   kubectl label namespace payments admission.k1n.dev/enforce=true
   ```

5. Apply the desired template:

   ```bash
   kubectl apply -f kubernetes/admission/validating-webhook-stack.yaml
   kubectl apply -f kubernetes/admission/mutating-webhook-stack.yaml
   ```

If your webhook must call the Kubernetes API, remove the
`automountServiceAccountToken: false` setting and add the minimum RBAC required
for that behavior.
