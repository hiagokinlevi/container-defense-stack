# Container Security Learning Path

A structured progression from foundational concepts to advanced threat modelling
and policy automation. Each track builds on the previous one.

---

## Beginner Track

**Goal**: Understand why container security differs from traditional server security
and apply the most impactful controls.

### Prerequisites
- Basic understanding of Linux processes and file permissions.
- Ability to read and write YAML.
- Docker CLI installed locally.

### Topics

1. **How containers work**
   - Namespaces (PID, network, mount, user, IPC, UTS) and cgroups.
   - What isolation containers do and do not provide.
   - Why a root container is dangerous even with namespaces.

2. **Dockerfile security fundamentals**
   - Using official base images and pinning versions.
   - Multi-stage builds to reduce image size and attack surface.
   - The `USER` instruction and non-root execution.
   - Avoiding secrets in `ENV` and `ARG`.

3. **First Kubernetes security controls**
   - `runAsNonRoot`, `runAsUser`, `allowPrivilegeEscalation`.
   - Setting `readOnlyRootFilesystem` and using `emptyDir` volumes.
   - Dropping all Linux capabilities.

4. **Resource limits**
   - Requests vs. limits and why both matter.
   - Preventing noisy-neighbour and denial-of-service scenarios.

### Recommended Resources
- [Kubernetes Security Basics tutorial](../training/01-kubernetes-security-basics.md) (this repo)
- [Container Hardening Guide](../training/02-container-hardening-guide.md) (this repo)
- Docker's official [Best practices for writing Dockerfiles](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
- Kubernetes [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

### Practical Exercises
- [ ] Run `docker run --rm -it alpine id` and observe UID 0.
- [ ] Build the `python.Dockerfile` from this repo and verify `id` returns UID 10001.
- [ ] Run `validate-dockerfile` from this repo against a Dockerfile you own.
- [ ] Apply `kubernetes/pod-security/baseline_psp.yaml` to a test namespace and
      try deploying a privileged pod — observe the rejection.

---

## Intermediate Track

**Goal**: Implement defence-in-depth controls, automate validation in CI, and
harden cluster-level configuration.

### Prerequisites
- Completed beginner track or equivalent experience.
- kubectl access to a non-production cluster.
- Basic Python or shell scripting.

### Topics

1. **RBAC in depth**
   - ServiceAccount identity model and token projection.
   - Auditing existing RBAC with `kubectl auth can-i --list` and `rakkess`.
   - Writing Roles that use `resourceNames` restrictions.
   - Avoiding wildcard verbs and resources.

2. **Network policies**
   - Default deny-all pattern and why it must come first.
   - Egress controls to prevent data exfiltration.
   - Namespace isolation with `namespaceSelector`.
   - Debugging NetworkPolicy with `kubectl exec` and `netcat`.

3. **Pod Security Admission (PSA)**
   - `baseline`, `restricted`, and `privileged` profiles.
   - Migrating from the deprecated PodSecurityPolicy.
   - Using `audit` and `warn` modes before switching to `enforce`.

4. **Image supply chain security**
   - Container image scanning with Trivy or Grype.
   - Generating SBOMs with Syft.
   - Using `imagePullPolicy: Always` and digest pinning.
   - Private registry authentication with imagePullSecrets.

5. **Secrets management**
   - Why Kubernetes Secrets are base64, not encrypted, by default.
   - Enabling envelope encryption with a KMS provider.
   - External secret stores: Vault, AWS Secrets Manager, Azure Key Vault.
   - The External Secrets Operator pattern.

### Practical Exercises
- [ ] Use the `validate-manifest` CLI from this repo to scan all manifests in a
      project and fix every HIGH/CRITICAL finding.
- [ ] Write a GitHub Actions workflow that runs Trivy on every pull request.
- [ ] Apply a default-deny NetworkPolicy to a namespace and verify with `netcat`.
- [ ] Audit cluster RBAC and identify any ServiceAccount with wildcard permissions.

---

## Advanced Track

**Goal**: Implement runtime security, policy-as-code, and supply-chain integrity
controls at scale.

### Prerequisites
- Completed intermediate track.
- Familiarity with Go or Python for writing admission webhooks or OPA policies.
- Production or staging cluster access.

### Topics

1. **Admission control and policy engines**
   - Validating vs. mutating admission webhooks.
   - OPA/Gatekeeper: writing ConstraintTemplates in Rego.
   - Kyverno: writing ClusterPolicies in YAML.
   - Choosing between OPA and Kyverno for your organisation.

2. **Runtime security with eBPF**
   - How Falco detects anomalous syscall sequences at runtime.
   - Writing custom Falco rules for your applications.
   - Cilium Network Policy with L7 HTTP visibility.
   - Tetragon for kernel-level process tracing.

3. **Supply chain integrity**
   - Signing images with Sigstore Cosign.
   - Verifying signatures with Kyverno or Connaisseur at admission.
   - Generating and attesting SBOMs as OCI artifacts.
   - SLSA provenance levels and how to achieve them in CI.

4. **Threat modelling for containerised workloads**
   - STRIDE model applied to Kubernetes deployments.
   - Identifying trust boundaries: host OS, container runtime, kubelet, API server.
   - Attack paths: container escape, SSRF to metadata API, RBAC privilege escalation.
   - Using `kube-bench` to run CIS Kubernetes Benchmark checks.

5. **Secrets at scale and zero-trust**
   - Workload identity with SPIFFE/SPIRE.
   - mTLS mesh with Istio or Linkerd.
   - Certificate rotation and short-lived credentials.
   - Audit logging and alerting for secret access patterns.

### Practical Exercises
- [ ] Write an OPA ConstraintTemplate that enforces `readOnlyRootFilesystem: true`
      cluster-wide and deploy it to a test cluster.
- [ ] Set up Falco and trigger a custom alert when a container writes to `/etc`.
- [ ] Sign a container image with Cosign and write a Kyverno policy that rejects
      unsigned images from your registry.
- [ ] Run `kube-bench` against your cluster and remediate at least 5 failures.
- [ ] Implement SPIRE workload identity in a two-service demo application.

---

## Reference Materials

| Resource | Description |
|---|---|
| [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) | Comprehensive hardening checklist |
| [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) | US government security guidance |
| [OWASP Kubernetes Top 10](https://owasp.org/www-project-kubernetes-top-10/) | Most critical Kubernetes risks |
| [Kubernetes Security Checklist](https://kubernetes.io/docs/concepts/security/security-checklist/) | Official checklist |
| [Falco Documentation](https://falco.org/docs/) | Runtime security rules and alerts |
| [Sigstore Documentation](https://docs.sigstore.dev/) | Supply chain signing and verification |
