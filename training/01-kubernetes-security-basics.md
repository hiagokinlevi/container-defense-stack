# Kubernetes Security Basics

This tutorial covers the foundational security controls every Kubernetes workload
should implement before reaching production: pod security contexts, RBAC, network
policies, and resource limits.

---

## 1. Pod Security Contexts

A security context defines privilege and access-control settings for a Pod or
individual container. Setting it explicitly removes reliance on runtime defaults
which vary by cluster configuration.

### Pod-level vs. container-level

Pod-level settings (under `spec.securityContext`) apply to all containers in the
pod. Container-level settings (under `spec.containers[*].securityContext`) override
pod-level settings for that specific container.

### Recommended baseline

```yaml
spec:
  securityContext:
    runAsNonRoot: true        # Reject the pod if any container would run as UID 0.
    runAsUser: 10001          # Explicit UID matching the USER in the container image.
    fsGroup: 10001            # Supplemental GID applied to mounted volumes.
    seccompProfile:
      type: RuntimeDefault    # Apply the container runtime's built-in seccomp filter.
  containers:
    - name: app
      securityContext:
        allowPrivilegeEscalation: false  # Block setuid / sudo escalation.
        readOnlyRootFilesystem: true      # Immutable root filesystem.
        runAsNonRoot: true
        capabilities:
          drop:
            - ALL                         # Drop every Linux capability.
```

### Why each field matters

| Field | Risk mitigated |
|---|---|
| `runAsNonRoot: true` | Prevents root container breakout |
| `allowPrivilegeEscalation: false` | Blocks sudo / setuid attacks |
| `readOnlyRootFilesystem: true` | Stops in-container file tampering |
| `capabilities.drop: [ALL]` | Removes raw socket, kernel module, and mount capabilities |
| `seccompProfile: RuntimeDefault` | Blocks ~300 dangerous syscalls by default |

---

## 2. RBAC: Principle of Least Privilege

Role-Based Access Control (RBAC) governs what API calls a ServiceAccount can make
to the Kubernetes API server.

### Core objects

- **ServiceAccount** — the identity of a running pod.
- **Role** — a namespace-scoped set of permissions.
- **ClusterRole** — a cluster-wide set of permissions.
- **RoleBinding / ClusterRoleBinding** — binds a Role to a subject (user, group, ServiceAccount).

### Least-privilege pattern

Grant only the minimum verbs on the minimum resources for the minimum scope.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: read-configmaps
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["app-config"]   # Restrict to named resources, not all configmaps.
    verbs: ["get"]                  # Read-only; never grant * verbs.
```

### Common mistakes to avoid

- Binding `cluster-admin` to workload ServiceAccounts.
- Using `verbs: ["*"]` or `resources: ["*"]` in production.
- Forgetting `automountServiceAccountToken: false` — every pod gets a mounted token
  by default, even if it never calls the API.

```yaml
spec:
  automountServiceAccountToken: false  # Add this to every pod that does not need API access.
```

---

## 3. Network Policies: Default Deny

Without a NetworkPolicy, all pods can communicate freely across namespaces.
The first policy to deploy in any namespace should be a default deny-all:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}       # Matches every pod in the namespace.
  policyTypes:
    - Ingress
    - Egress            # Listing without rules = block all.
```

Then explicitly allow the traffic your application needs:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - protocol: TCP
          port: 8080
```

> **CNI requirement**: NetworkPolicies are enforced by the CNI plugin, not by
> Kubernetes itself. Ensure your cluster uses a policy-aware CNI (Calico, Cilium,
> or Weave Net). On clusters using Flannel alone, NetworkPolicy objects are silently
> ignored.

---

## 4. Resource Limits

Without resource limits, a single misbehaving pod can exhaust node resources and
cause an outage for all workloads on that node.

```yaml
resources:
  requests:
    cpu: "100m"       # Minimum guaranteed CPU (1 core = 1000m).
    memory: "128Mi"   # Minimum guaranteed memory.
  limits:
    cpu: "500m"       # Hard cap — the container is throttled if it exceeds this.
    memory: "256Mi"   # Hard cap — the container is OOM-killed if it exceeds this.
```

### Guidance

- Always set both `requests` and `limits`.
- Start with conservative limits and tune based on observed usage (check with
  `kubectl top pods`).
- For Java/JVM workloads, also set `-XX:MaxRAMPercentage` to keep heap within
  the container memory limit.
- Consider LimitRange objects to enforce defaults namespace-wide:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: production
spec:
  limits:
    - type: Container
      default:
        cpu: "500m"
        memory: "256Mi"
      defaultRequest:
        cpu: "100m"
        memory: "128Mi"
```

---

## Summary Checklist

- [ ] `runAsNonRoot: true` and explicit non-zero `runAsUser`
- [ ] `allowPrivilegeEscalation: false`
- [ ] `readOnlyRootFilesystem: true` with emptyDir volumes for writable paths
- [ ] `capabilities.drop: [ALL]`
- [ ] `seccompProfile.type: RuntimeDefault`
- [ ] `automountServiceAccountToken: false` for pods that do not call the API
- [ ] RBAC Role with specific verbs and resourceNames, not wildcards
- [ ] Default-deny NetworkPolicy in every namespace
- [ ] `resources.requests` and `resources.limits` set on every container
