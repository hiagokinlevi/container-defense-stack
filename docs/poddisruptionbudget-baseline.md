# PodDisruptionBudget Security Baseline (Stateless Workloads)

Use `kubernetes/poddisruptionbudget-stateless-baseline.yaml` as the default PDB for stateless services.

## Why it matters in hardened clusters

A PodDisruptionBudget (PDB) protects **availability during voluntary disruptions** (for example, `kubectl drain`, node pool rotation, and control-plane driven upgrades) by limiting how many matching pods can be evicted at once.

This helps prevent avoidable outages during maintenance in production clusters with strict security and upgrade policies.

## Baseline guidance

- Default: `minAvailable: 1` for small stateless deployments.
- For larger replica sets and stricter SLOs, increase `minAvailable` (or use `maxUnavailable` percentage).
- Match `spec.selector.matchLabels` to your Deployment pod labels exactly.
- Ensure Deployment replicas are always greater than or equal to `minAvailable`.

> Set **only one** of `minAvailable` or `maxUnavailable`.
