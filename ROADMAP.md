# Roadmap

## v0.1 — Core Validators (current)
- [x] Kubernetes manifest security validator (SEC001–SEC015)
- [x] Dockerfile security validator (DF001–DF005)
- [x] Secure Deployment / Job YAML templates
- [x] RBAC minimum-privilege templates
- [x] Network policy default-deny templates
- [x] Pod security baseline labels
- [x] Multi-stage Dockerfiles (Python, Go)

## v0.2 — Helm & OCI
- [x] Helm chart values scanner
- [x] OCI image layer inspection
- [x] Distroless base image recommendations

## v0.3 — Admission Webhook
- [x] OPA/Gatekeeper policy library
- [x] Kyverno policy equivalents
- [x] Webhook deployment manifests

## v0.4 — Cloud Provider Packs
- [x] Multi-cloud workload identity manifest scanner
- [x] AKS node pool hardening guide
- [x] EKS managed node group hardening
- [x] GKE autopilot security baseline

## Automated Completions
- [x] Add Dockerfile Security Baseline Template (cycle 1)
- [x] Add Minimal Seccomp Profile for Containers (cycle 17)
- [x] Add Example AppArmor Profile for Containers (cycle 18)
- [x] Add Docker Compose Security Baseline Example (cycle 19)
- [x] Add Kubernetes Admission Policy Example (Kyverno) (cycle 20)
- [x] Add Container Runtime Capability Drop List (cycle 21)
- [x] Add .dockerignore Security Template (cycle 22)
- [x] Add Pre-Commit Hook for Container Security Checks (cycle 23)
- [x] Add GitHub Actions Workflow for Manifest and Dockerfile Security Validation (cycle 24)
- [x] Add Kubernetes CronJob Hardened Manifest Template (cycle 25)
- [x] Add Namespace Default ResourceQuota Security Baseline (cycle 26)
- [x] Add Namespace LimitRange Baseline for Safe Defaults (cycle 27)
- [x] Add Gatekeeper Constraint for Privileged Container Deny (cycle 28)
- [x] Add CLI Example for Policy Validation in CI (cycle 29)
- [x] Add PodDisruptionBud
- [x] Add SEC033 Validator Rule to Require Immutable Container Root Filesystem Mounts (`readOnly: true`) for ConfigMap/Secret Volumes (cycle 49)
