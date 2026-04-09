# Roadmap

## v0.1 — Core Validators (current)
- [x] Kubernetes manifest security validator (SEC001–SEC008)
- [x] Dockerfile security validator (DF001–DF005)
- [x] Secure Deployment / Job YAML templates
- [x] RBAC minimum-privilege templates
- [x] Network policy default-deny templates
- [x] Pod security baseline labels
- [x] Multi-stage Dockerfiles (Python, Go)

## v0.2 — Helm & OCI
- [ ] Helm chart values scanner
- [ ] OCI image layer inspection
- [ ] Distroless base image recommendations

## v0.3 — Admission Webhook
- [ ] OPA/Gatekeeper policy library
- [ ] Kyverno policy equivalents
- [ ] Webhook deployment manifests

## v0.4 — Cloud Provider Packs
- [ ] AKS node pool hardening guide
- [ ] EKS managed node group hardening
- [ ] GKE autopilot security baseline
