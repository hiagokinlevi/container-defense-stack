# GKE Autopilot Security Baseline

This guide documents the GKE Autopilot baseline shipped in
`container-defense-stack` and the offline posture checks implemented by
`scan-gke-autopilot`.

## Recommended Baseline

- Keep production clusters on Autopilot unless a documented Standard-mode
  exception is required.
- Enable private nodes so worker nodes do not receive public IP addresses.
- Restrict control-plane source networks with master authorized networks or an
  equivalent private access pattern.
- Enable Workload Identity Federation for GKE so workloads use scoped IAM
  bindings instead of node-level credentials.
- Enforce Binary Authorization for production release gates.

## Offline Export Workflow

Export cluster posture from gcloud:

```bash
gcloud container clusters describe prod-gke \
  --region us-central1 \
  --format=json > gke-autopilot.json
```

Then scan it locally:

```bash
k1n-container-guard scan-gke-autopilot gke-autopilot.json --fleet-name prod-gke
```

You can also scan a reduced multi-cluster review artifact:

```json
{
  "fleetName": "prod-gke",
  "clusters": [
    {
      "name": "payments-gke",
      "autopilot": {"enabled": true},
      "privateClusterConfig": {"enablePrivateNodes": true},
      "masterAuthorizedNetworksConfig": {"enabled": true},
      "workloadIdentityConfig": {"workloadPool": "acme.svc.id.goog"},
      "binaryAuthorization": {"evaluationMode": "PROJECT_SINGLETON_POLICY_ENFORCE"}
    }
  ]
}
```

## Built-in Checks

| Check ID | Severity | What it flags |
|---|---|---|
| `GKE-AP-001` | HIGH | Clusters that do not show `autopilot.enabled=true` |
| `GKE-AP-002` | HIGH | Autopilot clusters without private node evidence |
| `GKE-AP-003` | HIGH | Missing control-plane authorized network evidence |
| `GKE-AP-004` | MEDIUM | Missing Workload Identity pool evidence |
| `GKE-AP-005` | MEDIUM | Missing Binary Authorization enforcement evidence |

## Hardening Notes

- The scanner stays offline. It trusts exported JSON and does not call Google
  Cloud APIs.
- Use reduced artifacts in pull requests when full `gcloud` exports include
  noisy metadata that reviewers do not need.
- If your organization uses private endpoint-only control-plane access instead
  of master authorized networks, document the exception with the review export.
