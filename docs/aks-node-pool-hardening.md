# AKS Node Pool Hardening Guide

This guide documents the AKS node-pool baseline shipped in
`container-defense-stack` and the offline posture checks implemented by
`scan-aks-nodepools`.

## Recommended Baseline

- Keep application workloads on dedicated `User` pools and reserve `System`
  pools for critical add-ons only.
- Disable node public IP addresses and front workloads through private
  networking plus controlled ingress.
- Enable EncryptionAtHost for production pools that handle sensitive data.
- Prefer FIPS-enabled Linux images when regulatory or customer requirements
  demand stronger cryptographic assurance.
- Place each pool in an explicit VNet subnet so NSG, UDR, and egress controls
  stay reviewable.

## Offline Export Workflow

Export node-pool posture from Azure CLI:

```bash
az aks show \
  --resource-group rg-security \
  --name prod-cluster \
  --query '{clusterName:name,node_pools:agentPoolProfiles}' \
  -o json > aks-nodepools.json
```

Then scan it locally:

```bash
k1n-container-guard scan-aks-nodepools aks-nodepools.json
```

You can also scan the direct output of:

```bash
az aks nodepool list --resource-group rg-security --cluster-name prod-cluster -o json
```

## Built-in Checks

| Check ID | Severity | What it flags |
|---|---|---|
| `AKS-001` | HIGH | Node pools with `enableNodePublicIP=true` |
| `AKS-002` | HIGH | Node pools without `enableEncryptionAtHost` |
| `AKS-003` | MEDIUM | Linux pools without `enableFIPS` |
| `AKS-004` | HIGH | System pools without `onlyCriticalAddonsEnabled` |
| `AKS-005` | MEDIUM | Pools without explicit `vnetSubnetID` |

## Hardening Notes

- Treat `System` pools as cluster-control infrastructure, not spare capacity
  for application pods.
- If public node IPs are required temporarily, pair that exception with NSG
  restrictions, just-in-time access, and a documented decommission date.
- FIPS mode is workload-dependent. Keep it enabled on regulated pools and
  document justified exceptions where application compatibility prevents it.
- Subnet isolation matters because it lets you apply workload-specific NSGs,
  outbound filtering, and route segmentation without cross-pool ambiguity.
