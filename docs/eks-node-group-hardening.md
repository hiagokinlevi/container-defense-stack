# EKS Managed Node Group Hardening Guide

This guide documents the EKS managed node group baseline shipped in
`container-defense-stack` and the offline posture checks implemented by
`scan-eks-nodegroups`.

## Recommended Baseline

- Keep worker nodes in private subnets and expose workloads through controlled
  ingress only.
- Disable EC2 SSH remote access on managed node groups. Prefer SSM Session
  Manager with scoped IAM and audit logging for break-glass access.
- Require IMDSv2 through launch template `metadataOptions.httpTokens=required`
  before rolling production worker nodes.
- Include explicit Kubernetes version evidence in review exports so upgrade
  skew and patch intent are auditable.
- Use labels and taints to make restricted workload placement explicit.
- Set a managed update disruption budget with `maxUnavailable` or
  `maxUnavailablePercentage`.

## Offline Export Workflow

Export one node group with AWS CLI:

```bash
aws eks describe-nodegroup \
  --cluster-name prod-eks \
  --nodegroup-name payments-workers \
  > eks-nodegroup.json
```

Then scan it locally:

```bash
k1n-container-guard scan-eks-nodegroups eks-nodegroup.json
```

You can also scan a reduced multi-node-group review artifact:

```json
{
  "clusterName": "prod-eks",
  "nodegroups": [
    {
      "nodegroupName": "payments-workers",
      "version": "1.31",
      "amiType": "BOTTLEROCKET_x86_64",
      "subnets": [{"subnetId": "subnet-private-a", "mapPublicIpOnLaunch": false}],
      "metadataOptions": {"httpTokens": "required"},
      "labels": {"workload-tier": "restricted"},
      "taints": [{"key": "restricted", "value": "true", "effect": "NO_SCHEDULE"}],
      "updateConfig": {"maxUnavailable": 1}
    }
  ]
}
```

## Built-in Checks

| Check ID | Severity | What it flags |
|---|---|---|
| `EKS-001` | HIGH | Managed node groups with `remoteAccess` configured |
| `EKS-002` | HIGH | Node groups attached to public subnet markers |
| `EKS-003` | HIGH | Missing `metadataOptions.httpTokens=required` IMDSv2 evidence |
| `EKS-004` | MEDIUM | Missing Kubernetes version evidence in the export |
| `EKS-005` | MEDIUM | Missing labels or taints for workload isolation |
| `EKS-006` | MEDIUM | Missing managed update disruption budget |

## Hardening Notes

- The scanner stays offline. It trusts exported JSON and does not call AWS APIs.
- Public subnet detection uses explicit `public`, `isPublic`, or
  `mapPublicIpOnLaunch` fields when present, and falls back to subnet names
  containing `public` for reduced review artifacts.
- If your export comes directly from `describe-nodegroup`, enrich it with launch
  template metadata options and subnet public/private evidence before using it
  as a production gate.
