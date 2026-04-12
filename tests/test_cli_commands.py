"""CLI coverage for the exposed Helm, Kubernetes, and layer scanners."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from click.testing import CliRunner

from cli.main import cli


def test_scan_helm_values_exits_nonzero_for_high_findings(tmp_path: Path) -> None:
    values_path = tmp_path / "values.yaml"
    values_path.write_text(
        textwrap.dedent(
            """
            image:
              repository: example/app
              tag: latest
            securityContext:
              allowPrivilegeEscalation: false
              readOnlyRootFilesystem: true
              runAsNonRoot: true
            resources:
              limits:
                memory: 256Mi
                cpu: 500m
            serviceAccount:
              automountServiceAccountToken: false
            """
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["scan-helm-values", str(values_path), "--chart-name", "demo"])

    assert result.exit_code == 1
    assert "HELM001" in result.output


def test_scan_helm_chart_reports_template_secret(tmp_path: Path) -> None:
    chart_dir = tmp_path / "demo-chart"
    templates_dir = chart_dir / "templates"
    templates_dir.mkdir(parents=True)
    (chart_dir / "Chart.yaml").write_text("name: demo-chart\nversion: 0.1.0\n", encoding="utf-8")
    (chart_dir / "values.yaml").write_text(
        textwrap.dedent(
            """
            image:
              repository: example/app
              tag: "1.2.3"
            securityContext:
              allowPrivilegeEscalation: false
              readOnlyRootFilesystem: true
              runAsNonRoot: true
            resources:
              limits:
                memory: 128Mi
                cpu: 250m
            serviceAccount:
              automountServiceAccountToken: false
            """
        ),
        encoding="utf-8",
    )
    (templates_dir / "secret.yaml").write_text(
        "data:\n  password: supersecret123\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["scan-helm-chart", str(chart_dir)])

    assert result.exit_code == 1
    assert "HELM014" in result.output


def test_scan_image_layers_accepts_object_payload_and_string_modes(tmp_path: Path) -> None:
    payload_path = tmp_path / "layers.json"
    payload_path.write_text(
        json.dumps(
            {
                "image_tag": "demo:1.0.0",
                "layers": [
                    {
                        "layer_id": "sha256:abc",
                        "layer_index": 0,
                        "created_by": "RUN curl -fsSL https://example.test/app.tar.gz -o /tmp/app.tar.gz",
                        "size_bytes": 1024,
                        "files": [{"path": "/usr/local/bin/helper", "mode": "4755", "size": 256}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["scan-image-layers", str(payload_path)])

    assert result.exit_code == 1
    assert "LAY-004" in result.output
    assert "demo:1.0.0" in result.output


def test_scan_image_layers_succeeds_for_clean_payload(tmp_path: Path) -> None:
    payload_path = tmp_path / "layers.json"
    payload_path.write_text(
        json.dumps(
            [
                {
                    "layer_id": "sha256:def",
                    "layer_index": 0,
                    "created_by": "RUN apk add --no-cache ca-certificates",
                    "size_bytes": 2048,
                    "files": [{"path": "/app/server", "mode": 493, "size": 512}],
                }
            ]
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["scan-image-layers", str(payload_path), "--image-tag", "clean:1.0.0"])

    assert result.exit_code == 0
    assert "LayerScanReport [clean:1.0.0]" in result.output


def test_scan_aks_nodepools_reports_hardening_findings(tmp_path: Path) -> None:
    payload_path = tmp_path / "aks-nodepools.json"
    payload_path.write_text(
        json.dumps(
            {
                "clusterName": "prod-aks",
                "node_pools": [
                    {
                        "name": "systempool",
                        "mode": "System",
                        "osType": "Linux",
                        "enableNodePublicIP": True,
                        "enableEncryptionAtHost": False,
                        "enableFIPS": False,
                        "onlyCriticalAddonsEnabled": False,
                        "vnetSubnetID": "",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["scan-aks-nodepools", str(payload_path)])

    assert result.exit_code == 1
    assert "AKS-001" in result.output
    assert "prod-aks" in result.output


def test_scan_aks_nodepools_succeeds_for_hardened_export(tmp_path: Path) -> None:
    payload_path = tmp_path / "aks-nodepools.json"
    payload_path.write_text(
        json.dumps(
            [
                {
                    "name": "userpool-a",
                    "mode": "User",
                    "osType": "Linux",
                    "enableNodePublicIP": False,
                    "enableEncryptionAtHost": True,
                    "enableFIPS": True,
                    "vnetSubnetID": "/subscriptions/test/subnets/apps",
                }
            ]
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        ["scan-aks-nodepools", str(payload_path), "--cluster-name", "clean-aks"],
    )

    assert result.exit_code == 0
    assert "AKSNodePoolReport [clean-aks]" in result.output


def test_scan_eks_nodegroups_reports_hardening_findings(tmp_path: Path) -> None:
    payload_path = tmp_path / "eks-nodegroup.json"
    payload_path.write_text(
        json.dumps(
            {
                "nodegroup": {
                    "nodegroupName": "prod-workers",
                    "clusterName": "prod-eks",
                    "amiType": "AL2_x86_64",
                    "subnets": [{"subnetId": "subnet-123", "name": "public-a", "mapPublicIpOnLaunch": True}],
                    "remoteAccess": {
                        "ec2SshKey": "breakglass",
                        "sourceSecurityGroups": ["sg-123"],
                    },
                    "metadataOptions": {"httpTokens": "optional"},
                    "updateConfig": {},
                }
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["scan-eks-nodegroups", str(payload_path)])

    assert result.exit_code == 1
    assert "EKS-001" in result.output
    assert "EKS-002" in result.output
    assert "EKS-003" in result.output
    assert "prod-eks" in result.output


def test_scan_eks_nodegroups_succeeds_for_hardened_export(tmp_path: Path) -> None:
    payload_path = tmp_path / "eks-nodegroups.json"
    payload_path.write_text(
        json.dumps(
            {
                "clusterName": "clean-eks",
                "nodegroups": [
                    {
                        "nodegroupName": "payments-workers",
                        "version": "1.30",
                        "amiType": "BOTTLEROCKET_x86_64",
                        "subnets": [{"subnetId": "subnet-456", "name": "private-a", "mapPublicIpOnLaunch": False}],
                        "labels": {"workload-tier": "restricted"},
                        "taints": [{"key": "restricted", "value": "true", "effect": "NO_SCHEDULE"}],
                        "metadataOptions": {"httpTokens": "required"},
                        "updateConfig": {"maxUnavailable": 1},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["scan-eks-nodegroups", str(payload_path)])

    assert result.exit_code == 0
    assert "EKSNodeGroupReport [clean-eks]" in result.output


def test_scan_gke_autopilot_reports_hardening_findings(tmp_path: Path) -> None:
    payload_path = tmp_path / "gke-autopilot.json"
    payload_path.write_text(
        json.dumps(
            {
                "projectId": "prod-project",
                "clusters": [
                    {
                        "name": "prod-gke",
                        "autopilot": {"enabled": False},
                        "privateClusterConfig": {"enablePrivateNodes": False},
                        "masterAuthorizedNetworksConfig": {"enabled": False},
                        "workloadIdentityConfig": {},
                        "binaryAuthorization": {"evaluationMode": "DISABLED"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["scan-gke-autopilot", str(payload_path)])

    assert result.exit_code == 1
    assert "GKE-AP-001" in result.output
    assert "GKE-AP-002" in result.output
    assert "GKE-AP-003" in result.output
    assert "prod-project" in result.output


def test_scan_gke_autopilot_succeeds_for_hardened_export(tmp_path: Path) -> None:
    payload_path = tmp_path / "gke-autopilot.json"
    payload_path.write_text(
        json.dumps(
            {
                "fleetName": "clean-gke",
                "clusters": [
                    {
                        "name": "payments-gke",
                        "autopilot": {"enabled": True},
                        "privateClusterConfig": {"enablePrivateNodes": True},
                        "masterAuthorizedNetworksConfig": {"enabled": True},
                        "workloadIdentityConfig": {"workloadPool": "acme.svc.id.goog"},
                        "binaryAuthorization": {"evaluationMode": "PROJECT_SINGLETON_POLICY_ENFORCE"},
                        "releaseChannel": {"channel": "REGULAR"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["scan-gke-autopilot", str(payload_path)])

    assert result.exit_code == 0
    assert "GKEAutopilotReport [clean-gke]" in result.output


def test_scan_gke_autopilot_accepts_private_endpoint_only_control_plane(tmp_path: Path) -> None:
    payload_path = tmp_path / "gke-autopilot-private-endpoint.json"
    payload_path.write_text(
        json.dumps(
            {
                "fleetName": "private-endpoint-gke",
                "clusters": [
                    {
                        "name": "payments-gke",
                        "autopilot": {"enabled": True},
                        "privateClusterConfig": {
                            "enablePrivateNodes": True,
                            "enablePrivateEndpoint": True,
                        },
                        "masterAuthorizedNetworksConfig": {"enabled": False},
                        "workloadIdentityConfig": {"workloadPool": "acme.svc.id.goog"},
                        "binaryAuthorization": {"evaluationMode": "PROJECT_SINGLETON_POLICY_ENFORCE"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["scan-gke-autopilot", str(payload_path)])

    assert result.exit_code == 0
    assert "GKEAutopilotReport [private-endpoint-gke]" in result.output


def test_scan_workload_identity_reports_high_findings(tmp_path: Path) -> None:
    manifest_path = tmp_path / "workloads.yaml"
    manifest_path.write_text(
        textwrap.dedent(
            """
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: api
              namespace: prod
            spec:
              template:
                spec:
                  serviceAccountName: default
                  containers:
                    - name: api
                      image: example/api:1.0.0
                      env:
                        - name: AWS_ROLE_ARN
                          value: arn:aws:iam::123456789:role/AdminRole
            """
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["scan-workload-identity", str(manifest_path)])

    assert result.exit_code == 1
    assert "WID-001" in result.output
    assert "WID-004" in result.output


def test_scan_workload_identity_succeeds_for_scoped_projected_tokens(tmp_path: Path) -> None:
    manifest_path = tmp_path / "workloads.yaml"
    manifest_path.write_text(
        textwrap.dedent(
            """
            apiVersion: v1
            kind: ServiceAccount
            metadata:
              name: api-sa
              namespace: prod
              annotations:
                eks.amazonaws.com/role-arn: arn:aws:iam::123456789:role/payments-reader
            ---
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: api
              namespace: prod
            spec:
              template:
                metadata:
                  annotations:
                    team: platform
                spec:
                  serviceAccountName: api-sa
                  containers:
                    - name: api
                      image: example/api:1.0.0
                      env:
                        - name: AWS_ROLE_ARN
                          value: arn:aws:iam::123456789:role/payments-reader
                  volumes:
                    - name: identity-token
                      projected:
                        sources:
                          - serviceAccountToken:
                              audience: sts.amazonaws.com
                              expirationSeconds: 3600
            """
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["scan-workload-identity", str(manifest_path)])

    assert result.exit_code == 0
    assert "analyzed 1 workload(s) with no findings" in result.output


def test_scan_serviceaccounts_reports_privileged_bindings(tmp_path: Path) -> None:
    manifest_path = tmp_path / "serviceaccounts.yaml"
    manifest_path.write_text(
        textwrap.dedent(
            """
            apiVersion: v1
            kind: ServiceAccount
            metadata:
              name: default
              namespace: prod
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRoleBinding
            metadata:
              name: default-admin
            roleRef:
              apiGroup: rbac.authorization.k8s.io
              kind: ClusterRole
              name: cluster-admin
            subjects:
              - kind: ServiceAccount
                name: default
                namespace: prod
            """
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["scan-serviceaccounts", str(manifest_path)])

    assert result.exit_code == 1
    assert "SA-001" in result.output
    assert "SA-005" in result.output


def test_scan_serviceaccounts_reports_token_request_minting_risk(tmp_path: Path) -> None:
    manifest_path = tmp_path / "serviceaccounts.yaml"
    manifest_path.write_text(
        textwrap.dedent(
            """
            apiVersion: v1
            kind: ServiceAccount
            metadata:
              name: deployer
              namespace: prod
            automountServiceAccountToken: false
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRole
            metadata:
              name: token-minter
            rules:
              - apiGroups: [""]
                resources: ["serviceaccounts/token"]
                verbs: ["create"]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: ClusterRoleBinding
            metadata:
              name: deployer-token-mint
            roleRef:
              apiGroup: rbac.authorization.k8s.io
              kind: ClusterRole
              name: token-minter
            subjects:
              - kind: ServiceAccount
                name: deployer
                namespace: prod
            """
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["scan-serviceaccounts", str(manifest_path)])

    assert result.exit_code == 1
    assert "SA-008" in result.output


def test_scan_serviceaccounts_succeeds_for_scoped_service_account_bundle(tmp_path: Path) -> None:
    manifest_path = tmp_path / "serviceaccounts.yaml"
    manifest_path.write_text(
        textwrap.dedent(
            """
            apiVersion: v1
            kind: ServiceAccount
            metadata:
              name: api-sa
              namespace: prod
            automountServiceAccountToken: false
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata:
              name: api-reader
              namespace: prod
            rules:
              - apiGroups: [""]
                resources: ["configmaps"]
                verbs: ["get", "list"]
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: RoleBinding
            metadata:
              name: api-reader-binding
              namespace: prod
            roleRef:
              apiGroup: rbac.authorization.k8s.io
              kind: Role
              name: api-reader
            subjects:
              - kind: ServiceAccount
                name: api-sa
                namespace: prod
            """
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["scan-serviceaccounts", str(manifest_path)])

    assert result.exit_code == 0
    assert "analyzed 1 ServiceAccount(s) with no findings" in result.output
