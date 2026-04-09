"""CLI coverage for the exposed Helm and layer scanners."""

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
