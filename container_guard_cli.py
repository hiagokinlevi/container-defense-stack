"""
container-defense-stack CLI

Entry points:
  validate-manifest PATH   — Validate a Kubernetes YAML manifest for security issues.
  validate-dockerfile PATH — Validate a Dockerfile for security issues.
  scan-helm-values PATH    — Scan a Helm values file for security issues.
  scan-helm-chart PATH     — Scan a Helm chart directory for security issues.
  scan-image-layers PATH   — Scan Docker/OCI layer metadata from a JSON file.

Exit codes:
  0 — No HIGH or CRITICAL findings.
  1 — One or more HIGH or CRITICAL findings detected.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
import yaml
from rich import box
from rich.console import Console
from rich.table import Table

from docker.layer_scanner import LayerFile, LayerMetadata, LayerScanner
from kubernetes.aks_node_pool_analyzer import analyze_node_pools, node_pool_from_dict
from kubernetes.workload_identity_checker import check_many, load_configs_from_file
from validators.dockerfile_validator import Severity as DSeverity
from validators.dockerfile_validator import validate_dockerfile
from validators.helm_scanner import Severity as HSeverity
from validators.helm_scanner import scan_chart, scan_values_file
from validators.manifest_validator import Severity as MSeverity
from validators.manifest_validator import validate_manifest

console = Console()

_SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "white",
}


@click.group()
def cli() -> None:
    """k1n container defense stack — security posture validation toolkit."""


def _print_success(path: Path, noun: str = "file") -> None:
    console.print(f"[bold green]No findings — {noun} {path} passed.[/bold green]")


def _render_findings_table(title: str, columns: list[tuple[str, str | None]], rows: list[list[str]]) -> None:
    table = Table(title=title, box=box.ROUNDED, show_lines=True)
    for column_name, style in columns:
        kwargs: dict[str, Any] = {"no_wrap": column_name in {"Severity", "Rule ID", "Line", "Layer"}}
        if style:
            kwargs["style"] = style
        table.add_column(column_name, **kwargs)

    for row in rows:
        table.add_row(*row)

    console.print(table)


def _has_blocking_findings(findings: list[Any]) -> bool:
    return any(getattr(finding, "severity").value in {"HIGH", "CRITICAL"} for finding in findings)


def _load_layer_report(path: Path, image_tag: str, max_layers: int, max_layer_mb: int):
    payload = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(payload, list):
        layer_items = payload
        resolved_image_tag = image_tag
    elif isinstance(payload, dict):
        layer_items = payload.get("layers", [])
        resolved_image_tag = image_tag or str(payload.get("image_tag", ""))
    else:
        raise click.ClickException("Layer metadata JSON must be either a list or an object with a 'layers' key.")

    if not isinstance(layer_items, list):
        raise click.ClickException("The 'layers' value must be a list of layer objects.")

    layers: list[LayerMetadata] = []
    for index, item in enumerate(layer_items):
        if not isinstance(item, dict):
            raise click.ClickException(f"Layer entry {index} is not a JSON object.")

        files_payload = item.get("files", [])
        if not isinstance(files_payload, list):
            raise click.ClickException(f"Layer entry {index} has a non-list 'files' value.")

        files: list[LayerFile] = []
        for file_index, file_item in enumerate(files_payload):
            if not isinstance(file_item, dict):
                raise click.ClickException(f"Layer entry {index} file {file_index} is not a JSON object.")

            raw_mode = file_item.get("mode", 0o644)
            if isinstance(raw_mode, str):
                raw_mode = int(raw_mode, 8)

            files.append(
                LayerFile(
                    path=str(file_item.get("path", "")),
                    mode=int(raw_mode),
                    size=int(file_item.get("size", 0)),
                )
            )

        layers.append(
            LayerMetadata(
                layer_id=str(item.get("layer_id", "")),
                created_by=str(item.get("created_by", "")),
                size_bytes=int(item.get("size_bytes", 0)),
                files=files,
                layer_index=int(item.get("layer_index", index)),
            )
        )

    scanner = LayerScanner(max_layers=max_layers, max_layer_bytes=max_layer_mb * 1024 * 1024)
    return scanner.scan(layers, image_tag=resolved_image_tag)


def _load_workload_identity_results(path: Path):
    try:
        configs = load_configs_from_file(path)
    except yaml.YAMLError as exc:
        raise click.ClickException(f"Unable to parse Kubernetes YAML: {exc}") from exc

    if not configs:
        raise click.ClickException("No supported Kubernetes workloads found in the provided YAML.")

    return check_many(configs)


def _load_aks_node_pool_report(path: Path, cluster_name: str):
    payload = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(payload, list):
        node_pool_items = payload
        resolved_cluster_name = cluster_name or "aks-nodepools"
    elif isinstance(payload, dict):
        node_pool_items = payload.get("node_pools")
        if node_pool_items is None:
            node_pool_items = payload.get("agentPoolProfiles", [])
        resolved_cluster_name = cluster_name or str(
            payload.get("clusterName") or payload.get("name") or "aks-nodepools"
        )
    else:
        raise click.ClickException(
            "AKS node pool JSON must be a list or an object with 'node_pools' or 'agentPoolProfiles'."
        )

    if not isinstance(node_pool_items, list):
        raise click.ClickException("The AKS node pool payload must resolve to a list.")

    invalid_items = [index for index, item in enumerate(node_pool_items) if not isinstance(item, dict)]
    if invalid_items:
        raise click.ClickException(f"AKS node pool entries must be JSON objects (invalid index: {invalid_items[0]}).")

    return analyze_node_pools(
        [node_pool_from_dict(item) for item in node_pool_items],
        cluster_name=resolved_cluster_name,
    )


@cli.command("validate-manifest")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def validate_manifest_cmd(path: Path) -> None:
    """Validate a Kubernetes YAML manifest at PATH for security misconfigurations."""
    findings = validate_manifest(path)

    if not findings:
        _print_success(path)
        sys.exit(0)

    _render_findings_table(
        f"Findings: {path}",
        [
            ("Severity", "bold"),
            ("Rule ID", None),
            ("Message", None),
            ("Path", "dim"),
            ("Remediation", None),
        ],
        [
            [
                f"[{_SEVERITY_STYLE.get(f.severity.value, 'white')}]{f.severity.value}[/{_SEVERITY_STYLE.get(f.severity.value, 'white')}]",
                f.rule_id,
                f.message,
                f.path,
                f.remediation,
            ]
            for f in findings
        ],
    )
    console.print(f"\n[bold]Total findings:[/bold] {len(findings)}")

    if any(f.severity in (MSeverity.HIGH, MSeverity.CRITICAL) for f in findings):
        console.print("[bold red]Exiting 1 — HIGH or CRITICAL findings detected.[/bold red]")
        sys.exit(1)


@cli.command("validate-dockerfile")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def validate_dockerfile_cmd(path: Path) -> None:
    """Validate a Dockerfile at PATH for security misconfigurations."""
    findings = validate_dockerfile(path)

    if not findings:
        _print_success(path)
        sys.exit(0)

    _render_findings_table(
        f"Findings: {path}",
        [
            ("Severity", "bold"),
            ("Rule ID", None),
            ("Line", None),
            ("Message", None),
            ("Remediation", None),
        ],
        [
            [
                f"[{_SEVERITY_STYLE.get(f.severity.value, 'white')}]{f.severity.value}[/{_SEVERITY_STYLE.get(f.severity.value, 'white')}]",
                f.rule_id,
                str(f.line) if f.line > 0 else "—",
                f.message,
                f.remediation,
            ]
            for f in findings
        ],
    )
    console.print(f"\n[bold]Total findings:[/bold] {len(findings)}")

    if any(f.severity == DSeverity.HIGH for f in findings):
        console.print("[bold red]Exiting 1 — HIGH findings detected.[/bold red]")
        sys.exit(1)


@cli.command("scan-helm-values")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--chart-name", default="unknown", show_default=True, help="Chart name label to use in the report.")
def scan_helm_values_cmd(path: Path, chart_name: str) -> None:
    """Scan a Helm values file at PATH for security misconfigurations."""
    result = scan_values_file(path, chart_name=chart_name)

    if not result.findings:
        _print_success(path, noun="values file")
        sys.exit(0)

    _render_findings_table(
        f"Helm findings: {path}",
        [
            ("Severity", "bold"),
            ("Rule ID", None),
            ("Location", "dim"),
            ("Message", None),
            ("Remediation", None),
        ],
        [
            [
                f"[{_SEVERITY_STYLE.get(f.severity.value, 'white')}]{f.severity.value}[/{_SEVERITY_STYLE.get(f.severity.value, 'white')}]",
                f.rule_id,
                f.location,
                f.message,
                f.remediation,
            ]
            for f in result.findings
        ],
    )
    console.print(
        f"\n[bold]Total findings:[/bold] {len(result.findings)} "
        f"(critical={result.critical_count}, high={result.high_count})"
    )

    if any(f.severity in (HSeverity.HIGH, HSeverity.CRITICAL) for f in result.findings):
        console.print("[bold red]Exiting 1 — HIGH or CRITICAL findings detected.[/bold red]")
        sys.exit(1)


@cli.command("scan-helm-chart")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path))
def scan_helm_chart_cmd(path: Path) -> None:
    """Scan a Helm chart directory rooted at PATH for security misconfigurations."""
    result = scan_chart(path)

    if not result.findings:
        _print_success(path, noun="chart")
        sys.exit(0)

    _render_findings_table(
        f"Helm findings: {path}",
        [
            ("Severity", "bold"),
            ("Rule ID", None),
            ("Location", "dim"),
            ("Message", None),
            ("Remediation", None),
        ],
        [
            [
                f"[{_SEVERITY_STYLE.get(f.severity.value, 'white')}]{f.severity.value}[/{_SEVERITY_STYLE.get(f.severity.value, 'white')}]",
                f.rule_id,
                f.location,
                f.message,
                f.remediation,
            ]
            for f in result.findings
        ],
    )
    console.print(
        f"\n[bold]Total findings:[/bold] {len(result.findings)} "
        f"(critical={result.critical_count}, high={result.high_count})"
    )

    if any(f.severity in (HSeverity.HIGH, HSeverity.CRITICAL) for f in result.findings):
        console.print("[bold red]Exiting 1 — HIGH or CRITICAL findings detected.[/bold red]")
        sys.exit(1)


@cli.command("scan-image-layers")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--image-tag", default="", help="Optional image tag label shown in the report.")
@click.option("--max-layers", default=20, show_default=True, type=int, help="Maximum recommended layer count before LAY-005 triggers.")
@click.option("--max-layer-mb", default=500, show_default=True, type=int, help="Maximum recommended size for one image layer in MB.")
def scan_image_layers_cmd(path: Path, image_tag: str, max_layers: int, max_layer_mb: int) -> None:
    """Scan Docker/OCI image layer metadata from a JSON file."""
    report = _load_layer_report(path, image_tag=image_tag, max_layers=max_layers, max_layer_mb=max_layer_mb)

    if not report.findings:
        _print_success(path, noun="layer metadata")
        console.print(f"Summary: {report.summary()}", markup=False)
        sys.exit(0)

    _render_findings_table(
        f"Layer findings: {path}",
        [
            ("Severity", "bold"),
            ("Rule ID", None),
            ("Layer", None),
            ("Title", None),
            ("Evidence", "dim"),
            ("Remediation", None),
        ],
        [
            [
                f"[{_SEVERITY_STYLE.get(f.severity.value, 'white')}]{f.severity.value}[/{_SEVERITY_STYLE.get(f.severity.value, 'white')}]",
                f.check_id,
                str(f.layer_index),
                f.title,
                f.evidence or "—",
                f.remediation,
            ]
            for f in report.findings
        ],
    )
    console.print(f"\nSummary: {report.summary()}", markup=False)

    if any(f.severity.value in {"HIGH", "CRITICAL"} for f in report.findings):
        console.print("[bold red]Exiting 1 — HIGH or CRITICAL findings detected.[/bold red]")
        sys.exit(1)


@cli.command("scan-aks-nodepools")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--cluster-name", default="", help="Optional AKS cluster label shown in the report.")
def scan_aks_nodepools_cmd(path: Path, cluster_name: str) -> None:
    """Scan AKS node pool posture exported as JSON."""
    report = _load_aks_node_pool_report(path, cluster_name=cluster_name)

    if not report.findings:
        _print_success(path, noun="AKS node pool export")
        console.print(f"Summary: {report.summary()}", markup=False)
        sys.exit(0)

    _render_findings_table(
        f"AKS node pool findings: {path}",
        [
            ("Severity", "bold"),
            ("Check ID", None),
            ("Pool", None),
            ("Title", None),
            ("Detail", "dim"),
            ("Remediation", None),
        ],
        [
            [
                f"[{_SEVERITY_STYLE.get(f.severity, 'white')}]{f.severity}[/{_SEVERITY_STYLE.get(f.severity, 'white')}]",
                f.check_id,
                f.pool_name,
                f.title,
                f.detail,
                f.remediation,
            ]
            for f in report.findings
        ],
    )
    console.print(f"\nSummary: {report.summary()}", markup=False)

    if any(f.severity in {"HIGH", "CRITICAL"} for f in report.findings):
        console.print("[bold red]Exiting 1 — HIGH or CRITICAL findings detected.[/bold red]")
        sys.exit(1)


@cli.command("scan-workload-identity")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def scan_workload_identity_cmd(path: Path) -> None:
    """Scan Kubernetes workloads in PATH for cloud workload identity misconfigurations."""
    results = _load_workload_identity_results(path)
    findings = [finding for result in results for finding in result.findings]

    if not findings:
        _print_success(path, noun="workload identity manifest")
        console.print(f"Summary: analyzed {len(results)} workload(s) with no findings.", markup=False)
        sys.exit(0)

    _render_findings_table(
        f"Workload identity findings: {path}",
        [
            ("Severity", "bold"),
            ("Rule ID", None),
            ("Workload", None),
            ("Namespace", "dim"),
            ("Title", None),
            ("Detail", None),
        ],
        [
            [
                f"[{_SEVERITY_STYLE.get(finding.severity, 'white')}]{finding.severity}[/{_SEVERITY_STYLE.get(finding.severity, 'white')}]",
                finding.check_id,
                f"{result.workload_kind}/{result.workload_name}",
                result.namespace,
                finding.title,
                finding.detail,
            ]
            for result in results
            for finding in result.findings
        ],
    )
    total_risk = max(result.risk_score for result in results)
    console.print(
        f"\n[bold]Total findings:[/bold] {len(findings)} "
        f"across {len(results)} workload(s); highest workload risk score={total_risk}/100"
    )

    if any(finding.severity in {"HIGH", "CRITICAL"} for finding in findings):
        console.print("[bold red]Exiting 1 — HIGH or CRITICAL findings detected.[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    cli()
