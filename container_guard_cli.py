"""
container-defense-stack CLI

Entry points:
  validate-manifest PATH   — Validate a Kubernetes YAML manifest for security issues.
  validate-dockerfile PATH — Validate a Dockerfile for security issues.

Exit codes:
  0 — No HIGH or CRITICAL findings.
  1 — One or more HIGH or CRITICAL findings detected.
"""
from __future__ import annotations

import sys
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.table import Table

from validators.dockerfile_validator import Severity as DSeverity
from validators.dockerfile_validator import validate_dockerfile
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


@cli.command("validate-manifest")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def validate_manifest_cmd(path: Path) -> None:
    """Validate a Kubernetes YAML manifest at PATH for security misconfigurations."""
    findings = validate_manifest(path)

    if not findings:
        console.print(f"[bold green]No findings — {path} is secure.[/bold green]")
        sys.exit(0)

    table = Table(title=f"Findings: {path}", box=box.ROUNDED, show_lines=True)
    table.add_column("Severity", style="bold", no_wrap=True)
    table.add_column("Rule ID", no_wrap=True)
    table.add_column("Message")
    table.add_column("Path", style="dim")
    table.add_column("Remediation")

    high_or_critical = False
    for finding in findings:
        style = _SEVERITY_STYLE.get(finding.severity.value, "white")
        table.add_row(
            f"[{style}]{finding.severity.value}[/{style}]",
            finding.rule_id,
            finding.message,
            finding.path,
            finding.remediation,
        )
        if finding.severity in (MSeverity.HIGH, MSeverity.CRITICAL):
            high_or_critical = True

    console.print(table)
    console.print(f"\n[bold]Total findings:[/bold] {len(findings)}")

    if high_or_critical:
        console.print("[bold red]Exiting 1 — HIGH or CRITICAL findings detected.[/bold red]")
        sys.exit(1)


@cli.command("validate-dockerfile")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def validate_dockerfile_cmd(path: Path) -> None:
    """Validate a Dockerfile at PATH for security misconfigurations."""
    findings = validate_dockerfile(path)

    if not findings:
        console.print(f"[bold green]No findings — {path} is secure.[/bold green]")
        sys.exit(0)

    table = Table(title=f"Findings: {path}", box=box.ROUNDED, show_lines=True)
    table.add_column("Severity", style="bold", no_wrap=True)
    table.add_column("Rule ID", no_wrap=True)
    table.add_column("Line", no_wrap=True)
    table.add_column("Message")
    table.add_column("Remediation")

    high_or_critical = False
    for finding in findings:
        style = _SEVERITY_STYLE.get(finding.severity.value, "white")
        line_str = str(finding.line) if finding.line > 0 else "—"
        table.add_row(
            f"[{style}]{finding.severity.value}[/{style}]",
            finding.rule_id,
            line_str,
            finding.message,
            finding.remediation,
        )
        if finding.severity == DSeverity.HIGH:
            high_or_critical = True

    console.print(table)
    console.print(f"\n[bold]Total findings:[/bold] {len(findings)}")

    if high_or_critical:
        console.print("[bold red]Exiting 1 — HIGH findings detected.[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    cli()
