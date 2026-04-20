"""CLI entry-point for prom-alert-lint.

The CLI acts an adapter resolving configurations and invoking the AnalyzerEngine.

Usage examples::

    prom-alert-lint rules.yaml
    prom-alert-lint ./rules-dir --recursive
    prom-alert-lint ./examples --policy policy.yaml --fail-on error
"""

from __future__ import annotations

import logging
from pathlib import Path

import typer

from prom_alert_linter.app import AnalyzerEngine
from prom_alert_linter.exit_codes import compute_exit_code
from prom_alert_linter.models import Severity
from prom_alert_linter.policy import PolicyError, load_policy
from prom_alert_linter.reporter import print_json_report, print_text_report

app = typer.Typer(
    name="prom-alert-lint",
    help="Analyse Prometheus alerting rule YAML files and flag quality issues.",
    add_completion=False,
)

_SEVERITY_MAP = {
    "info": Severity.INFO,
    "warning": Severity.WARNING,
    "error": Severity.ERROR,
}


@app.command()
def lint(
    paths: list[Path] = typer.Argument(
        ...,
        help="One or more YAML files or directories to analyse.",
        exists=False,
    ),
    format: str = typer.Option(
        "text", "--format", "-f",
        help="Output format: text or json.",
    ),
    min_severity: str = typer.Option(
        "info", "--min-severity", "-s",
        help="Only show findings at or above this severity.",
    ),
    fail_on: str = typer.Option(
        "warning", "--fail-on",
        help="Exit 1 if any finding is at or above this severity.",
    ),
    policy_path: Path | None = typer.Option(
        None, "--policy", "-p",
        help="Path to a YAML policy file for team-specific configuration.",
    ),
    no_color: bool = typer.Option(
        False, "--no-color",
        help="Disable colour output.",
    ),
    recursive: bool = typer.Option(
        False, "--recursive", "-r",
        help="Recurse into subdirectories.",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Enable debug logging.",
    ),
) -> None:
    """Analyse Prometheus alerting rules and report findings."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")

    # Validate options early
    min_sev = _SEVERITY_MAP.get(min_severity.lower())
    if min_sev is None:
        typer.echo(f"Error: unknown severity '{min_severity}'", err=True)
        raise typer.Exit(code=2)

    fail_sev = _SEVERITY_MAP.get(fail_on.lower())
    if fail_sev is None:
        typer.echo(f"Error: unknown severity '{fail_on}'", err=True)
        raise typer.Exit(code=2)

    if format.lower() not in ("text", "json"):
        typer.echo(f"Error: unknown format '{format}'", err=True)
        raise typer.Exit(code=2)

    # Policy Loading Stage
    try:
        policy = load_policy(policy_path)
    except PolicyError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2)

    # Initialize orchestrator
    engine = AnalyzerEngine(policy=policy)
    
    # Run analysis pipeline
    result = engine.run(paths=paths, recursive=recursive, min_severity=min_sev)

    # Report generating stage
    if format.lower() == "json":
        print_json_report(result)
    else:
        print_text_report(result, no_color=no_color)

    # Check for empty files warning, only if we successfully reached the end and didn't find any.
    if result.summary.files_scanned == 0 and not result.parse_errors:
        typer.echo("Error: no YAML files found in the provided paths.", err=True)
        raise typer.Exit(code=2)

    # Decide exit code
    exit_code = compute_exit_code(result, fail_sev)
    raise typer.Exit(code=exit_code)
