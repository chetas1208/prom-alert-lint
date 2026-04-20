"""Output formatting — human-readable and JSON reporters."""

from __future__ import annotations

import json
from typing import TextIO

from rich.console import Console
from rich.text import Text

from prom_alert_linter.models import AnalysisResult, Severity


_SEVERITY_STYLES = {
    Severity.ERROR: "bold red",
    Severity.WARNING: "yellow",
    Severity.INFO: "cyan",
}


def print_text_report(
    result: AnalysisResult,
    file: TextIO | None = None,
    no_color: bool = False,
) -> None:
    """Print a human-readable, scannable report to the terminal."""
    console = Console(file=file, no_color=no_color, width=120)

    if result.parse_errors:
        console.print("[bold red]Parsing Errors[/]")
        for err in result.parse_errors:
            console.print(f"  [red]- {err.file_path}:[/] {err.error_message}")
        console.print()

    if not result.findings and not result.parse_errors:
        console.print("\n✅ [bold green]No findings — all rules look clean![/]\n")
        _print_summary(console, result)
        return
    elif not result.findings:
        console.print("\n✅ [bold green]No rule quality findings, but parse errors exist.[/]\n")
        _print_summary(console, result)
        return

    for finding in result.findings:
        style = _SEVERITY_STYLES[finding.severity]
        tag = finding.severity.value.upper()

        header = Text()
        header.append(f"[{tag}]", style=style)
        header.append(f" {finding.file_path}", style="bold")
        header.append(f" :: group={finding.group_name}", style="dim")
        header.append(f" :: alert={finding.alert_name}", style="bold")
        console.print(header)

        console.print(f"  check: {finding.check_id}", style="dim")
        console.print(f"  confidence: {finding.confidence.value}", style="dim")
        console.print(f"  issue: {finding.issue}")
        console.print(f"  why it matters: {finding.why_it_matters}", style="dim italic")
        console.print(f"  suggestion: {finding.suggestion}", style="green")

        if finding.autofix_snippet:
            console.print("  autofix:", style="bold magenta")
            for line in finding.autofix_snippet.splitlines():
                console.print(f"    {line}", style="magenta")

        if finding.related_alerts:
            console.print(
                f"  related: {', '.join(finding.related_alerts)}", style="dim"
            )

        console.print()

    _print_summary(console, result)


def _print_summary(console: Console, result: AnalysisResult) -> None:
    """Print the aggregated summary."""
    counts = result.summary.findings_by_severity
    console.rule("[bold]Summary")
    console.print(f"  Files scanned:   {result.summary.files_scanned}")
    console.print(f"  Rules scanned:   {result.summary.rules_scanned}")
    console.print(f"  Parse Errors:    {result.summary.parse_errors}")
    console.print(f"  Total findings:  {result.summary.findings_total}")
    console.print(
        f"  Errors: {counts['error']}  |  "
        f"Warnings: {counts['warning']}  |  "
        f"Info: {counts['info']}"
    )
    console.print()


def print_json_report(result: AnalysisResult, file: TextIO | None = None) -> None:
    """Print a machine-readable JSON report."""
    import sys
    target = file or sys.stdout
    json.dump(result.to_dict(), target, indent=2)
    target.write("\n")
