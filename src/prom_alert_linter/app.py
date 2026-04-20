"""Application orchestration service.

This module coordinates the complete lifecycle of a linting run:
1. Discovery
2. Parsing
3. Checking
4. Aggregation
"""

from __future__ import annotations

import logging
from pathlib import Path

from prom_alert_linter.checks.registry import get_all_checks
from prom_alert_linter.discovery import resolve_paths
from prom_alert_linter.models import AnalysisResult, Summary, Severity
from prom_alert_linter.parser import parse_files
from prom_alert_linter.policy import Policy, load_policy

logger = logging.getLogger(__name__)


class AnalyzerEngine:
    """Orchestrates the analysis pipeline."""

    def __init__(self, policy: Policy | None = None):
        """Initialize the engine with an explicit policy or fallback to default."""
        self.policy = policy if policy is not None else load_policy()
        self.checks = get_all_checks()

    def run(self, paths: list[Path], recursive: bool = False, min_severity: Severity | None = None) -> AnalysisResult:
        """Execute the full pipeline on a set of paths and return the final result."""
        # 1. Discovery
        resolved = resolve_paths(paths, recursive)
        if not resolved:
            logger.warning("No files found to lint.")
            return AnalysisResult(
                findings=[],
                summary=Summary(0, 0, 0, {s.value: 0 for s in Severity}, 0),
                parse_errors=[]
            )

        # 2. Parsing
        parse_result = parse_files(resolved)

        # 3. Checking
        findings = []
        for check in self.checks:
            check_findings = check.check_all(parse_result.alert_rules, self.policy)
            for f in check_findings:
                if f.check_id in self.policy.ignored_checks_set:
                    continue
                if f.alert_name in self.policy.ignored_names_set:
                    continue
                findings.append(f)

        # Filtering
        if min_severity:
            findings = [f for f in findings if f.severity >= min_severity]

        # Sorting: errors first, then warnings, then info, then alphabetically
        # Severity ENUM __ge__ etc handles severity ordering, but to be safe we use a rank mapping
        rank = {Severity.ERROR: 2, Severity.WARNING: 1, Severity.INFO: 0}
        findings.sort(
            key=lambda f: (-rank[f.severity], f.file_path, f.alert_name, f.check_id)
        )

        # Summarizing
        sev_counts = {s.value: 0 for s in Severity}
        for f in findings:
            sev_counts[f.severity.value] += 1

        summary = Summary(
            files_scanned=parse_result.scanned_files,
            rules_scanned=len(parse_result.alert_rules),
            findings_total=len(findings),
            findings_by_severity=sev_counts,
            parse_errors=len(parse_result.parse_errors)
        )

        return AnalysisResult(
            findings=findings,
            summary=summary,
            parse_errors=parse_result.parse_errors
        )
