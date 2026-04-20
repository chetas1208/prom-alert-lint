"""Domain models for parsed alert rules, findings, and analysis results."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(enum.Enum):
    """Severity of a lint finding, ordered from least to most severe."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"

    def __ge__(self, other: "Severity") -> bool:
        return _SEV_RANK[self] >= _SEV_RANK[other]

    def __gt__(self, other: "Severity") -> bool:
        return _SEV_RANK[self] > _SEV_RANK[other]

    def __le__(self, other: "Severity") -> bool:
        return _SEV_RANK[self] <= _SEV_RANK[other]

    def __lt__(self, other: "Severity") -> bool:
        return _SEV_RANK[self] < _SEV_RANK[other]


_SEV_RANK = {Severity.INFO: 0, Severity.WARNING: 1, Severity.ERROR: 2}


class Confidence(enum.Enum):
    """How confident are we that a finding is a real problem?"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ---------------------------------------------------------------------------
# AST representations
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AlertRule:
    """A single Prometheus alerting rule extracted from YAML.

    Fields are intentionall flat. The raw dict is preserved so checks can
    access anything we didn't destructure.
    """
    file_path: str
    group_name: str
    alert_name: str
    expr: str
    duration_for: str | None
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    line_number: int | None = None


# ---------------------------------------------------------------------------
# Output representations
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    """A single lint finding produced by a check."""
    check_id: str
    title: str
    severity: Severity
    confidence: Confidence
    file_path: str
    group_name: str
    alert_name: str
    expr: str
    issue: str
    why_it_matters: str
    suggestion: str
    autofix_snippet: str | None = None
    related_alerts: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "file_path": self.file_path,
            "group_name": self.group_name,
            "alert_name": self.alert_name,
            "expr": self.expr,
            "issue": self.issue,
            "why_it_matters": self.why_it_matters,
            "suggestion": self.suggestion,
        }
        if self.autofix_snippet:
            d["autofix_snippet"] = self.autofix_snippet
        if self.related_alerts:
            d["related_alerts"] = self.related_alerts
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass(frozen=True)
class ParseErrorDetails:
    """Encapsulates a parse failure for a specific file."""
    file_path: str
    error_message: str


@dataclass(frozen=True)
class ParseResult:
    """The result of the parsing stage."""
    alert_rules: list[AlertRule] = field(default_factory=list)
    parse_errors: list[ParseErrorDetails] = field(default_factory=list)
    scanned_files: int = 0


@dataclass(frozen=True)
class Summary:
    """Aggregated statistics for a complete run."""
    files_scanned: int
    rules_scanned: int
    findings_total: int
    findings_by_severity: dict[str, int]
    parse_errors: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "rules_scanned": self.rules_scanned,
            "findings_total": self.findings_total,
            "findings_by_severity": self.findings_by_severity,
            "parse_errors": self.parse_errors,
        }


@dataclass(frozen=True)
class AnalysisResult:
    """The final result of the analysis stage, ready for reporting."""
    findings: list[Finding]
    summary: Summary
    parse_errors: list[ParseErrorDetails]

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary.to_dict(),
            "parse_errors": [
                {"file_path": e.file_path, "error": e.error_message}
                for e in self.parse_errors
            ],
            "findings": [f.to_dict() for f in self.findings],
        }

