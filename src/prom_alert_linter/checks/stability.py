"""Stability / noise checks — catch alerts likely to flap or over-fire.

Alert fatigue is one of the biggest risks in an on-call rotation.  These
checks flag patterns that produce noisy, unreliable pages.
"""

from __future__ import annotations

import re
from collections import defaultdict

from prom_alert_linter.checks.base import BaseCheck
from prom_alert_linter.models import AlertRule, Confidence, Finding, Severity
from prom_alert_linter.policy import Policy
from prom_alert_linter.utils import extract_functions, parse_duration_seconds


class MissingForClause(BaseCheck):
    """STAB001: alert has no ``for`` clause — fires on a single evaluation."""

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        if rule.duration_for is None:
            suggestion_dur = policy.default_for_suggestion
            return [
                Finding(
                    check_id="STAB001",
                    title="missing_for_clause",
                    severity=Severity.WARNING,
                    confidence=Confidence.HIGH,
                    file_path=rule.file_path,
                    group_name=rule.group_name,
                    alert_name=rule.alert_name,
                    expr=rule.expr,
                    issue="Alert has no 'for' clause and may fire on transient spikes.",
                    why_it_matters=(
                        "Without a stabilization window, a single-sample anomaly "
                        "can trigger a page. This is the #1 source of alert fatigue."
                    ),
                    suggestion=f"Add 'for: {suggestion_dur}' to require persistence.",
                    autofix_snippet=f"for: {suggestion_dur}",
                )
            ]
        return []


class ShortForDuration(BaseCheck):
    """STAB002: ``for`` duration is below the policy minimum."""

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        seconds = parse_duration_seconds(rule.duration_for)
        min_sec = policy.minimum_for_seconds
        if seconds is not None and seconds < min_sec:
            suggestion_dur = policy.default_for_suggestion
            return [
                Finding(
                    check_id="STAB002",
                    title="short_for_duration",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    file_path=rule.file_path,
                    group_name=rule.group_name,
                    alert_name=rule.alert_name,
                    expr=rule.expr,
                    issue=(
                        f"'for: {rule.duration_for}' is below the policy minimum "
                        f"({policy.minimum_for_duration})."
                    ),
                    why_it_matters=(
                        "Short stabilization windows mean brief anomalies that "
                        "resolve on their own still generate pages."
                    ),
                    suggestion=f"Consider increasing to at least '{suggestion_dur}'.",
                    autofix_snippet=f"for: {suggestion_dur}",
                )
            ]
        return []


class IrateInExpr(BaseCheck):
    """STAB003: expression uses ``irate()`` which is inherently volatile."""

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        funcs = extract_functions(rule.expr)
        if "irate" in funcs:
            # Build a suggested replacement expression
            fixed_expr = re.sub(r"\birate\(", "rate(", rule.expr)
            return [
                Finding(
                    check_id="STAB003",
                    title="irate_in_expr",
                    severity=Severity.WARNING,
                    confidence=Confidence.HIGH,
                    file_path=rule.file_path,
                    group_name=rule.group_name,
                    alert_name=rule.alert_name,
                    expr=rule.expr,
                    issue=(
                        "Expression uses irate() which computes an instantaneous "
                        "rate from the last two samples."
                    ),
                    why_it_matters=(
                        "irate() is inherently spiky and volatile. It's designed "
                        "for dashboards, not alerting. Using it in alerts causes "
                        "flapping and false positives."
                    ),
                    suggestion="Replace irate() with rate() over an appropriate window.",
                    autofix_snippet=f"expr: {fixed_expr.strip()}",
                )
            ]
        return []


class InstantThresholdWithoutSmoothing(BaseCheck):
    """STAB004: direct threshold on a raw metric without smoothing."""

    _BARE_THRESHOLD = re.compile(
        r"^[a-zA-Z_:][a-zA-Z0-9_:]*\s*"
        r"(?:\{[^}]*\})?\s*"
        r"(?:>|>=|<|<=|==|!=)\s*"
        r"[\d.]+\s*$"
    )

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        expr = rule.expr.strip()
        funcs = extract_functions(expr)
        if funcs:
            return []
        if self._BARE_THRESHOLD.match(expr):
            return [
                Finding(
                    check_id="STAB004",
                    title="instant_threshold_without_smoothing",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    file_path=rule.file_path,
                    group_name=rule.group_name,
                    alert_name=rule.alert_name,
                    expr=rule.expr,
                    issue=(
                        "Expression applies a threshold directly to a raw metric "
                        "without any smoothing function."
                    ),
                    why_it_matters=(
                        "Noisy gauge metrics can briefly exceed a threshold due to "
                        "measurement jitter. A 'for' clause alone may not fully "
                        "prevent false positives on very noisy signals."
                    ),
                    suggestion=(
                        "Consider wrapping the metric in avg_over_time(), "
                        "rate(), or another windowed function."
                    ),
                )
            ]
        return []


class CriticalFiresBeforeWarning(BaseCheck):
    """STAB005: critical variant fires sooner than its warning counterpart."""

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        return []  # cross-rule only

    def check_all(
        self, rules: list[AlertRule], policy: Policy
    ) -> list[Finding]:
        findings: list[Finding] = []
        groups: dict[str, list[AlertRule]] = defaultdict(list)
        for r in rules:
            groups[self._base_name(r)].append(r)

        for _base, group in groups.items():
            warnings = [
                r for r in group
                if policy.is_warning_severity(r.labels.get(policy.severity_label_key, ""))
            ]
            criticals = [
                r for r in group
                if policy.is_critical_severity(r.labels.get(policy.severity_label_key, ""))
            ]

            for warn in warnings:
                for crit in criticals:
                    w_sec = parse_duration_seconds(warn.duration_for)
                    c_sec = parse_duration_seconds(crit.duration_for)
                    if w_sec is not None and c_sec is not None and c_sec < w_sec:
                        findings.append(
                            Finding(
                                check_id="STAB005",
                                title="critical_fires_before_warning",
                                severity=Severity.WARNING,
                                confidence=Confidence.HIGH,
                                file_path=crit.file_path,
                                group_name=crit.group_name,
                                alert_name=crit.alert_name,
                                expr=crit.expr,
                                issue=(
                                    f"Critical fires after {crit.duration_for} but "
                                    f"warning '{warn.alert_name}' requires "
                                    f"{warn.duration_for}."
                                ),
                                why_it_matters=(
                                    "If critical fires before warning, engineers get "
                                    "paged before seeing a warning — defeating the "
                                    "purpose of tiered escalation."
                                ),
                                suggestion=(
                                    "Ensure the critical 'for' duration is >= the "
                                    "warning 'for' duration."
                                ),
                                autofix_snippet=f"for: {warn.duration_for}",
                                related_alerts=[warn.alert_name],
                            )
                        )
        return findings

    @staticmethod
    def _base_name(rule: AlertRule) -> str:
        name = rule.alert_name
        for suffix in ("Warning", "Critical", "Page", "Info"):
            if name.endswith(suffix):
                return name[: -len(suffix)]
        return name
