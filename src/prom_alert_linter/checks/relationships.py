"""Relationship / cross-alert checks — analyse the rule set as a whole.

Single-rule checks answer "is this alert well-formed?"  Cross-alert
checks answer "does this alert make sense alongside the others?"

Duplicate names, identical expressions, inverted thresholds, and
overlapping alerts are invisible when you look at rules one at a time.
"""

from __future__ import annotations

import re
from collections import defaultdict

import yaml

from prom_alert_linter.checks.base import BaseCheck
from prom_alert_linter.models import AlertRule, Confidence, Finding, Severity
from prom_alert_linter.policy import Policy
from prom_alert_linter.utils import extract_metric_names, parse_duration_seconds


class DuplicateAlertNames(BaseCheck):
    """REL001: same alert name appears in multiple files or groups."""

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        return []

    def check_all(
        self, rules: list[AlertRule], policy: Policy
    ) -> list[Finding]:
        by_name: dict[str, list[AlertRule]] = defaultdict(list)
        for r in rules:
            by_name[r.alert_name].append(r)

        findings: list[Finding] = []
        for name, dupes in by_name.items():
            if len(dupes) <= 1:
                continue
            locations = ", ".join(
                f"{r.file_path}::{r.group_name}" for r in dupes
            )

            # Check for conflicting metadata
            conflicts: list[str] = []
            first = dupes[0]
            for other in dupes[1:]:
                if first.labels != other.labels:
                    conflicts.append("labels differ")
                if first.annotations != other.annotations:
                    conflicts.append("annotations differ")

            conflict_msg = ""
            if conflicts:
                conflict_msg = f" Conflicts detected: {', '.join(set(conflicts))}."

            for dupe in dupes[1:]:
                findings.append(
                    Finding(
                        check_id="REL001",
                        title="duplicate_alert_names",
                        severity=Severity.WARNING,
                        confidence=Confidence.HIGH,
                        file_path=dupe.file_path,
                        group_name=dupe.group_name,
                        alert_name=dupe.alert_name,
                        expr=dupe.expr,
                        issue=(
                            f"Alert name '{name}' is defined {len(dupes)} times "
                            f"across: {locations}.{conflict_msg}"
                        ),
                        why_it_matters=(
                            "Duplicate names cause confusing routing and silencing. "
                            "If they have different metadata, teams may disagree on "
                            "ownership or severity."
                        ),
                        suggestion=(
                            "Consolidate or differentiate these alerts with "
                            "unique names."
                        ),
                        related_alerts=[
                            f"{r.alert_name} ({r.file_path})" for r in dupes
                            if r is not dupe
                        ],
                    )
                )
        return findings


class IdenticalExpressions(BaseCheck):
    """REL002: different alert names use the exact same expression."""

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        return []

    def check_all(
        self, rules: list[AlertRule], policy: Policy
    ) -> list[Finding]:
        by_expr: dict[str, list[AlertRule]] = defaultdict(list)
        for r in rules:
            normalised = re.sub(r"\s+", " ", r.expr.strip())
            by_expr[normalised].append(r)

        findings: list[Finding] = []
        for _expr, group in by_expr.items():
            if len(group) <= 1:
                continue
            names = [r.alert_name for r in group]
            for r in group[1:]:
                findings.append(
                    Finding(
                        check_id="REL002",
                        title="identical_expressions",
                        severity=Severity.WARNING,
                        confidence=Confidence.HIGH,
                        file_path=r.file_path,
                        group_name=r.group_name,
                        alert_name=r.alert_name,
                        expr=r.expr,
                        issue=(
                            f"Alert shares an identical expression with: "
                            f"{', '.join(names)}."
                        ),
                        why_it_matters=(
                            "Identical expressions under different names suggest "
                            "copy-paste duplication. Both alerts fire on the same "
                            "condition, creating redundant noise."
                        ),
                        suggestion=(
                            "If intentional, add a comment explaining why. "
                            "Otherwise, consolidate into a single alert."
                        ),
                        related_alerts=[
                            f"{a.alert_name} ({a.file_path})" for a in group
                            if a is not r
                        ],
                    )
                )
        return findings


class LikelyDuplicateAlerts(BaseCheck):
    """REL003: same expression + different metadata = likely copy-paste."""

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        return []

    def check_all(
        self, rules: list[AlertRule], policy: Policy
    ) -> list[Finding]:
        by_expr: dict[str, list[AlertRule]] = defaultdict(list)
        for r in rules:
            normalised = re.sub(r"\s+", " ", r.expr.strip())
            by_expr[normalised].append(r)

        findings: list[Finding] = []
        for _expr, group in by_expr.items():
            if len(group) <= 1:
                continue
            names = {r.alert_name for r in group}
            if len(names) <= 1:
                continue  # same-name duplicates caught by REL001

            first = group[0]
            for other in group[1:]:
                if first.labels != other.labels or first.annotations != other.annotations:
                    findings.append(
                        Finding(
                            check_id="REL003",
                            title="likely_duplicate_alerts",
                            severity=Severity.INFO,
                            confidence=Confidence.MEDIUM,
                            file_path=other.file_path,
                            group_name=other.group_name,
                            alert_name=other.alert_name,
                            expr=other.expr,
                            issue=(
                                f"Same expression as '{first.alert_name}' but "
                                f"different metadata — likely copy-paste."
                            ),
                            why_it_matters=(
                                "Unintentional duplicates waste on-call attention "
                                "and complicate silencing. If intentional, the "
                                "names and metadata should make the distinction clear."
                            ),
                            suggestion=(
                                "Verify both alerts are intentional. If so, "
                                "differentiate names and metadata clearly."
                            ),
                            related_alerts=[
                                f"{first.alert_name} ({first.file_path})"
                            ],
                        )
                    )
        return findings


class SuspiciousThresholdOrdering(BaseCheck):
    """REL004: warning/critical pair has inverted threshold ordering."""

    _THRESHOLD_RE = re.compile(r"(>|>=|<|<=)\s*([\d.]+)\s*$")

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        return []

    def check_all(
        self, rules: list[AlertRule], policy: Policy
    ) -> list[Finding]:
        findings: list[Finding] = []
        groups: dict[str, list[AlertRule]] = defaultdict(list)
        for r in rules:
            groups[self._base_name(r)].append(r)

        sev_key = policy.severity_label_key

        for _base, group in groups.items():
            warnings = [
                r for r in group
                if policy.is_warning_severity(r.labels.get(sev_key, ""))
            ]
            criticals = [
                r for r in group
                if policy.is_critical_severity(r.labels.get(sev_key, ""))
            ]

            for warn in warnings:
                w_match = self._THRESHOLD_RE.search(warn.expr)
                if not w_match:
                    continue
                w_op, w_val = w_match.group(1), float(w_match.group(2))

                for crit in criticals:
                    c_match = self._THRESHOLD_RE.search(crit.expr)
                    if not c_match:
                        continue
                    c_op, c_val = c_match.group(1), float(c_match.group(2))

                    inverted = False
                    if c_op in (">", ">=") and w_op in (">", ">="):
                        inverted = c_val < w_val
                    elif c_op in ("<", "<=") and w_op in ("<", "<="):
                        inverted = c_val > w_val

                    if inverted:
                        findings.append(
                            Finding(
                                check_id="REL004",
                                title="suspicious_threshold_ordering",
                                severity=Severity.ERROR,
                                confidence=Confidence.HIGH,
                                file_path=crit.file_path,
                                group_name=crit.group_name,
                                alert_name=crit.alert_name,
                                expr=crit.expr,
                                issue=(
                                    f"Critical threshold ({c_val}) is less severe "
                                    f"than warning ({w_val}) for '{warn.alert_name}'."
                                ),
                                why_it_matters=(
                                    "An inverted threshold means critical fires "
                                    "on a less serious condition than warning. "
                                    "This defeats tiered alerting."
                                ),
                                suggestion="Swap the thresholds.",
                                autofix_snippet=(
                                    f"# {crit.alert_name}: change threshold to "
                                    f"{w_op} {w_val} (swap with warning)\n"
                                    f"# {warn.alert_name}: change threshold to "
                                    f"{c_op} {c_val}"
                                ),
                                related_alerts=[
                                    f"{warn.alert_name} ({warn.file_path})"
                                ],
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


class OverlappingAlerts(BaseCheck):
    """REL005: alerts on the same metric family with close thresholds."""

    _THRESHOLD_RE = re.compile(r"(>|>=|<|<=)\s*([\d.]+)")

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        return []

    def check_all(
        self, rules: list[AlertRule], policy: Policy
    ) -> list[Finding]:
        findings: list[Finding] = []
        sev_key = policy.severity_label_key

        by_metric: dict[str, list[AlertRule]] = defaultdict(list)
        for r in rules:
            metrics = extract_metric_names(r.expr)
            if metrics:
                by_metric[metrics[0]].append(r)

        for _metric, group in by_metric.items():
            if len(group) <= 1:
                continue

            checked: set[tuple[str, str]] = set()
            for i, a in enumerate(group):
                for b in group[i + 1:]:
                    pair = tuple(sorted([a.alert_name, b.alert_name]))
                    if pair in checked:
                        continue
                    checked.add(pair)

                    # Skip intentional warning/critical pairs
                    sev_a = a.labels.get(sev_key, "").lower()
                    sev_b = b.labels.get(sev_key, "").lower()
                    if (policy.is_warning_severity(sev_a) and
                            policy.is_critical_severity(sev_b)):
                        continue
                    if (policy.is_critical_severity(sev_a) and
                            policy.is_warning_severity(sev_b)):
                        continue

                    a_t = self._extract_threshold(a.expr)
                    b_t = self._extract_threshold(b.expr)
                    if a_t is None or b_t is None:
                        continue

                    bigger = max(abs(a_t), abs(b_t))
                    if bigger == 0:
                        continue
                    diff = abs(a_t - b_t) / bigger
                    if diff < 0.20:
                        findings.append(
                            Finding(
                                check_id="REL005",
                                title="overlapping_alerts",
                                severity=Severity.INFO,
                                confidence=Confidence.MEDIUM,
                                file_path=b.file_path,
                                group_name=b.group_name,
                                alert_name=b.alert_name,
                                expr=b.expr,
                                issue=(
                                    f"Very similar threshold to '{a.alert_name}' "
                                    f"on the same metric (< 20% difference)."
                                ),
                                why_it_matters=(
                                    "Both alerts will likely fire simultaneously, "
                                    "creating redundant pages that dilute attention."
                                ),
                                suggestion=(
                                    "Consider merging or widening the threshold gap."
                                ),
                                related_alerts=[
                                    f"{a.alert_name} ({a.file_path})"
                                ],
                            )
                        )
        return findings

    def _extract_threshold(self, expr: str) -> float | None:
        m = self._THRESHOLD_RE.search(expr)
        return float(m.group(2)) if m else None


class ConflictingDefinitions(BaseCheck):
    """REL006: same alert name with conflicting severity or runbook."""

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        return []

    def check_all(
        self, rules: list[AlertRule], policy: Policy
    ) -> list[Finding]:
        by_name: dict[str, list[AlertRule]] = defaultdict(list)
        for r in rules:
            by_name[r.alert_name].append(r)

        findings: list[Finding] = []
        sev_key = policy.severity_label_key

        for name, dupes in by_name.items():
            if len(dupes) <= 1:
                continue

            severities = {r.labels.get(sev_key, "<none>") for r in dupes}
            runbooks = set()
            for r in dupes:
                for key in policy.runbook_annotation_keys:
                    if key in r.annotations:
                        runbooks.add(r.annotations[key])

            conflicts: list[str] = []
            if len(severities) > 1:
                conflicts.append(f"severity values: {severities}")
            if len(runbooks) > 1:
                conflicts.append(f"runbook urls: {runbooks}")

            if conflicts:
                findings.append(
                    Finding(
                        check_id="REL006",
                        title="conflicting_definitions",
                        severity=Severity.WARNING,
                        confidence=Confidence.HIGH,
                        file_path=dupes[1].file_path,
                        group_name=dupes[1].group_name,
                        alert_name=name,
                        expr=dupes[1].expr,
                        issue=(
                            f"Alert '{name}' has conflicting definitions: "
                            f"{'; '.join(conflicts)}."
                        ),
                        why_it_matters=(
                            "Conflicting severity or runbook URLs between "
                            "duplicate definitions means on-call gets "
                            "inconsistent information depending on which "
                            "Prometheus evaluates first."
                        ),
                        suggestion=(
                            "Consolidate into a single definition with "
                            "consistent metadata."
                        ),
                        related_alerts=[
                            f"{r.alert_name} ({r.file_path})" for r in dupes
                        ],
                    )
                )
        return findings
