"""Selector quality checks — catch expressions that are too broad or too brittle.

An alert that selects ``up == 0`` with no label filters will page for every
target.  An alert pinned to a specific pod name stops working after the
next deploy.
"""

from __future__ import annotations

import re

import yaml

from prom_alert_linter.checks.base import BaseCheck
from prom_alert_linter.models import AlertRule, Confidence, Finding, Severity
from prom_alert_linter.policy import Policy
from prom_alert_linter.utils import (
    HASH_LABEL_RE,
    extract_label_matchers,
    extract_metric_names,
    has_label_filters,
)


class BareMetricSelector(BaseCheck):
    """SEL001: expression uses a metric with no label filters at all."""

    _BARE_RE = re.compile(
        r"\b([a-zA-Z_:][a-zA-Z0-9_:]*)\s*(?:\{\s*\})?\s*(?:[><=!]|$)"
    )

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        if has_label_filters(rule.expr):
            return []
        if self._BARE_RE.search(rule.expr):
            return [
                Finding(
                    check_id="SEL001",
                    title="bare_metric_selector",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    file_path=rule.file_path,
                    group_name=rule.group_name,
                    alert_name=rule.alert_name,
                    expr=rule.expr,
                    issue=(
                        "Expression uses a bare metric selector with no label "
                        "filters."
                    ),
                    why_it_matters=(
                        "Without label matchers, the alert matches every time "
                        "series for the metric. This can create unexpected "
                        "blast radius or noisy per-target alerts."
                    ),
                    suggestion="Add label matchers (e.g. job, namespace) to scope.",
                )
            ]
        return []


class BroadUpSelector(BaseCheck):
    """SEL002: ``up == 0`` without scoping labels is a blast-radius risk."""

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        # Check all metrics configured as broad-selector risks
        for metric in policy.broad_selector_metrics:
            pattern = re.compile(
                rf"\b{re.escape(metric)}\s*(?:\{{\s*\}})?\s*==\s*0"
            )
            if pattern.search(rule.expr) and not has_label_filters(rule.expr):
                return [
                    Finding(
                        check_id="SEL002",
                        title="broad_up_selector",
                        severity=Severity.WARNING,
                        confidence=Confidence.HIGH,
                        file_path=rule.file_path,
                        group_name=rule.group_name,
                        alert_name=rule.alert_name,
                        expr=rule.expr,
                        issue=(
                            f"'{metric} == 0' without label filters will fire for "
                            "every down target in the scrape config."
                        ),
                        why_it_matters=(
                            "A single maintenance window or network blip can "
                            "trigger hundreds of identical pages, one per target."
                        ),
                        suggestion="Scope with job, namespace, or service labels.",
                        autofix_snippet=(
                            f'expr: {metric}{{job="your-job"}} == 0'
                        ),
                    )
                ]
        return []


class EphemeralLabelDependency(BaseCheck):
    """SEL003: expression equality-matches on ephemeral labels."""

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        matchers = extract_label_matchers(rule.expr)
        findings: list[Finding] = []
        ephemeral = policy.ephemeral_labels_set

        for label, op, value in matchers:
            if op != "=":
                continue

            is_ephemeral = label in ephemeral
            is_hash = bool(HASH_LABEL_RE.fullmatch(value))

            if is_ephemeral or is_hash:
                reason = (
                    f"ephemeral label '{label}'"
                    if is_ephemeral
                    else f"hash-like value '{value}' for label '{label}'"
                )
                findings.append(
                    Finding(
                        check_id="SEL003",
                        title="ephemeral_label_dependency",
                        severity=Severity.WARNING,
                        confidence=Confidence.HIGH if is_ephemeral else Confidence.MEDIUM,
                        file_path=rule.file_path,
                        group_name=rule.group_name,
                        alert_name=rule.alert_name,
                        expr=rule.expr,
                        issue=f"Expression depends on {reason}.",
                        why_it_matters=(
                            "Ephemeral labels change with pod reschedules or "
                            "deploys. The alert silently stops matching after "
                            "the next rollout."
                        ),
                        suggestion=(
                            "Use stable labels (job, namespace, service) or "
                            "aggregate away the ephemeral dimension."
                        ),
                    )
                )

        return findings


class OverlyNarrowSelector(BaseCheck):
    """SEL004: expression pins to a single auto-generated pod/instance name."""

    _GENERATED_NAME = re.compile(
        r"-[a-z0-9]*[0-9][a-z0-9]*-[a-z0-9]{4,6}$"
    )

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        matchers = extract_label_matchers(rule.expr)
        ephemeral = policy.ephemeral_labels_set

        for label, op, value in matchers:
            if op != "=":
                continue
            if label in ("pod", "pod_name", "instance") or label in ephemeral:
                if self._GENERATED_NAME.search(value):
                    return [
                        Finding(
                            check_id="SEL004",
                            title="overly_narrow_selector",
                            severity=Severity.WARNING,
                            confidence=Confidence.HIGH,
                            file_path=rule.file_path,
                            group_name=rule.group_name,
                            alert_name=rule.alert_name,
                            expr=rule.expr,
                            issue=(
                                f"Expression pins to {label}='{value}' which "
                                "looks auto-generated."
                            ),
                            why_it_matters=(
                                "Auto-generated names change every deploy or "
                                "reschedule. This alert will silently stop "
                                "matching."
                            ),
                            suggestion=(
                                "Use a stable selector like a deployment name, "
                                "label set, or regex match."
                            ),
                            autofix_snippet=(
                                f'{label}=~"{value.rsplit("-", 2)[0]}-.*"'
                            ),
                        )
                    ]
        return []
