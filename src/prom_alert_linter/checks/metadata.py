"""Metadata checks — ensure alerts carry enough context for on-call engineers.

A page that arrives with no description, no runbook, and no owning team is
effectively a riddle wrapped in a PagerDuty notification.
"""

from __future__ import annotations

import yaml

from prom_alert_linter.checks.base import BaseCheck
from prom_alert_linter.models import AlertRule, Confidence, Finding, Severity
from prom_alert_linter.policy import Policy


class MissingSeverityLabel(BaseCheck):
    """META001: alert has no severity label (key from policy)."""

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        key = policy.severity_label_key
        if key not in rule.labels:
            return [
                Finding(
                    check_id="META001",
                    title="missing_severity_label",
                    severity=Severity.ERROR,
                    confidence=Confidence.HIGH,
                    file_path=rule.file_path,
                    group_name=rule.group_name,
                    alert_name=rule.alert_name,
                    expr=rule.expr,
                    issue=f"Alert is missing a '{key}' label.",
                    why_it_matters=(
                        "Without a severity label, notification routing and "
                        "escalation policies cannot prioritize this alert. "
                        "It may be treated as low-priority or lost entirely."
                    ),
                    suggestion=f"Add a '{key}' label with an appropriate value.",
                    autofix_snippet=yaml.dump(
                        {"labels": {key: "warning"}}, default_flow_style=False
                    ).strip(),
                )
            ]
        return []


class MissingSummaryAnnotation(BaseCheck):
    """META002: alert has no ``summary`` annotation."""

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        if "summary" not in rule.annotations and "summary" in policy.required_annotations:
            return [
                Finding(
                    check_id="META002",
                    title="missing_summary_annotation",
                    severity=Severity.WARNING,
                    confidence=Confidence.HIGH,
                    file_path=rule.file_path,
                    group_name=rule.group_name,
                    alert_name=rule.alert_name,
                    expr=rule.expr,
                    issue="Alert is missing a 'summary' annotation.",
                    why_it_matters=(
                        "On-call engineers see the summary in their pager "
                        "notification. Without one they must read the raw "
                        "expression to understand what's happening."
                    ),
                    suggestion="Add a short 'summary' annotation.",
                    autofix_snippet=yaml.dump(
                        {"annotations": {
                            "summary": f"{rule.alert_name} is firing on "
                                       "{{ $labels.instance }}"
                        }}, default_flow_style=False
                    ).strip(),
                )
            ]
        return []


class MissingDescriptionAnnotation(BaseCheck):
    """META003: alert has no ``description`` annotation."""

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        if "description" not in rule.annotations and "description" in policy.required_annotations:
            return [
                Finding(
                    check_id="META003",
                    title="missing_description_annotation",
                    severity=Severity.WARNING,
                    confidence=Confidence.HIGH,
                    file_path=rule.file_path,
                    group_name=rule.group_name,
                    alert_name=rule.alert_name,
                    expr=rule.expr,
                    issue="Alert is missing a 'description' annotation.",
                    why_it_matters=(
                        "The description gives responders context about what "
                        "triggered the alert and what conditions are abnormal."
                    ),
                    suggestion="Add a 'description' annotation with trigger context.",
                    autofix_snippet=yaml.dump(
                        {"annotations": {
                            "description": (
                                f"{rule.alert_name} has been firing for "
                                "more than the configured threshold."
                            )
                        }}, default_flow_style=False
                    ).strip(),
                )
            ]
        return []


class MissingRunbookURL(BaseCheck):
    """META004: alert has no runbook annotation."""

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        if not (set(rule.annotations.keys()) & policy.runbook_keys_set):
            return [
                Finding(
                    check_id="META004",
                    title="missing_runbook_url",
                    severity=Severity.WARNING,
                    confidence=Confidence.HIGH,
                    file_path=rule.file_path,
                    group_name=rule.group_name,
                    alert_name=rule.alert_name,
                    expr=rule.expr,
                    issue="Alert has no runbook annotation.",
                    why_it_matters=(
                        "Without a runbook link, responders have no step-by-step "
                        "remediation guidance. Resolution takes longer and is "
                        "more error-prone under pressure."
                    ),
                    suggestion="Link to a runbook, even a short wiki page.",
                    autofix_snippet=yaml.dump(
                        {"annotations": {
                            "runbook_url": f"https://wiki.example.com/runbooks/{rule.alert_name}"
                        }}, default_flow_style=False
                    ).strip(),
                )
            ]
        return []


class MissingOwnership(BaseCheck):
    """META005: no ownership label or annotation (team / service / owner)."""

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        all_keys = set(rule.labels.keys()) | set(rule.annotations.keys())
        if not all_keys & policy.owner_keys_set:
            preferred = sorted(policy.preferred_owner_keys)[:2]
            return [
                Finding(
                    check_id="META005",
                    title="missing_ownership",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    file_path=rule.file_path,
                    group_name=rule.group_name,
                    alert_name=rule.alert_name,
                    expr=rule.expr,
                    issue="Alert has no ownership context.",
                    why_it_matters=(
                        "Without a team or service label, the alert cannot be "
                        "automatically routed to the right responders."
                    ),
                    suggestion=f"Add a '{preferred[0]}' or '{preferred[1]}' label.",
                    autofix_snippet=yaml.dump(
                        {"labels": {preferred[0]: "your-team-name"}},
                        default_flow_style=False,
                    ).strip(),
                )
            ]
        return []


class GenericAlertName(BaseCheck):
    """META006: alert name is too vague to be actionable."""

    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        if policy.is_generic_name(rule.alert_name):
            return [
                Finding(
                    check_id="META006",
                    title="generic_alert_name",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    file_path=rule.file_path,
                    group_name=rule.group_name,
                    alert_name=rule.alert_name,
                    expr=rule.expr,
                    issue=f"Alert name '{rule.alert_name}' is too generic.",
                    why_it_matters=(
                        "Generic names make it impossible to triage alerts "
                        "from a notification list. Names should encode the "
                        "service, symptom, and scope."
                    ),
                    suggestion=(
                        "Use a descriptive name like "
                        "'PaymentServiceHighLatencyP99'."
                    ),
                )
            ]
        return []
