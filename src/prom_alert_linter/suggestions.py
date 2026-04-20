"""Autofix suggestion helpers.

This module centralises autofix snippet generation so it can be
extended independently of the check logic.  Today, autofix snippets
are advisory strings embedded in findings.  The architecture is
designed so a future ``--fix`` mode could use these same functions
to rewrite files.
"""

from __future__ import annotations

import yaml

from prom_alert_linter.models import AlertRule
from prom_alert_linter.policy import Policy


def suggest_for_clause(policy: Policy) -> str:
    """Return a suggested ``for`` clause based on policy defaults."""
    return f"for: {policy.default_for_suggestion}"


def suggest_severity_label(policy: Policy) -> str:
    """Return a suggested severity label block."""
    key = policy.severity_label_key
    return yaml.dump(
        {"labels": {key: "warning"}}, default_flow_style=False
    ).strip()


def suggest_runbook_annotation(rule: AlertRule, policy: Policy) -> str:
    """Return a suggested runbook annotation block."""
    key = policy.runbook_annotation_keys[0] if policy.runbook_annotation_keys else "runbook_url"
    return yaml.dump(
        {"annotations": {
            key: f"https://wiki.example.com/runbooks/{rule.alert_name}"
        }}, default_flow_style=False
    ).strip()


def suggest_summary_annotation(rule: AlertRule) -> str:
    """Return a suggested summary annotation block."""
    return yaml.dump(
        {"annotations": {
            "summary": f"{rule.alert_name} is firing on {{{{ $labels.instance }}}}"
        }}, default_flow_style=False
    ).strip()


def suggest_description_annotation(rule: AlertRule) -> str:
    """Return a suggested description annotation block."""
    return yaml.dump(
        {"annotations": {
            "description": (
                f"{rule.alert_name} has been firing for more than "
                "the configured threshold."
            )
        }}, default_flow_style=False
    ).strip()


def suggest_ownership_label(policy: Policy) -> str:
    """Return a suggested ownership label block."""
    key = policy.preferred_owner_keys[0] if policy.preferred_owner_keys else "team"
    return yaml.dump(
        {"labels": {key: "your-team-name"}}, default_flow_style=False
    ).strip()


def suggest_scoped_selector(metric: str) -> str:
    """Return a suggested scoped selector for a broad metric."""
    return f'expr: {metric}{{job="your-job"}} == 0'


def suggest_rate_replacement(expr: str) -> str:
    """Return the expression with irate() replaced by rate()."""
    return f"expr: {expr.replace('irate(', 'rate(').strip()}"

