"""Tests for autofix suggestion presence and quality."""

import pytest

from prom_alert_linter.checks.metadata import (
    MissingRunbookURL,
    MissingSeverityLabel,
    MissingSummaryAnnotation,
    MissingDescriptionAnnotation,
    MissingOwnership,
)
from prom_alert_linter.checks.stability import (
    IrateInExpr,
    MissingForClause,
    ShortForDuration,
)
from prom_alert_linter.checks.selectors import (
    BroadUpSelector,
    OverlyNarrowSelector,
)
from prom_alert_linter.checks.relationships import SuspiciousThresholdOrdering
from prom_alert_linter.models import AlertRule
from prom_alert_linter.policy import load_policy
from prom_alert_linter.suggestions import (
    suggest_for_clause,
    suggest_severity_label,
    suggest_runbook_annotation,
    suggest_rate_replacement,
    suggest_scoped_selector,
)

POLICY = load_policy(None)


def _rule(**overrides) -> AlertRule:
    defaults = dict(
        file_path="test.yaml",
        group_name="test-group",
        alert_name="TestAlert",
        expr="up == 0",
        duration_for="5m",
        labels={},
        annotations={},
        raw={},
    )
    defaults.update(overrides)
    return AlertRule(**defaults)


class TestAutofixSnippetsInFindings:
    """Verify that checks that should produce autofix snippets actually do."""

    def test_missing_severity_has_autofix(self):
        findings = MissingSeverityLabel().check_rule(_rule(), POLICY)
        assert findings[0].autofix_snippet
        assert "severity" in findings[0].autofix_snippet

    def test_missing_for_has_autofix(self):
        findings = MissingForClause().check_rule(
            _rule(duration_for=None), POLICY
        )
        assert findings[0].autofix_snippet == "for: 5m"

    def test_short_for_has_autofix(self):
        findings = ShortForDuration().check_rule(
            _rule(duration_for="30s"), POLICY
        )
        assert findings[0].autofix_snippet == "for: 5m"

    def test_irate_has_autofix(self):
        findings = IrateInExpr().check_rule(
            _rule(expr="irate(cpu[1m]) > 0.9"), POLICY
        )
        assert "rate(" in findings[0].autofix_snippet
        assert "irate" not in findings[0].autofix_snippet

    def test_missing_runbook_has_autofix(self):
        findings = MissingRunbookURL().check_rule(_rule(), POLICY)
        assert "runbook" in findings[0].autofix_snippet.lower()

    def test_missing_summary_has_autofix(self):
        findings = MissingSummaryAnnotation().check_rule(_rule(), POLICY)
        assert "summary" in findings[0].autofix_snippet

    def test_missing_description_has_autofix(self):
        findings = MissingDescriptionAnnotation().check_rule(_rule(), POLICY)
        assert "description" in findings[0].autofix_snippet

    def test_missing_ownership_has_autofix(self):
        findings = MissingOwnership().check_rule(_rule(), POLICY)
        assert findings[0].autofix_snippet is not None

    def test_broad_up_has_autofix(self):
        findings = BroadUpSelector().check_rule(
            _rule(expr="up == 0"), POLICY
        )
        assert findings[0].autofix_snippet
        assert "job" in findings[0].autofix_snippet

    def test_narrow_selector_has_autofix(self):
        findings = OverlyNarrowSelector().check_rule(
            _rule(expr='kube_pod{pod="api-7b4f8c6d9-xk2qw"} > 0'), POLICY
        )
        assert findings[0].autofix_snippet
        assert "=~" in findings[0].autofix_snippet

    def test_threshold_ordering_has_autofix(self):
        rules = [
            _rule(alert_name="CPUWarning", expr="cpu > 90",
                  labels={"severity": "warning"}),
            _rule(alert_name="CPUCritical", expr="cpu > 80",
                  labels={"severity": "critical"}),
        ]
        findings = SuspiciousThresholdOrdering().check_all(rules, POLICY)
        assert findings[0].autofix_snippet
        assert "swap" in findings[0].autofix_snippet.lower()


class TestSuggestionHelpers:
    def test_suggest_for_clause(self):
        result = suggest_for_clause(POLICY)
        assert result == "for: 5m"

    def test_suggest_severity_label(self):
        result = suggest_severity_label(POLICY)
        assert "severity" in result

    def test_suggest_runbook(self):
        rule = _rule(alert_name="MyAlert")
        result = suggest_runbook_annotation(rule, POLICY)
        assert "MyAlert" in result
        assert "runbook" in result.lower()

    def test_suggest_rate_replacement(self):
        result = suggest_rate_replacement("irate(node_cpu_seconds_total[5m]) > 0.9")
        assert "rate(node_cpu_seconds_total[5m])" in result
        assert "irate" not in result

    def test_suggest_scoped_selector(self):
        result = suggest_scoped_selector("up")
        assert "job" in result
        assert "up" in result
