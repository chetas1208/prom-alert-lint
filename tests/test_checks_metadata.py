"""Tests for metadata checks (META001–META006)."""

import pytest

from prom_alert_linter.checks.metadata import (
    GenericAlertName,
    MissingDescriptionAnnotation,
    MissingOwnership,
    MissingRunbookURL,
    MissingSeverityLabel,
    MissingSummaryAnnotation,
)
from prom_alert_linter.models import AlertRule, Confidence, Severity
from prom_alert_linter.policy import load_policy


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


class TestMissingSeverityLabel:
    def test_flags_when_missing(self):
        findings = MissingSeverityLabel().check_rule(_rule(), POLICY)
        assert len(findings) == 1
        assert findings[0].check_id == "META001"
        assert findings[0].severity == Severity.ERROR
        assert findings[0].confidence == Confidence.HIGH
        assert findings[0].autofix_snippet is not None

    def test_passes_when_present(self):
        findings = MissingSeverityLabel().check_rule(
            _rule(labels={"severity": "warning"}), POLICY
        )
        assert findings == []


class TestMissingSummaryAnnotation:
    def test_flags_when_missing(self):
        findings = MissingSummaryAnnotation().check_rule(_rule(), POLICY)
        assert len(findings) == 1
        assert findings[0].check_id == "META002"
        assert findings[0].autofix_snippet is not None

    def test_passes_when_present(self):
        findings = MissingSummaryAnnotation().check_rule(
            _rule(annotations={"summary": "Some summary"}), POLICY
        )
        assert findings == []


class TestMissingDescriptionAnnotation:
    def test_flags_when_missing(self):
        findings = MissingDescriptionAnnotation().check_rule(_rule(), POLICY)
        assert len(findings) == 1
        assert findings[0].check_id == "META003"

    def test_passes_when_present(self):
        findings = MissingDescriptionAnnotation().check_rule(
            _rule(annotations={"description": "Details"}), POLICY
        )
        assert findings == []


class TestMissingRunbookURL:
    def test_flags_when_missing(self):
        findings = MissingRunbookURL().check_rule(_rule(), POLICY)
        assert len(findings) == 1
        assert findings[0].check_id == "META004"
        assert "runbook" in findings[0].autofix_snippet.lower()

    def test_passes_with_runbook_url(self):
        findings = MissingRunbookURL().check_rule(
            _rule(annotations={"runbook_url": "https://example.com"}), POLICY
        )
        assert findings == []

    def test_passes_with_runbook_key(self):
        findings = MissingRunbookURL().check_rule(
            _rule(annotations={"runbook": "https://example.com"}), POLICY
        )
        assert findings == []


class TestMissingOwnership:
    def test_flags_when_missing(self):
        findings = MissingOwnership().check_rule(_rule(), POLICY)
        assert len(findings) == 1
        assert findings[0].check_id == "META005"
        assert findings[0].autofix_snippet is not None

    def test_passes_with_team(self):
        assert MissingOwnership().check_rule(
            _rule(labels={"team": "sre"}), POLICY
        ) == []

    def test_passes_with_service(self):
        assert MissingOwnership().check_rule(
            _rule(annotations={"service": "api"}), POLICY
        ) == []


class TestGenericAlertName:
    @pytest.mark.parametrize("name", ["Alert", "Error", "HighCPU", "Problem"])
    def test_flags_generic(self, name):
        findings = GenericAlertName().check_rule(
            _rule(alert_name=name), POLICY
        )
        assert len(findings) == 1
        assert findings[0].check_id == "META006"

    @pytest.mark.parametrize("name", [
        "ApiServerHighErrorRate",
        "DatabaseConnectionPoolExhausted",
    ])
    def test_passes_descriptive(self, name):
        assert GenericAlertName().check_rule(
            _rule(alert_name=name), POLICY
        ) == []
