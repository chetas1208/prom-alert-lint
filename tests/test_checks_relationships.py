"""Tests for relationship / cross-alert checks (REL001–REL006)."""

import pytest

from prom_alert_linter.checks.relationships import (
    ConflictingDefinitions,
    DuplicateAlertNames,
    IdenticalExpressions,
    LikelyDuplicateAlerts,
    OverlappingAlerts,
    SuspiciousThresholdOrdering,
)
from prom_alert_linter.models import AlertRule, Severity
from prom_alert_linter.policy import load_policy


POLICY = load_policy(None)


def _rule(**overrides) -> AlertRule:
    defaults = dict(
        file_path="test.yaml",
        group_name="test-group",
        alert_name="TestAlert",
        expr="up == 0",
        duration_for="5m",
        labels={"severity": "warning"},
        annotations={},
        raw={},
    )
    defaults.update(overrides)
    return AlertRule(**defaults)


class TestDuplicateAlertNames:
    def test_flags_duplicates(self):
        rules = [
            _rule(alert_name="HighCPU", file_path="a.yaml"),
            _rule(alert_name="HighCPU", file_path="b.yaml"),
        ]
        findings = DuplicateAlertNames().check_all(rules, POLICY)
        assert len(findings) == 1
        assert findings[0].check_id == "REL001"
        assert findings[0].related_alerts

    def test_passes_unique(self):
        rules = [_rule(alert_name="A"), _rule(alert_name="B")]
        assert DuplicateAlertNames().check_all(rules, POLICY) == []

    def test_three_duplicates(self):
        rules = [
            _rule(alert_name="X", file_path="a.yaml"),
            _rule(alert_name="X", file_path="b.yaml"),
            _rule(alert_name="X", file_path="c.yaml"),
        ]
        findings = DuplicateAlertNames().check_all(rules, POLICY)
        assert len(findings) == 2

    def test_detects_conflicting_metadata(self):
        rules = [
            _rule(alert_name="X", labels={"severity": "warning"}),
            _rule(alert_name="X", labels={"severity": "critical"}),
        ]
        findings = DuplicateAlertNames().check_all(rules, POLICY)
        assert "Conflicts detected" in findings[0].issue


class TestIdenticalExpressions:
    def test_flags_identical(self):
        rules = [
            _rule(alert_name="A", expr="up == 0"),
            _rule(alert_name="B", expr="up == 0"),
        ]
        findings = IdenticalExpressions().check_all(rules, POLICY)
        assert len(findings) == 1
        assert findings[0].check_id == "REL002"
        assert findings[0].related_alerts

    def test_normalises_whitespace(self):
        rules = [
            _rule(alert_name="A", expr="up  ==   0"),
            _rule(alert_name="B", expr="up == 0"),
        ]
        assert len(IdenticalExpressions().check_all(rules, POLICY)) == 1

    def test_passes_different(self):
        rules = [
            _rule(alert_name="A", expr="up == 0"),
            _rule(alert_name="B", expr="down == 1"),
        ]
        assert IdenticalExpressions().check_all(rules, POLICY) == []


class TestLikelyDuplicateAlerts:
    def test_flags_same_expr_different_metadata(self):
        rules = [
            _rule(alert_name="A", expr="up == 0",
                  labels={"severity": "warning", "team": "alpha"}),
            _rule(alert_name="B", expr="up == 0",
                  labels={"severity": "warning", "team": "beta"}),
        ]
        findings = LikelyDuplicateAlerts().check_all(rules, POLICY)
        assert len(findings) == 1
        assert findings[0].check_id == "REL003"

    def test_passes_same_name(self):
        rules = [
            _rule(alert_name="X", expr="up == 0"),
            _rule(alert_name="X", expr="up == 0"),
        ]
        assert LikelyDuplicateAlerts().check_all(rules, POLICY) == []


class TestSuspiciousThresholdOrdering:
    def test_flags_inverted_gt(self):
        rules = [
            _rule(alert_name="CPUWarning", expr="cpu > 90",
                  labels={"severity": "warning"}),
            _rule(alert_name="CPUCritical", expr="cpu > 80",
                  labels={"severity": "critical"}),
        ]
        findings = SuspiciousThresholdOrdering().check_all(rules, POLICY)
        assert len(findings) == 1
        assert findings[0].check_id == "REL004"
        assert findings[0].severity == Severity.ERROR
        assert findings[0].autofix_snippet is not None

    def test_passes_correct_ordering(self):
        rules = [
            _rule(alert_name="CPUWarning", expr="cpu > 80",
                  labels={"severity": "warning"}),
            _rule(alert_name="CPUCritical", expr="cpu > 95",
                  labels={"severity": "critical"}),
        ]
        assert SuspiciousThresholdOrdering().check_all(rules, POLICY) == []

    def test_flags_inverted_lt(self):
        rules = [
            _rule(alert_name="DiskWarning", expr="disk < 20",
                  labels={"severity": "warning"}),
            _rule(alert_name="DiskCritical", expr="disk < 30",
                  labels={"severity": "critical"}),
        ]
        assert len(SuspiciousThresholdOrdering().check_all(rules, POLICY)) == 1


class TestOverlappingAlerts:
    def test_flags_close_thresholds(self):
        rules = [
            _rule(alert_name="LoadA", expr="node_load1 > 10",
                  labels={"severity": "warning"}),
            _rule(alert_name="LoadB", expr="node_load1 > 11",
                  labels={"severity": "warning"}),
        ]
        findings = OverlappingAlerts().check_all(rules, POLICY)
        assert len(findings) == 1
        assert findings[0].check_id == "REL005"

    def test_passes_warning_critical_pair(self):
        rules = [
            _rule(alert_name="LoadWarn", expr="node_load1 > 10",
                  labels={"severity": "warning"}),
            _rule(alert_name="LoadCrit", expr="node_load1 > 20",
                  labels={"severity": "critical"}),
        ]
        assert OverlappingAlerts().check_all(rules, POLICY) == []


class TestConflictingDefinitions:
    def test_flags_conflicting_severity(self):
        rules = [
            _rule(alert_name="X", labels={"severity": "warning"},
                  annotations={"runbook_url": "https://a.com"}),
            _rule(alert_name="X", labels={"severity": "critical"},
                  annotations={"runbook_url": "https://a.com"}),
        ]
        findings = ConflictingDefinitions().check_all(rules, POLICY)
        assert len(findings) == 1
        assert findings[0].check_id == "REL006"
        assert "severity" in findings[0].issue.lower()

    def test_flags_conflicting_runbooks(self):
        rules = [
            _rule(alert_name="X", labels={"severity": "warning"},
                  annotations={"runbook_url": "https://a.com"}),
            _rule(alert_name="X", labels={"severity": "warning"},
                  annotations={"runbook_url": "https://b.com"}),
        ]
        findings = ConflictingDefinitions().check_all(rules, POLICY)
        assert len(findings) == 1
        assert "runbook" in findings[0].issue.lower()

    def test_passes_consistent(self):
        rules = [
            _rule(alert_name="X", labels={"severity": "warning"},
                  annotations={"runbook_url": "https://a.com"}),
            _rule(alert_name="X", labels={"severity": "warning"},
                  annotations={"runbook_url": "https://a.com"}),
        ]
        assert ConflictingDefinitions().check_all(rules, POLICY) == []

    def test_passes_unique_names(self):
        rules = [_rule(alert_name="A"), _rule(alert_name="B")]
        assert ConflictingDefinitions().check_all(rules, POLICY) == []
