"""Tests for stability / noise checks (STAB001–STAB005)."""

import pytest

from prom_alert_linter.checks.stability import (
    CriticalFiresBeforeWarning,
    InstantThresholdWithoutSmoothing,
    IrateInExpr,
    MissingForClause,
    ShortForDuration,
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


class TestMissingForClause:
    def test_flags_when_missing(self):
        findings = MissingForClause().check_rule(_rule(duration_for=None), POLICY)
        assert len(findings) == 1
        assert findings[0].check_id == "STAB001"
        assert findings[0].autofix_snippet == "for: 5m"

    def test_passes_when_present(self):
        assert MissingForClause().check_rule(
            _rule(duration_for="5m"), POLICY
        ) == []


class TestShortForDuration:
    @pytest.mark.parametrize("dur", ["30s", "1m"])
    def test_flags_short(self, dur):
        findings = ShortForDuration().check_rule(
            _rule(duration_for=dur), POLICY
        )
        assert len(findings) == 1
        assert findings[0].check_id == "STAB002"
        assert findings[0].autofix_snippet is not None

    @pytest.mark.parametrize("dur", ["5m", "10m", "1h"])
    def test_passes_adequate(self, dur):
        assert ShortForDuration().check_rule(
            _rule(duration_for=dur), POLICY
        ) == []

    def test_passes_when_none(self):
        assert ShortForDuration().check_rule(
            _rule(duration_for=None), POLICY
        ) == []

    def test_respects_policy_minimum(self):
        """With default policy minimum of 2m, '2m' should pass."""
        findings = ShortForDuration().check_rule(
            _rule(duration_for="2m"), POLICY
        )
        assert findings == []


class TestIrateInExpr:
    def test_flags_irate(self):
        findings = IrateInExpr().check_rule(
            _rule(expr="irate(node_cpu_seconds_total[1m]) > 0.9"), POLICY
        )
        assert len(findings) == 1
        assert findings[0].check_id == "STAB003"
        assert "rate(" in findings[0].autofix_snippet

    def test_passes_rate(self):
        assert IrateInExpr().check_rule(
            _rule(expr="rate(node_cpu_seconds_total[5m]) > 0.9"), POLICY
        ) == []


class TestInstantThreshold:
    def test_flags_bare_threshold(self):
        findings = InstantThresholdWithoutSmoothing().check_rule(
            _rule(expr="node_memory_avail_bytes < 1073741824"), POLICY
        )
        assert len(findings) == 1
        assert findings[0].check_id == "STAB004"

    def test_passes_with_function(self):
        assert InstantThresholdWithoutSmoothing().check_rule(
            _rule(expr="avg_over_time(cpu_usage[5m]) > 0.9"), POLICY
        ) == []


class TestCriticalFiresBeforeWarning:
    def test_flags_critical_shorter(self):
        warn = _rule(
            alert_name="HighMemoryWarning", duration_for="10m",
            labels={"severity": "warning"},
        )
        crit = _rule(
            alert_name="HighMemoryCritical", duration_for="2m",
            labels={"severity": "critical"},
        )
        findings = CriticalFiresBeforeWarning().check_all([warn, crit], POLICY)
        assert len(findings) == 1
        assert findings[0].check_id == "STAB005"
        assert findings[0].related_alerts == ["HighMemoryWarning"]

    def test_passes_critical_longer(self):
        warn = _rule(
            alert_name="HighMemoryWarning", duration_for="5m",
            labels={"severity": "warning"},
        )
        crit = _rule(
            alert_name="HighMemoryCritical", duration_for="10m",
            labels={"severity": "critical"},
        )
        assert CriticalFiresBeforeWarning().check_all(
            [warn, crit], POLICY
        ) == []

    def test_passes_unrelated(self):
        a = _rule(
            alert_name="DiskWarning", duration_for="10m",
            labels={"severity": "warning"},
        )
        b = _rule(
            alert_name="MemoryCritical", duration_for="2m",
            labels={"severity": "critical"},
        )
        assert CriticalFiresBeforeWarning().check_all([a, b], POLICY) == []
