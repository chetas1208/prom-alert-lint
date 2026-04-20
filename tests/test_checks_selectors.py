"""Tests for selector quality checks (SEL001–SEL004)."""

import pytest

from prom_alert_linter.checks.selectors import (
    BareMetricSelector,
    BroadUpSelector,
    EphemeralLabelDependency,
    OverlyNarrowSelector,
)
from prom_alert_linter.models import AlertRule
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


class TestBareMetricSelector:
    def test_flags_unfiltered(self):
        findings = BareMetricSelector().check_rule(
            _rule(expr="node_load1 > 10"), POLICY
        )
        assert len(findings) == 1
        assert findings[0].check_id == "SEL001"

    def test_passes_with_filter(self):
        assert BareMetricSelector().check_rule(
            _rule(expr='node_load1{job="node"} > 10'), POLICY
        ) == []


class TestBroadUpSelector:
    def test_flags_bare_up_zero(self):
        findings = BroadUpSelector().check_rule(
            _rule(expr="up == 0"), POLICY
        )
        assert len(findings) == 1
        assert findings[0].check_id == "SEL002"
        assert findings[0].autofix_snippet is not None

    def test_passes_scoped(self):
        assert BroadUpSelector().check_rule(
            _rule(expr='up{job="apiserver"} == 0'), POLICY
        ) == []


class TestEphemeralLabelDependency:
    def test_flags_pod_label(self):
        findings = EphemeralLabelDependency().check_rule(
            _rule(expr='metric{pod="my-pod"} > 0'), POLICY
        )
        assert len(findings) == 1
        assert findings[0].check_id == "SEL003"

    def test_flags_instance_label(self):
        findings = EphemeralLabelDependency().check_rule(
            _rule(expr='up{instance="10.0.0.1:9090"} == 0'), POLICY
        )
        assert len(findings) == 1

    def test_passes_stable_labels(self):
        assert EphemeralLabelDependency().check_rule(
            _rule(expr='up{job="api", namespace="prod"} == 0'), POLICY
        ) == []

    def test_ignores_regex(self):
        assert EphemeralLabelDependency().check_rule(
            _rule(expr='metric{pod=~"api-.*"} > 0'), POLICY
        ) == []


class TestOverlyNarrowSelector:
    def test_flags_generated_pod(self):
        findings = OverlyNarrowSelector().check_rule(
            _rule(expr='kube_pod_status{pod="api-7b4f8c6d9-xk2qw"} > 0'), POLICY
        )
        assert len(findings) == 1
        assert findings[0].check_id == "SEL004"
        assert findings[0].autofix_snippet is not None

    def test_passes_stable_name(self):
        assert OverlyNarrowSelector().check_rule(
            _rule(expr='kube_pod_status{pod="redis-master"} > 0'), POLICY
        ) == []

    def test_passes_deployment(self):
        assert OverlyNarrowSelector().check_rule(
            _rule(expr='kube_deployment{deployment="web-api"} < 2'), POLICY
        ) == []
