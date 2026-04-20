"""Tests for policy loading, merging, and validation."""

from pathlib import Path

import pytest

from prom_alert_linter.policy import Policy, PolicyError, load_policy


@pytest.fixture
def tmp_policy(tmp_path: Path):
    def _write(content: str) -> Path:
        p = tmp_path / "policy.yaml"
        p.write_text(content)
        return p
    return _write


class TestLoadDefaults:
    def test_loads_without_file(self):
        policy = load_policy(None)
        assert isinstance(policy, Policy)
        assert "severity" in policy.required_labels
        assert "summary" in policy.required_annotations

    def test_default_minimum_for_duration(self):
        policy = load_policy(None)
        assert policy.minimum_for_seconds == 120.0

    def test_default_generic_patterns(self):
        policy = load_policy(None)
        assert policy.is_generic_name("Alert")
        assert policy.is_generic_name("HighCPU")
        assert not policy.is_generic_name("ApiServerHighErrorRate")


class TestUserOverrides:
    def test_overrides_minimum_for(self, tmp_policy):
        path = tmp_policy('minimum_for_duration: "5m"\n')
        policy = load_policy(path)
        assert policy.minimum_for_seconds == 300.0

    def test_overrides_required_labels(self, tmp_policy):
        path = tmp_policy("required_labels:\n  - severity\n  - priority\n")
        policy = load_policy(path)
        assert policy.required_labels == ["severity", "priority"]

    def test_overrides_ephemeral_labels(self, tmp_policy):
        path = tmp_policy("ephemeral_labels:\n  - pod\n  - custom_label\n")
        policy = load_policy(path)
        assert "custom_label" in policy.ephemeral_labels_set

    def test_overrides_ignored_checks(self, tmp_policy):
        path = tmp_policy("ignored_checks:\n  - META001\n  - STAB002\n")
        policy = load_policy(path)
        assert "META001" in policy.ignored_checks_set

    def test_overrides_ignored_alert_names(self, tmp_policy):
        path = tmp_policy("ignored_alert_names:\n  - Watchdog\n")
        policy = load_policy(path)
        assert "Watchdog" in policy.ignored_names_set

    def test_default_for_suggestion(self, tmp_policy):
        path = tmp_policy('default_for_suggestion: "10m"\n')
        policy = load_policy(path)
        assert policy.default_for_suggestion == "10m"


class TestSeverityMethods:
    def test_is_warning_severity(self):
        policy = load_policy(None)
        assert policy.is_warning_severity("warning")
        assert not policy.is_warning_severity("critical")

    def test_is_critical_severity(self):
        policy = load_policy(None)
        assert policy.is_critical_severity("critical")
        assert policy.is_critical_severity("page")
        assert not policy.is_critical_severity("warning")


class TestValidation:
    def test_unknown_key_raises(self, tmp_policy):
        path = tmp_policy("unknown_key: true\n")
        with pytest.raises(PolicyError, match="Unknown policy key"):
            load_policy(path)

    def test_wrong_type_list_raises(self, tmp_policy):
        path = tmp_policy("required_labels: not-a-list\n")
        with pytest.raises(PolicyError, match="must be a list"):
            load_policy(path)

    def test_wrong_type_string_raises(self, tmp_policy):
        path = tmp_policy("minimum_for_duration:\n  - a\n  - b\n")
        with pytest.raises(PolicyError, match="must be a string"):
            load_policy(path)

    def test_invalid_yaml_raises(self, tmp_policy):
        path = tmp_policy("{{bad yaml::")
        with pytest.raises(PolicyError, match="Invalid YAML"):
            load_policy(path)

    def test_non_mapping_raises(self, tmp_policy):
        path = tmp_policy("- just\n- a\n- list\n")
        with pytest.raises(PolicyError, match="must be a YAML mapping"):
            load_policy(path)
