"""Tests for YAML parsing and rule extraction."""

from pathlib import Path

import pytest

from prom_alert_linter.parser import extract_rules, load_yaml, ParseError


GOOD_YAML = """
groups:
  - name: test-group
    rules:
      - alert: TestAlert
        expr: up == 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Test alert"
"""

MIXED_YAML = """
groups:
  - name: mixed
    rules:
      - alert: AlertingRule
        expr: some_metric > 1
        for: 5m
        labels:
          severity: warning
      - record: job:metric:rate5m
        expr: sum(rate(metric[5m])) by (job)
      - alert: AnotherAlert
        expr: other_metric < 0
"""

EMPTY_GROUPS = """
groups: []
"""

NO_GROUPS = """
some_other_key: value
"""


@pytest.fixture
def tmp_yaml(tmp_path: Path):
    def _write(content: str, name: str = "rules.yaml") -> Path:
        p = tmp_path / name
        p.write_text(content)
        return p
    return _write


class TestLoadYaml:
    def test_valid_yaml(self, tmp_yaml):
        path = tmp_yaml(GOOD_YAML)
        data = load_yaml(path)
        assert "groups" in data

    def test_invalid_yaml_raises(self, tmp_yaml):
        path = tmp_yaml("{{invalid yaml::")
        with pytest.raises(ParseError, match="Invalid YAML"):
            load_yaml(path)

    def test_non_mapping_raises(self, tmp_yaml):
        path = tmp_yaml("- just\n- a\n- list\n")
        with pytest.raises(ParseError, match="expected a YAML mapping"):
            load_yaml(path)


class TestExtractRules:
    def test_extracts_alerting_rules(self, tmp_yaml):
        path = tmp_yaml(GOOD_YAML)
        data = load_yaml(path)
        rules = extract_rules(path, data)
        assert len(rules) == 1
        assert rules[0].alert_name == "TestAlert"
        assert rules[0].group_name == "test-group"
        assert rules[0].duration_for == "5m"

    def test_skips_recording_rules(self, tmp_yaml):
        path = tmp_yaml(MIXED_YAML)
        data = load_yaml(path)
        rules = extract_rules(path, data)
        assert len(rules) == 2
        names = {r.alert_name for r in rules}
        assert names == {"AlertingRule", "AnotherAlert"}

    def test_empty_groups_returns_empty(self, tmp_yaml):
        path = tmp_yaml(EMPTY_GROUPS)
        data = load_yaml(path)
        assert extract_rules(path, data) == []

    def test_no_groups_key_returns_empty(self, tmp_yaml):
        path = tmp_yaml(NO_GROUPS)
        data = load_yaml(path)
        assert extract_rules(path, data) == []

    def test_missing_for_is_none(self, tmp_yaml):
        content = "groups:\n  - name: g\n    rules:\n      - alert: X\n        expr: up == 0\n"
        path = tmp_yaml(content)
        data = load_yaml(path)
        rules = extract_rules(path, data)
        assert rules[0].duration_for is None

    def test_file_path_stored(self, tmp_yaml):
        path = tmp_yaml(GOOD_YAML)
        data = load_yaml(path)
        rules = extract_rules(path, data)
        assert rules[0].file_path == str(path)

    def test_defaults_to_empty_dicts(self, tmp_yaml):
        content = "groups:\n  - name: g\n    rules:\n      - alert: X\n        expr: up\n"
        path = tmp_yaml(content)
        data = load_yaml(path)
        rules = extract_rules(path, data)
        assert rules[0].annotations == {}
        assert rules[0].labels == {}
