"""Tests for JSON output shape and CI-friendly structure."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from prom_alert_linter.cli import app

runner = CliRunner()

_RULES = """
groups:
  - name: test
    rules:
      - alert: TestAlert
        expr: up == 0
"""


@pytest.fixture
def rule_file(tmp_path: Path) -> Path:
    p = tmp_path / "test.yaml"
    p.write_text(_RULES)
    return p


class TestJSONStructure:
    def test_top_level_keys(self, rule_file):
        result = runner.invoke(app, [str(rule_file), "--format", "json"])
        data = json.loads(result.output)
        assert "summary" in data
        assert "findings" in data

    def test_summary_fields(self, rule_file):
        result = runner.invoke(app, [str(rule_file), "--format", "json"])
        summary = json.loads(result.output)["summary"]
        assert "files_scanned" in summary
        assert "rules_scanned" in summary
        assert "findings_total" in summary
        assert "findings_by_severity" in summary
        assert isinstance(summary["findings_by_severity"], dict)

    def test_finding_fields(self, rule_file):
        result = runner.invoke(app, [str(rule_file), "--format", "json"])
        data = json.loads(result.output)
        assert len(data["findings"]) > 0
        f = data["findings"][0]
        required = {
            "check_id", "title", "severity", "confidence",
            "file_path", "group_name", "alert_name", "expr",
            "issue", "why_it_matters", "suggestion",
        }
        assert required.issubset(set(f.keys()))

    def test_severity_values(self, rule_file):
        result = runner.invoke(app, [str(rule_file), "--format", "json"])
        data = json.loads(result.output)
        valid_severities = {"info", "warning", "error"}
        for f in data["findings"]:
            assert f["severity"] in valid_severities

    def test_confidence_values(self, rule_file):
        result = runner.invoke(app, [str(rule_file), "--format", "json"])
        data = json.loads(result.output)
        valid = {"high", "medium", "low"}
        for f in data["findings"]:
            assert f["confidence"] in valid

    def test_autofix_present_when_applicable(self, rule_file):
        result = runner.invoke(app, [str(rule_file), "--format", "json"])
        data = json.loads(result.output)
        # At least one finding should have autofix (e.g. STAB001 for missing for)
        autofixes = [f for f in data["findings"] if "autofix_snippet" in f]
        assert len(autofixes) > 0

    def test_cross_alert_has_related(self, tmp_path):
        rules = tmp_path / "dup.yaml"
        rules.write_text("""
groups:
  - name: g
    rules:
      - alert: Dup
        expr: up == 0
        labels:
          severity: warning
      - alert: Dup
        expr: up == 0
        labels:
          severity: critical
""")
        result = runner.invoke(app, [str(rules), "--format", "json"])
        data = json.loads(result.output)
        rel_findings = [
            f for f in data["findings"]
            if "related_alerts" in f and f["related_alerts"]
        ]
        assert len(rel_findings) > 0
