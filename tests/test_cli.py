"""Tests for the CLI interface, exit codes, and flag behavior."""

from pathlib import Path
import json

import pytest
from typer.testing import CliRunner

from prom_alert_linter.cli import app


runner = CliRunner()

_CLEAN_RULES = """
groups:
  - name: clean
    rules:
      - alert: WellFormedAlert
        expr: rate(http_errors_total{job="api"}[5m]) > 0.05
        for: 10m
        labels:
          severity: warning
          team: platform
          service: api
        annotations:
          summary: "HTTP error rate above 5%"
          description: "Error rate is elevated."
          runbook_url: "https://wiki.example.com/runbook"
"""

_BAD_RULES = """
groups:
  - name: bad
    rules:
      - alert: Alert
        expr: up == 0
"""


@pytest.fixture
def clean_file(tmp_path: Path) -> Path:
    p = tmp_path / "clean.yaml"
    p.write_text(_CLEAN_RULES)
    return p


@pytest.fixture
def bad_file(tmp_path: Path) -> Path:
    p = tmp_path / "bad.yaml"
    p.write_text(_BAD_RULES)
    return p


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text("ignored_checks:\n  - META006\n")
    return p


class TestExitCodes:
    def test_clean_exits_zero(self, clean_file):
        result = runner.invoke(app, [str(clean_file)])
        assert result.exit_code == 0

    def test_bad_exits_nonzero(self, bad_file):
        result = runner.invoke(app, [str(bad_file)])
        assert result.exit_code == 1

    def test_fail_on_error(self, bad_file):
        result = runner.invoke(app, [str(bad_file), "--fail-on", "error"])
        assert result.exit_code == 1  # META001 is severity=error

    def test_no_files_exits_two(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        result = runner.invoke(app, [str(empty)])
        assert result.exit_code == 2

    def test_invalid_policy_exits_two(self, bad_file, tmp_path):
        policy = tmp_path / "bad_policy.yaml"
        policy.write_text("unknown_key: true\n")
        result = runner.invoke(
            app, [str(bad_file), "--policy", str(policy)]
        )
        assert result.exit_code == 2


class TestOutputFormats:
    def test_text_contains_check_id(self, bad_file):
        result = runner.invoke(app, [str(bad_file), "--no-color"])
        assert "META001" in result.output

    def test_json_is_valid(self, bad_file):
        result = runner.invoke(app, [str(bad_file), "--format", "json"])
        data = json.loads(result.output)
        assert "summary" in data
        assert "findings" in data

    def test_json_has_required_fields(self, bad_file):
        result = runner.invoke(app, [str(bad_file), "--format", "json"])
        data = json.loads(result.output)
        for f in data["findings"]:
            assert "check_id" in f
            assert "severity" in f
            assert "confidence" in f
            assert "issue" in f
            assert "why_it_matters" in f
            assert "suggestion" in f


class TestPolicyIntegration:
    def test_policy_ignores_checks(self, bad_file, policy_file):
        result = runner.invoke(
            app, [str(bad_file), "--format", "json",
                  "--policy", str(policy_file)]
        )
        data = json.loads(result.output)
        check_ids = {f["check_id"] for f in data["findings"]}
        assert "META006" not in check_ids

    def test_policy_ignores_alert_names(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text(_BAD_RULES)
        policy = tmp_path / "policy.yaml"
        policy.write_text("ignored_alert_names:\n  - Alert\n")
        result = runner.invoke(
            app, [str(rules), "--format", "json",
                  "--policy", str(policy)]
        )
        data = json.loads(result.output)
        assert data["summary"]["findings_total"] == 0


class TestFiltering:
    def test_min_severity_filters(self, bad_file):
        all_result = runner.invoke(
            app, [str(bad_file), "--format", "json", "--min-severity", "info"]
        )
        warn_result = runner.invoke(
            app, [str(bad_file), "--format", "json", "--min-severity", "warning"]
        )
        all_data = json.loads(all_result.output)
        warn_data = json.loads(warn_result.output)
        assert len(all_data["findings"]) >= len(warn_data["findings"])


class TestDirectoryScanning:
    def test_scans_directory(self, tmp_path):
        (tmp_path / "a.yaml").write_text(_CLEAN_RULES)
        (tmp_path / "b.yaml").write_text(_BAD_RULES)
        result = runner.invoke(app, [str(tmp_path), "--format", "json"])
        data = json.loads(result.output)
        assert data["summary"]["files_scanned"] == 2

    def test_recursive(self, tmp_path):
        sub = tmp_path / "sub" / "deep"
        sub.mkdir(parents=True)
        (sub / "r.yaml").write_text(_BAD_RULES)
        result = runner.invoke(
            app, [str(tmp_path / "sub"), "-r", "--format", "json"]
        )
        data = json.loads(result.output)
        assert data["summary"]["files_scanned"] == 1
