"""Tests for the application orchestrator."""

from pathlib import Path

from prom_alert_linter.app import AnalyzerEngine
from prom_alert_linter.models import Severity

GOOD_YAML = """
groups:
  - name: test
    rules:
      - alert: GoodAlert
        expr: up == 0
        for: 5m
        labels:
          severity: warning
          team: platform
        annotations:
          summary: "test"
          description: "test"
          runbook_url: "http"
"""

def test_analyzer_engine_clean(tmp_path: Path):
    f = tmp_path / "good.yaml"
    f.write_text(GOOD_YAML)
    
    engine = AnalyzerEngine()
    result = engine.run([tmp_path])
    
    assert result.summary.files_scanned == 1
    assert result.summary.rules_scanned == 1
    assert not result.parse_errors

def test_analyzer_engine_bad_yaml(tmp_path: Path):
    f = tmp_path / "bad.yaml"
    f.write_text("{[\n::::")
    
    engine = AnalyzerEngine()
    result = engine.run([tmp_path])
    
    assert result.summary.files_scanned == 1
    assert result.summary.rules_scanned == 0
    assert len(result.parse_errors) == 1
