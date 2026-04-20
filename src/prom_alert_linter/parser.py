"""YAML parser for Prometheus rule files.

Prometheus rule files follow the structure:

    groups:
      - name: example
        rules:
          - alert: HighErrorRate
            expr: ...
            for: 5m
            labels: ...
            annotations: ...

Recording rules (``record`` instead of ``alert``) are skipped — this
tool focuses on alerting rules only.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from prom_alert_linter.models import AlertRule, ParseErrorDetails, ParseResult

logger = logging.getLogger(__name__)


class ParseError(Exception):
    """Raised when a YAML file cannot be parsed or has unexpected structure."""


def load_yaml(path: Path) -> dict[str, Any]:
    """Read and parse a single YAML file."""
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ParseError(f"Invalid YAML in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ParseError(
            f"{path}: expected a YAML mapping at top level, "
            f"got {type(data).__name__}"
        )
    return data


def extract_rules(path: Path, data: dict[str, Any]) -> list[AlertRule]:
    """Extract AlertRule objects from a parsed Prometheus rule file.

    Skips recording rules (those with a ``record`` key).
    """
    groups = data.get("groups")
    if not groups:
        logger.debug("%s: no 'groups' key found — skipping", path)
        return []

    rules: list[AlertRule] = []

    for group in groups:
        if not isinstance(group, dict):
            logger.warning("%s: expected group to be a mapping, skipping", path)
            continue

        group_name = group.get("name", "<unnamed>")

        for rule in group.get("rules", []):
            if not isinstance(rule, dict):
                continue
            if "record" in rule:
                continue

            alert_name = rule.get("alert")
            if not alert_name:
                continue

            rules.append(
                AlertRule(
                    file_path=str(path),
                    group_name=group_name,
                    alert_name=str(alert_name),
                    expr=str(rule.get("expr", "")),
                    duration_for=rule.get("for"),
                    labels=rule.get("labels") or {},
                    annotations=rule.get("annotations") or {},
                    raw=rule,
                )
            )

    return rules


def parse_files(paths: list[Path]) -> ParseResult:
    """Parse multiple YAML files and return a comprehensive ParseResult."""
    all_rules: list[AlertRule] = []
    errors: list[ParseErrorDetails] = []
    files_scanned = 0

    for path in paths:
        try:
            data = load_yaml(path)
            files_scanned += 1
            all_rules.extend(extract_rules(path, data))
        except ParseError as exc:
            logger.error("%s", exc)
            errors.append(
                ParseErrorDetails(file_path=str(path), error_message=str(exc))
            )
            # Count files even if they fail to parse completely structure-wise
            files_scanned += 1 

    return ParseResult(
        alert_rules=all_rules,
        parse_errors=errors,
        scanned_files=files_scanned
    )
