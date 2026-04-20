"""Configurable policy engine.

Teams have different conventions — some use ``team``, others ``owner``;
some want ``runbook_url``, others accept ``runbook``.  The policy file
lets teams codify their expectations without forking the linter.

The engine loads a built-in default policy, then merges any user-supplied
overrides on top.  This means users only need to specify the fields they
want to change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from prom_alert_linter.utils import parse_duration_seconds


class PolicyError(Exception):
    """Raised when a policy file is invalid."""


# ---------------------------------------------------------------------------
# Default policy — used when no --policy flag is supplied
# ---------------------------------------------------------------------------

_DEFAULTS: dict[str, Any] = {
    "required_labels": ["severity"],
    "required_annotations": ["summary", "description"],
    "preferred_owner_keys": ["team", "service", "owner", "component", "squad"],
    "ephemeral_labels": ["pod", "pod_name", "instance", "container",
                         "container_name", "endpoint", "revision"],
    "minimum_for_duration": "2m",
    "default_for_suggestion": "5m",
    "severity_label_key": "severity",
    "warning_severity_values": ["warning"],
    "critical_severity_values": ["critical", "page"],
    "runbook_annotation_keys": ["runbook_url", "runbook"],
    "generic_alert_name_patterns": [
        r"^Alert$", r"^Problem$", r"^Error$", r"^Warning$", r"^Critical$",
        r"^HighCPU$", r"^HighLatency$", r"^HighMemory$", r"^HighLoad$",
        r"^Issue$", r"^Failure$", r"^Notify$", r"^Notification$",
    ],
    "broad_selector_metrics": ["up"],
    "ignored_checks": [],
    "ignored_alert_names": [],
}


@dataclass
class Policy:
    """Parsed and validated lint policy."""

    required_labels: list[str] = field(default_factory=list)
    required_annotations: list[str] = field(default_factory=list)
    preferred_owner_keys: list[str] = field(default_factory=list)
    ephemeral_labels: list[str] = field(default_factory=list)
    minimum_for_duration: str = "2m"
    default_for_suggestion: str = "5m"
    severity_label_key: str = "severity"
    warning_severity_values: list[str] = field(default_factory=list)
    critical_severity_values: list[str] = field(default_factory=list)
    runbook_annotation_keys: list[str] = field(default_factory=list)
    generic_alert_name_patterns: list[str] = field(default_factory=list)
    broad_selector_metrics: list[str] = field(default_factory=list)
    ignored_checks: list[str] = field(default_factory=list)
    ignored_alert_names: list[str] = field(default_factory=list)

    # ── derived / cached ──────────────────────────────────────────────

    @property
    def minimum_for_seconds(self) -> float:
        s = parse_duration_seconds(self.minimum_for_duration)
        return s if s is not None else 120.0

    @property
    def ephemeral_labels_set(self) -> frozenset[str]:
        return frozenset(self.ephemeral_labels)

    @property
    def owner_keys_set(self) -> frozenset[str]:
        return frozenset(self.preferred_owner_keys)

    @property
    def runbook_keys_set(self) -> frozenset[str]:
        return frozenset(self.runbook_annotation_keys)

    @property
    def ignored_checks_set(self) -> frozenset[str]:
        return frozenset(self.ignored_checks)

    @property
    def ignored_names_set(self) -> frozenset[str]:
        return frozenset(self.ignored_alert_names)

    def is_generic_name(self, name: str) -> bool:
        """Return True if the alert name matches any generic pattern."""
        for pattern in self.generic_alert_name_patterns:
            if re.search(pattern, name, re.IGNORECASE):
                return True
        return False

    def is_warning_severity(self, value: str) -> bool:
        return value.lower() in {v.lower() for v in self.warning_severity_values}

    def is_critical_severity(self, value: str) -> bool:
        return value.lower() in {v.lower() for v in self.critical_severity_values}


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

_KNOWN_KEYS = set(_DEFAULTS.keys())
_LIST_KEYS = {k for k, v in _DEFAULTS.items() if isinstance(v, list)}
_STR_KEYS = {k for k, v in _DEFAULTS.items() if isinstance(v, str)}


def load_policy(path: Path | None = None) -> Policy:
    """Load and merge policy from an optional YAML file.

    If *path* is None, returns the built-in defaults.
    """
    merged = dict(_DEFAULTS)

    if path is not None:
        try:
            with path.open("r", encoding="utf-8") as fh:
                user_data = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise PolicyError(f"Invalid YAML in policy file {path}: {exc}") from exc

        if not isinstance(user_data, dict):
            raise PolicyError(
                f"Policy file {path} must be a YAML mapping, "
                f"got {type(user_data).__name__}"
            )

        _validate_user_policy(user_data, path)
        merged.update(user_data)

    return Policy(**merged)


def _validate_user_policy(data: dict[str, Any], path: Path) -> None:
    """Check for unknown keys and type mismatches."""
    for key in data:
        if key not in _KNOWN_KEYS:
            raise PolicyError(
                f"Unknown policy key '{key}' in {path}. "
                f"Valid keys: {sorted(_KNOWN_KEYS)}"
            )

    for key in _LIST_KEYS:
        if key in data and not isinstance(data[key], list):
            raise PolicyError(
                f"Policy key '{key}' in {path} must be a list, "
                f"got {type(data[key]).__name__}"
            )

    for key in _STR_KEYS:
        if key in data and not isinstance(data[key], str):
            raise PolicyError(
                f"Policy key '{key}' in {path} must be a string, "
                f"got {type(data[key]).__name__}"
            )
