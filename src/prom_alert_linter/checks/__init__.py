"""Check registry — collects and exposes all implemented checks."""

from prom_alert_linter.checks.base import BaseCheck
from prom_alert_linter.checks.registry import get_all_checks

__all__ = ["BaseCheck", "get_all_checks"]
