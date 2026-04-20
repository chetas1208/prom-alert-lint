"""Lightweight helpers — duration parsing and PromQL string heuristics.

We avoid pulling in a PromQL parser; instead we use practical heuristics
that work correctly for the vast majority of real-world Prometheus rules.
"""

from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Duration helpers
# ---------------------------------------------------------------------------

_DURATION_RE = re.compile(
    r"^(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$"
)


def parse_duration_seconds(raw: str | None) -> float | None:
    """Parse a Prometheus-style duration string into seconds.

    Supports combinations like ``1h30m``, ``5m``, ``30s``, ``1d``.
    Returns *None* when the input is None or cannot be parsed.
    """
    if not raw:
        return None

    raw = raw.strip()
    m = _DURATION_RE.match(raw)
    if not m:
        return None

    days = int(m.group(1) or 0)
    hours = int(m.group(2) or 0)
    minutes = int(m.group(3) or 0)
    seconds = int(m.group(4) or 0)
    total = days * 86400 + hours * 3600 + minutes * 60 + seconds
    return float(total) if total > 0 or raw == "0s" else None


def format_duration(seconds: float) -> str:
    """Format a number of seconds into a short Prometheus-style duration."""
    if seconds >= 86400 and seconds % 86400 == 0:
        return f"{int(seconds // 86400)}d"
    if seconds >= 3600 and seconds % 3600 == 0:
        return f"{int(seconds // 3600)}h"
    if seconds >= 60 and seconds % 60 == 0:
        return f"{int(seconds // 60)}m"
    return f"{int(seconds)}s"


# ---------------------------------------------------------------------------
# PromQL string heuristics
# ---------------------------------------------------------------------------

def extract_label_matchers(expr: str) -> list[tuple[str, str, str]]:
    """Extract ``(label, operator, value)`` tuples from a PromQL expression.

    This is a *heuristic* regex parser — it handles the simple selector
    patterns found in 95%+ of real alerting rules.
    """
    pattern = re.compile(r'(\w+)\s*(=~|!~|!=|=)\s*"([^"]*)"')
    return pattern.findall(expr)


def has_label_filters(expr: str) -> bool:
    """Return True if the expression contains at least one label matcher."""
    return bool(extract_label_matchers(expr))


def extract_metric_names(expr: str) -> list[str]:
    """Best-effort extraction of metric names from a PromQL expression."""
    candidates = re.findall(r"\b([a-zA-Z_:][a-zA-Z0-9_:]*)\s*[{(]", expr)
    bare = re.findall(r"\b([a-zA-Z_:][a-zA-Z0-9_:]*)\b", expr)

    promql_keywords = {
        "by", "without", "on", "ignoring", "group_left", "group_right",
        "bool", "offset", "and", "or", "unless",
        "sum", "avg", "min", "max", "count", "stddev", "stdvar",
        "topk", "bottomk", "count_values", "quantile",
        "rate", "irate", "increase", "delta", "idelta",
        "histogram_quantile", "label_replace", "label_join",
        "predict_linear", "deriv", "changes", "resets",
        "absent", "absent_over_time", "present_over_time",
        "ceil", "floor", "round", "clamp", "clamp_min", "clamp_max",
        "abs", "sqrt", "ln", "log2", "log10", "exp",
        "time", "timestamp", "vector", "scalar",
        "sort", "sort_desc", "sgn",
        "year", "month", "day_of_month", "day_of_week",
        "hour", "minute", "days_in_month",
    }

    results: list[str] = []
    seen: set[str] = set()
    for name in candidates + bare:
        low = name.lower()
        if low not in promql_keywords and name not in seen:
            results.append(name)
            seen.add(name)
    return results


def extract_functions(expr: str) -> list[str]:
    """Return a list of function names used in the expression."""
    return re.findall(r"\b([a-zA-Z_]\w*)\s*\(", expr)


# Default ephemeral labels — can be overridden by policy
DEFAULT_EPHEMERAL_LABELS = frozenset({
    "pod", "pod_name", "instance", "container",
    "container_name", "endpoint", "revision",
})

HASH_LABEL_RE = re.compile(r"[a-f0-9]{7,}")

DEFAULT_GENERIC_NAMES = frozenset({
    "alert", "error", "problem", "warning", "critical",
    "highcpu", "highlatency", "highmemory", "highload",
    "issue", "failure", "notify", "notification",
})
