"""File discovery and filtering module."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def resolve_paths(paths: list[Path], recursive: bool = False) -> list[Path]:
    """Expand directories into individual YAML file paths.

    If a path points to a specific file, it is included directly.
    If a path points to a directory, it is scanned for .yaml and .yml files.

    Non-existent paths are logged and skipped.
    """
    result: list[Path] = []
    
    for p in paths:
        if p.is_file():
            result.append(p)
        elif p.is_dir():
            pattern = "**/*.y*ml" if recursive else "*.y*ml"
            # Sort for deterministic processing order
            found = sorted(p.glob(pattern))
            if not found:
                logger.debug("No YAML files found in directory: %s", p)
            result.extend(found)
        else:
            logger.warning("Path %s does not exist or is not accessible — skipping", p)

    return _deduplicate_paths(result)


def _deduplicate_paths(paths: list[Path]) -> list[Path]:
    """Remove absolute path duplicates while retaining order."""
    seen: set[Path] = set()
    unique: list[Path] = []
    for p in paths:
        abs_p = p.resolve()
        if abs_p not in seen:
            seen.add(abs_p)
            unique.append(p)
    return unique
