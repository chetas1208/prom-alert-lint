"""Check registry module.

Responsible for discovering or manually registering all checks.
Isolating standard checks from execution logic ensures we can easily
mock or swap check implementations.
"""

from __future__ import annotations

from prom_alert_linter.checks.base import BaseCheck
from prom_alert_linter.checks.metadata import (
    MissingSeverityLabel,
    MissingSummaryAnnotation,
    MissingDescriptionAnnotation,
    MissingRunbookURL,
    MissingOwnership,
    GenericAlertName,
)
from prom_alert_linter.checks.stability import (
    MissingForClause,
    ShortForDuration,
    IrateInExpr,
    InstantThresholdWithoutSmoothing,
    CriticalFiresBeforeWarning,
)
from prom_alert_linter.checks.selectors import (
    BareMetricSelector,
    BroadUpSelector,
    EphemeralLabelDependency,
    OverlyNarrowSelector,
)
from prom_alert_linter.checks.relationships import (
    DuplicateAlertNames,
    IdenticalExpressions,
    LikelyDuplicateAlerts,
    SuspiciousThresholdOrdering,
    OverlappingAlerts,
    ConflictingDefinitions,
)

def get_all_checks() -> list[BaseCheck]:
    """Return one instance of every default implemented check."""
    return [
        # Metadata
        MissingSeverityLabel(),
        MissingSummaryAnnotation(),
        MissingDescriptionAnnotation(),
        MissingRunbookURL(),
        MissingOwnership(),
        GenericAlertName(),
        # Stability / noise
        MissingForClause(),
        ShortForDuration(),
        IrateInExpr(),
        InstantThresholdWithoutSmoothing(),
        CriticalFiresBeforeWarning(),
        # Selector quality
        BareMetricSelector(),
        BroadUpSelector(),
        EphemeralLabelDependency(),
        OverlyNarrowSelector(),
        # Cross-rule relationships
        DuplicateAlertNames(),
        IdenticalExpressions(),
        LikelyDuplicateAlerts(),
        SuspiciousThresholdOrdering(),
        OverlappingAlerts(),
        ConflictingDefinitions(),
    ]
