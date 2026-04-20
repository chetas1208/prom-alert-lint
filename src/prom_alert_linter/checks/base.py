"""Base class for lint checks."""

from __future__ import annotations

from abc import ABC, abstractmethod

from prom_alert_linter.models import AlertRule, Finding
from prom_alert_linter.policy import Policy


class BaseCheck(ABC):
    """Interface that every lint check must implement.

    * **Per-rule checks** — override :meth:`check_rule`.
    * **Cross-rule checks** — override :meth:`check_all`.

    Every check receives the active :class:`Policy` so it can respect
    team-specific configuration.
    """

    @abstractmethod
    def check_rule(self, rule: AlertRule, policy: Policy) -> list[Finding]:
        """Run the check against a single rule."""
        ...

    def check_all(
        self, rules: list[AlertRule], policy: Policy
    ) -> list[Finding]:
        """Run against the full rule set.

        The default implementation calls :meth:`check_rule` per rule.
        Cross-rule checks should override this entirely.
        """
        findings: list[Finding] = []
        for rule in rules:
            findings.extend(self.check_rule(rule, policy))
        return findings
