"""Domain and tool errors."""

from __future__ import annotations


class AlertNotFound(Exception):
    """Raised when an investigation targets an alert that is not stored."""


class ScenarioNotFound(Exception):
    """Raised when a scenario id does not exist on disk."""


class UnknownToolError(Exception):
    """Raised when a planner or caller names a tool outside the allowlist."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"Unknown tool: {name}")


class UnscopedQueryError(Exception):
    """Raised when a query names no user, host, or indicator. It would match every record."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"Unscoped query: {name}")
