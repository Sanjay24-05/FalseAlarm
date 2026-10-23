"""Report generation."""

from false_alarm.reports.render import (
    EVIDENCE_ID_RE,
    SECTION_KEYS,
    apply_citation_policy,
    compose_report,
    deterministic_template,
)

__all__ = [
    "EVIDENCE_ID_RE",
    "SECTION_KEYS",
    "apply_citation_policy",
    "compose_report",
    "deterministic_template",
]
