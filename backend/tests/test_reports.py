"""Citations that are not stored evidence ids are thrown out."""

from false_alarm.reports import (
    SECTION_KEYS,
    apply_citation_policy,
    deterministic_template,
)


def test_unknown_report_citations_are_rejected():
    known = {"ev-0001"}
    bad = {key: "The narrative cites ev-9999." for key in SECTION_KEYS}
    fallback = deterministic_template([{"id": "ev-0001"}])
    result = apply_citation_policy(bad, known, fallback)
    assert result == fallback
    blob = "\n".join(result.values())
    assert "ev-9999" not in blob
    assert "ev-0001" in blob
    assert "Deterministic template." in result["incident_summary"]


def test_known_citations_are_kept():
    known = {"ev-0001"}
    good = {key: "Supported by ev-0001." for key in SECTION_KEYS}
    fallback = deterministic_template([{"id": "ev-0001"}])
    assert apply_citation_policy(good, known, fallback) == good
