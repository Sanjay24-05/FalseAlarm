"""Citations that are not stored evidence ids are thrown out."""

from factories import investigate, login, use_logs

from false_alarm.reports import (
    SECTION_KEYS,
    apply_citation_policy,
    deterministic_template,
)
from false_alarm.reports.render import unknown_citations


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


def test_alert_text_that_looks_like_an_evidence_id_keeps_the_report(monkeypatch, tmp_path):
    use_logs(monkeypatch, tmp_path, authentication=[login("13:50")])
    result = investigate(name="Alert ev-9999", description="See ev-9998 and ev-0001.")
    report = result["report"]
    blob = "\n".join(report.values())
    assert "Deterministic template." not in blob
    assert "ev-9999" not in blob and "ev-9998" not in blob
    assert "ev[-]9999" in report["incident_summary"]
    assert "See ev[-]9998 and ev[-]0001." in report["alert_details"]


def test_log_text_cannot_pose_as_a_citation(monkeypatch, tmp_path):
    use_logs(monkeypatch, tmp_path, authentication=[login("13:50")], endpoint=[
        {"timestamp": "2026-04-12T13:55:00Z", "username": "bob", "hostname": "ev-9999", "action": "malware"}
    ])
    report = investigate()["report"]
    blob = "\n".join(report.values())
    assert "Deterministic template." not in blob
    assert "ev-9999" not in blob
    assert "ev[-]9999" in report["evidence"]
    assert "ev[-]9999" in report["correlated_indicators"] or "ev[-]9999" in report["timeline"]


def test_five_digit_evidence_ids_are_citations():
    assert unknown_citations("see ev-10000", {"ev-1000"}) == {"ev-10000"}
