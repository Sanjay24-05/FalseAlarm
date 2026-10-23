"""Scenario outcomes, timeline labels, and the tool budget."""

from __future__ import annotations

from false_alarm.reports import EVIDENCE_ID_RE, SECTION_KEYS
from false_alarm.service import list_scenarios, load_scenario, run_investigation
from false_alarm.settings import get_settings


def _investigate(scenario_id: str) -> dict:
    loaded = load_scenario(scenario_id)
    assert loaded.errors == []
    assert loaded.warnings == []
    assert loaded.duplicate is False
    return run_investigation(loaded.alert["id"])


def _assert_citations(result: dict) -> None:
    known = {item["id"] for item in result["evidence"]}
    assert set(result["report"]) == set(SECTION_KEYS)
    blob = "\n".join(result["report"].values())
    assert "Deterministic template." not in blob
    assert EVIDENCE_ID_RE.findall(blob)
    assert set(EVIDENCE_ID_RE.findall(blob)) <= known
    for event in result["timeline"]:
        assert event["relationship"] in {"observed", "inferred"}
        assert set(event["evidence_ids"]) <= known
    for item in result["evidence"]:
        assert item["kind"] == "observation"


def test_account_compromise_is_a_confirmed_threat():
    result = _investigate("account_compromise")
    assessment = result["assessment"]
    assert result["status"] == "completed"
    assert result["stop_reason"] == "completed"
    assert assessment["verdict"] == "confirmed_threat"
    assert assessment["severity"] in {"high", "critical"}
    assert assessment["confidence"] in {"low", "medium", "high"}
    assert assessment["escalate"] is True
    assert result["steps"][0]["tool"] == "query_authentication"
    assert "target account" in result["steps"][0]["question"].lower()
    assert result["metrics"]["tool_call_count"] <= 12
    assert result["metrics"]["event_count"] == len(result["evidence"])

    labels = {event["relationship"] for event in result["timeline"]}
    assert labels == {"observed", "inferred"}
    stamps = [event["timestamp"] for event in result["timeline"]]
    assert stamps == sorted(stamps)

    observed = [event for event in result["timeline"] if event["relationship"] == "observed"]

    def position(predicate) -> int:
        for index, event in enumerate(observed):
            if predicate(event["summary"]):
                return index
        raise AssertionError([event["summary"] for event in observed])

    failure = position(lambda text: text.startswith("Authentication failure"))
    success = position(lambda text: text.startswith("Authentication success"))
    fileserver = position(lambda text: "FS-FINANCE" in text)
    outbound = position(lambda text: text.startswith("Firewall outbound") and "198.51.100.77" in text)
    assert failure < success < fileserver < outbound
    assert any(
        item["source_type"] == "threat_intel"
        and item["raw"].get("indicator") == "203.0.113.50"
        and item["raw"].get("reputation") == "malicious"
        for item in result["evidence"]
    )
    _assert_citations(result)


def test_benign_vpn_login_is_not_escalated():
    result = _investigate("benign_vpn_login")
    assessment = result["assessment"]
    assert result["status"] == "completed"
    assert assessment["verdict"] == "likely_benign"
    assert assessment["escalate"] is False
    assert assessment["severity"] in {"informational", "low"}
    reputations = [
        item["raw"].get("reputation")
        for item in result["evidence"]
        if item["source_type"] == "threat_intel"
    ]
    assert "clean" in reputations
    assert "malicious" not in reputations
    _assert_citations(result)


def test_scenarios_publish_expected_verdicts():
    by_id = {item["id"]: item for item in list_scenarios()}
    assert by_id["account_compromise"]["expected_verdict"] == "confirmed_threat"
    assert by_id["benign_vpn_login"]["expected_verdict"] == "likely_benign"


def test_unrelated_alert_does_not_invent_a_threat():
    from false_alarm.ingest import ingest_alert

    loaded = ingest_alert(
        {
            "source": "demo-siem",
            "name": "Multiple failed logins followed by success",
            "description": "No matching logs exist for this user.",
            "severity": "medium",
            "detected_at": "2026-01-01T00:00:00Z",
            "src_ip": "198.51.100.9",
            "username": "ghost.user",
            "hostname": "GHOST-1",
            "mitre_techniques": ["T1110"],
        }
    )
    result = run_investigation(loaded.alert["id"])
    assert result["assessment"]["verdict"] == "suspicious"
    blob = " ".join(event["summary"] for event in result["timeline"])
    evidence_blob = " ".join(item["summary"] for item in result["evidence"])
    assert "jsmith" not in blob
    assert "FS-FINANCE" not in blob
    assert "jsmith" not in evidence_blob
    assert "FS-FINANCE" not in evidence_blob


def test_tool_budget_exhaustion(monkeypatch):
    monkeypatch.setenv("FALSE_ALARM_MAX_TOOL_CALLS", "2")
    get_settings.cache_clear()
    result = _investigate("account_compromise")
    assert result["status"] == "budget_exhausted"
    assert result["stop_reason"] == "tool_call_budget"
    assert result["metrics"]["tool_call_count"] == 2
