"""Evidence is deduplicated only when it is the same record."""

import pytest
from factories import ATTACKER, at, intel, investigate, login, use_logs

from false_alarm.agent.observe import event_fingerprint

PROCESS = {"timestamp": at("13:58"), "username": "bob", "hostname": "WS-BOB", "action": "process"}
QUIET = {**PROCESS, "severity": "low", "file_hash": "a" * 32}
LOUD = {**PROCESS, "severity": "critical", "file_hash": "b" * 32}


@pytest.mark.parametrize("order", [[QUIET, LOUD], [LOUD, QUIET]])
def test_same_second_events_are_both_kept_in_either_order(monkeypatch, tmp_path, order):
    use_logs(monkeypatch, tmp_path, authentication=[login("13:50")], endpoint=order)
    result = investigate()
    kept = sorted(item["raw"]["severity"] for item in result["evidence"] if item["source_type"] == "endpoint")
    assert kept == ["critical", "low"]
    assert result["assessment"]["verdict"] == "confirmed_threat"


def test_identical_rows_in_one_result_are_separate_events(monkeypatch, tmp_path):
    burst = [login("13:40", action="failure") for _ in range(4)]
    use_logs(monkeypatch, tmp_path, authentication=burst)
    result = investigate()
    assert len([item for item in result["evidence"] if item["source_type"] == "authentication"]) == 4


def test_the_same_record_found_by_two_queries_is_stored_once(monkeypatch, tmp_path):
    use_logs(monkeypatch, tmp_path, authentication=[login("13:40")])
    result = investigate()
    assert len([step for step in result["steps"] if step["tool"] == "query_authentication"]) == 2
    assert len([item for item in result["evidence"] if item["source_type"] == "authentication"]) == 1


def test_a_repeated_reputation_lookup_is_the_same_evidence():
    first = {**intel(ATTACKER, "malicious"), "timestamp": "2026-01-01T00:00:00Z"}
    later = {**first, "timestamp": "2026-01-01T00:00:09Z"}
    assert event_fingerprint("threat_intel", first) == event_fingerprint("threat_intel", later)
