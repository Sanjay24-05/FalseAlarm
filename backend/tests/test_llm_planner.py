"""A model may reorder the investigation. It may not shorten it, fake it, or widen it."""

import json

import pytest
from factories import ATTACKER, finance_access, flow, intel, investigate, login, use_logs

from false_alarm.planner import llm
from false_alarm.settings import get_settings

FINISH = {"tool": "finish", "arguments": {}, "question": "done"}


@pytest.fixture
def model(monkeypatch, tmp_path):
    """Run an investigation whose model replies with these proposals, then always with `otherwise`."""
    use_logs(
        monkeypatch,
        tmp_path,
        authentication=[login("13:50")],
        firewall=[finance_access("13:58"), flow("13:40", user="alice", host="WS-ALICE")],
        threat_intel=[intel(ATTACKER, "malicious")],
    )
    for key, value in {"ENABLED": "1", "BASE_URL": "http://llm.invalid", "API_KEY": "sekret-key", "MODEL": "m"}.items():
        monkeypatch.setenv(f"FALSE_ALARM_LLM_{key}", value)
    get_settings.cache_clear()

    def run(*proposals, otherwise=FINISH):
        replies = iter(proposals)

        def reply(*_args, **_kwargs):
            value = next(replies, otherwise)
            return value if isinstance(value, str) else json.dumps(value)

        monkeypatch.setattr(llm, "chat_complete", reply)
        return investigate()

    return run


def _planner(result):
    return [entry["details"] for entry in result["audit"] if entry["kind"] == "planner"]


def _tools(result):
    return [step["tool"] for step in result["steps"]]


def test_finishing_early_does_not_skip_the_investigation(model):
    result = model()
    assert {"query_authentication", "query_firewall", "lookup_threat_intel"} <= set(_tools(result))
    assert result["assessment"]["verdict"] == "confirmed_threat"
    assert result["assessment"]["unresolved_questions"] == []
    assert _planner(result)[0]["source"] == "playbook_override"
    assert "open" in _planner(result)[0]["override_reason"]


def test_a_useful_proposal_is_followed(model):
    result = model({"tool": "query_firewall", "arguments": {"user": "bob"}, "question": "Firewall first?"})
    assert _tools(result)[0] == "query_firewall"
    assert _planner(result)[0]["source"] == "llm"


def test_a_forged_question_id_answers_nothing(model):
    result = model({"tool": "query_dns", "arguments": {"user": "bob"}, "question": "x", "question_id": "q_ti"})
    assert "lookup_threat_intel" in _tools(result)


def test_a_narrower_query_does_not_answer_the_question(model):
    result = model({"tool": "query_authentication", "arguments": {"user": "nobody"}, "question": "x"})
    users = [step["arguments"].get("user") for step in result["steps"] if step["tool"] == "query_authentication"]
    assert "bob" in users


def test_an_empty_reputation_lookup_does_not_count_as_asking(model):
    result = model({"tool": "lookup_threat_intel", "arguments": {"iocs": ["1.1.1.1"]}, "question": "x"})
    looked_up = [ioc for step in result["steps"] for ioc in step["arguments"].get("iocs", [])]
    assert ATTACKER in looked_up
    assert result["assessment"]["verdict"] == "confirmed_threat"


def test_a_query_that_covers_the_playbook_question_is_not_repeated(model):
    result = model({"tool": "query_authentication", "arguments": {"user": "BOB", "host": "WS-BOB"}, "question": "x"})
    users = [step["arguments"].get("user") for step in result["steps"] if step["tool"] == "query_authentication"]
    assert users.count("bob") == 0


def test_an_unscoped_proposal_is_replaced(model):
    result = model({"tool": "query_firewall", "arguments": {}, "question": "everything"})
    assert [step["status"] for step in result["steps"]] == ["completed"] * len(result["steps"])
    assert all("alice" not in item["entities"]["users"] for item in result["evidence"])
    assert _planner(result)[0]["source"] == "playbook_override"


def test_a_model_cannot_widen_the_case_to_another_user(model):
    result = model(
        {"tool": "query_firewall", "arguments": {"user": "alice"}, "question": "x"},
        {"tool": "query_firewall", "arguments": {"host": "WS-ALICE"}, "question": "x"},
        {"tool": "query_dns", "arguments": {"iocs": ["198.51.100.250"]}, "question": "x"},
    )
    assert all("alice" not in item["entities"]["users"] for item in result["evidence"])
    reasons = [entry.get("override_reason", "") for entry in _planner(result)[:3]]
    assert all("outside this case" in reason for reason in reasons), reasons


def test_a_looping_model_cannot_spend_the_budget(model):
    again = {"tool": "query_dns", "arguments": {"user": "bob"}, "question": "again"}
    result = model(otherwise=again)
    assert result["status"] == "completed"
    assert result["assessment"]["verdict"] == "confirmed_threat"


def test_a_tool_outside_the_allowlist_falls_back_to_the_playbook(model):
    result = model(otherwise={"tool": "drop_table", "arguments": {}, "question": "x"})
    assert result["status"] == "completed"
    assert {entry["source"] for entry in _planner(result)} == {"playbook_fallback"}


def test_a_wandering_model_leaves_budget_for_the_playbook(model):
    wander = [{"tool": "query_dns", "arguments": {"user": f"u{n}"}, "question": "x"} for n in range(30)]
    result = model(*wander)
    assert result["status"] == "completed"
    assert result["assessment"]["verdict"] == "confirmed_threat"
    assert result["assessment"]["unresolved_questions"] == []


@pytest.mark.parametrize("iocs", [5, {"a": 1}, [None, 3], "x"])
def test_malformed_arguments_do_not_crash(model, iocs):
    result = model({"tool": "query_dns", "arguments": {"iocs": iocs}, "question": "x"})
    assert result["status"] == "completed"
