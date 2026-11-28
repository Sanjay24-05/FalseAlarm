"""Unknown tools are rejected, and a bad model response falls back after one retry."""

import pytest
from pydantic import ValidationError

from false_alarm.domain.allowlist import ALLOWED_TOOLS
from false_alarm.agent.tools import execute_tool
from false_alarm.errors import UnknownToolError
from false_alarm.planner.actions import ToolAction
from false_alarm.planner.llm import propose_with_llm
from false_alarm.settings import get_settings


def test_allowlist_is_exact():
    assert ALLOWED_TOOLS == {
        "query_authentication",
        "query_firewall",
        "query_endpoint",
        "query_dns",
        "query_related_alerts",
        "lookup_threat_intel",
        "expand_time_window",
        "finish",
    }


def test_execute_rejects_unknown_tool():
    with pytest.raises(UnknownToolError) as caught:
        execute_tool("drop_table", {})
    assert caught.value.name == "drop_table"


def test_planner_schema_rejects_unknown_tool():
    with pytest.raises(ValidationError):
        ToolAction(tool="drop_table", arguments={}, question="erase logs")


def test_llm_invalid_response_retries_once_then_fails(monkeypatch):
    calls = {"n": 0}

    def fake(_summary, _settings, **_kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return "not json"
        return '{"tool": "drop_table", "arguments": {}, "question": "erase"}'

    monkeypatch.setattr("false_alarm.planner.llm.chat_complete", fake)
    assert propose_with_llm("bounded summary", get_settings()) is None
    assert calls["n"] == 2
