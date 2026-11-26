"""A query without a filter would hand one alert everyone's logs."""

import pytest
from factories import ATTACKER, at, finance_access, flow, investigate, login, use_logs

from false_alarm.agent import loop
from false_alarm.agent.tools import execute_tool
from false_alarm.connectors import build_registry
from false_alarm.errors import UnscopedQueryError
from false_alarm.planner.actions import ToolAction
from false_alarm.settings import get_settings
from false_alarm.util import parse_datetime

LOG_TOOLS = {"query_authentication", "query_firewall", "query_endpoint", "query_dns", "query_related_alerts"}


def test_ip_only_alert_does_not_collect_other_users_evidence(monkeypatch, tmp_path):
    use_logs(
        monkeypatch,
        tmp_path,
        authentication=[login("13:00", user="alice", ip="10.8.0.9")],
        firewall=[finance_access("13:30", user="alice", host="WS-ALICE")],
    )
    result = investigate(username=None, hostname=None)
    assert [item for item in result["evidence"] if "alice" in item["entities"]["users"]] == []
    assert result["assessment"]["verdict"] == "suspicious"


def test_ip_only_alert_still_finds_traffic_from_that_ip(monkeypatch, tmp_path):
    use_logs(monkeypatch, tmp_path, firewall=[flow("13:30", user="", host="", src_ip=ATTACKER, dst_ip="10.0.9.9")])
    result = investigate(username=None, hostname=None)
    assert [item["source_type"] for item in result["evidence"] if item["source_type"] == "firewall"] == ["firewall"]


@pytest.mark.parametrize("name", ["Odd sign-in", "Malware found", "Outbound beacon"])
@pytest.mark.parametrize("field", ["username", "hostname", "src_ip", "dst_ip"])
def test_playbook_never_issues_an_unscoped_query(monkeypatch, tmp_path, name, field):
    use_logs(monkeypatch, tmp_path)
    known = {"username": "bob", "hostname": "WS-BOB", "src_ip": ATTACKER, "dst_ip": "10.0.9.9"}
    only = {key: (value if key == field else None) for key, value in known.items()}
    result = investigate(name=name, description="x", mitre_techniques=[], **only)
    for step in result["steps"]:
        if step["tool"] in LOG_TOOLS:
            assert any(step["arguments"].get(key) for key in ("user", "host", "iocs")), step


def test_execute_tool_refuses_an_unscoped_query():
    with pytest.raises(UnscopedQueryError):
        execute_tool(
            "query_firewall",
            {"limit": 10},
            window_start=parse_datetime(at("12:00")),
            window_end=parse_datetime(at("14:00")),
            connectors=build_registry(get_settings()),
        )


def test_loop_records_an_unscoped_proposal_as_rejected(monkeypatch, tmp_path):
    use_logs(monkeypatch, tmp_path, authentication=[login("13:00")])
    real = loop.choose_action
    proposals = iter([ToolAction(tool="query_firewall", arguments={}, question="everything")])

    def propose_once(fallback, *args, **kwargs):
        action = next(proposals, None)
        return (action, "test", []) if action is not None else real(fallback, *args, **kwargs)

    monkeypatch.setattr(loop, "choose_action", propose_once)
    result = investigate()
    assert result["status"] == "completed"
    assert result["steps"][0]["status"] == "rejected"
    assert any(step["tool"] == "query_firewall" and step["status"] == "completed" for step in result["steps"])
