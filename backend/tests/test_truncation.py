"""A capped query must not hide the newest events or support a benign verdict."""

from datetime import datetime, timezone

from factories import ATTACKER, VPN, at, failures, flow, intel, investigate, login, use_logs

from false_alarm.connectors import FileConnector, QueryRequest
from false_alarm.settings import get_settings

ROUTINE = [login(f"10:{n // 4:02d}:{(n % 4) * 15:02d}", ip=VPN) for n in range(230)]
CLEAN = [intel(ATTACKER, "clean"), intel(VPN, "clean")]


def test_truncation_keeps_the_newest_events_in_order(monkeypatch, tmp_path):
    use_logs(monkeypatch, tmp_path, authentication=[login(f"12:{n:02d}") for n in range(10)])
    result = FileConnector(get_settings().scenarios_dir, "authentication.json", "authentication").query(
        QueryRequest(
            user="bob",
            start=datetime(2026, 4, 12, 12, tzinfo=timezone.utc),
            end=datetime(2026, 4, 12, 13, tzinfo=timezone.utc),
            limit=3,
        )
    )
    assert result.truncated is True
    assert [event["timestamp"] for event in result.events] == [at("12:07"), at("12:08"), at("12:09")]


def test_an_attack_after_many_routine_logins_is_seen(monkeypatch, tmp_path):
    use_logs(
        monkeypatch,
        tmp_path,
        authentication=[*ROUTINE, *failures(20), login("13:56")],
        firewall=[flow("10:05", dst_ip="10.0.9.9")],
        threat_intel=CLEAN,
    )
    result = investigate(src_ip=VPN)
    assert any(ATTACKER in item["entities"]["ips"] for item in result["evidence"])
    assert result["assessment"]["verdict"] == "suspicious"
    assert result["assessment"]["escalate"] is True


def test_a_truncated_query_is_a_gap_that_blocks_benign(monkeypatch, tmp_path):
    use_logs(
        monkeypatch,
        tmp_path,
        authentication=ROUTINE,
        firewall=[flow("10:05", dst_ip="10.0.9.9")],
        threat_intel=CLEAN,
    )
    assessment = investigate(src_ip=VPN)["assessment"]
    assert assessment["verdict"] == "suspicious"
    assert assessment["confidence"] != "high"
    assert any("authentication" in gap and "limit" in gap for gap in assessment["missing_evidence"])
