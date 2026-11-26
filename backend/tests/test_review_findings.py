"""Regression tests for the final-review findings. Each reproduces a false negative or a hang the review confirmed."""

import json
import threading

import pytest
from factories import ATTACKER, VPN, alert_payload, failures, flow, intel, investigate, login, use_logs

from false_alarm import db
from false_alarm.connectors import clear_jsonl_cache
from false_alarm.scenarios import load_catalog
from false_alarm.settings import get_settings
from test_connector_registry import CONTEXT

EXFIL = flow("14:10", dst_ip=ATTACKER, direction="outbound", bytes=900_000_000)


# C1: a run that stops early is never benign


@pytest.mark.parametrize("budget", ["1", "2"])
def test_a_run_that_runs_out_of_tool_calls_is_not_benign(monkeypatch, tmp_path, budget):
    use_logs(monkeypatch, tmp_path, authentication=[login("13:50", ip=VPN)], firewall=[EXFIL], threat_intel=[intel(VPN, "clean")])
    monkeypatch.setenv("FALSE_ALARM_MAX_TOOL_CALLS", budget)
    get_settings.cache_clear()
    result = investigate(src_ip=VPN)
    assert result["status"] == "budget_exhausted"
    assert result["assessment"]["verdict"] == "suspicious"
    assert result["assessment"]["escalate"] is True
    assert any("not asked" in gap for gap in result["assessment"]["missing_evidence"])


def test_threat_intelligence_never_queried_blocks_benign(monkeypatch, tmp_path):
    from false_alarm.assessment.rules import assess
    from false_alarm.scenarios import get_catalog

    use_logs(monkeypatch, tmp_path)
    evidence = [
        {
            "id": "ev-0001",
            "source": "file:authentication",
            "source_type": "authentication",
            "observed_at": "2026-04-12T13:50:00Z",
            "query_id": "qry-0001",
            "summary": "s",
            "entities": {},
            "kind": "observation",
            "raw": login("13:50", ip=VPN),
        }
    ]
    assessment, _, _ = assess(alert_payload(src_ip=VPN), evidence, get_catalog(), [], answered_questions=set())
    assert assessment["verdict"] == "suspicious"


# C2: sign-ins under another form of the name, or another account, from the alert's source


@pytest.mark.parametrize("name", ["bob@corp.local", "CORP\\bob", "alice"])
def test_sign_ins_from_the_alerts_source_under_another_name_are_not_benign(monkeypatch, tmp_path, name):
    use_logs(
        monkeypatch,
        tmp_path,
        authentication=[login("11:00", ip=VPN), *failures(5, user=name), login("13:56", user=name)],
        threat_intel=[intel(ATTACKER, "clean"), intel(VPN, "clean")],
    )
    result = investigate()
    assert result["assessment"]["verdict"] == "suspicious"
    assert result["assessment"]["escalate"] is True


@pytest.mark.parametrize("name", ["bob@corp.local", "CORP\\bob"])
def test_account_name_forms_are_the_same_user(monkeypatch, tmp_path, name):
    use_logs(
        monkeypatch,
        tmp_path,
        authentication=[*failures(4, user=name), login("13:56", user=name)],
        firewall=[flow("13:58", user=name, dst_ip="10.0.1.50", dst_host="FS-FIN")],
        threat_intel=[intel(ATTACKER, "clean")],
    )
    assert investigate()["assessment"]["verdict"] == "confirmed_threat"


def test_other_accounts_on_the_vpn_do_not_block_benign(monkeypatch, tmp_path):
    use_logs(
        monkeypatch,
        tmp_path,
        authentication=[login("13:40", user="carol", ip=VPN), login("13:50", ip=VPN)],
        threat_intel=[intel(VPN, "clean")],
    )
    assert investigate(src_ip=VPN)["assessment"]["verdict"] == "likely_benign"


# I1: JSONL records that cannot be read


def _jsonl(monkeypatch, tmp_path, firewall_lines):
    logs = tmp_path / "export"
    logs.mkdir()
    (logs / "context.json").write_text(json.dumps(CONTEXT), encoding="utf-8")
    (logs / "authentication.jsonl").write_text(json.dumps(login("13:50", ip=VPN)) + "\n", encoding="utf-8")
    (logs / "threat_intel.jsonl").write_text(json.dumps(intel(VPN, "clean")) + "\n", encoding="utf-8")
    (logs / "firewall.jsonl").write_text("\n".join(firewall_lines) + "\n", encoding="utf-8")
    monkeypatch.setenv("FALSE_ALARM_CONNECTOR", "jsonl")
    monkeypatch.setenv("FALSE_ALARM_LOGS_DIR", str(logs))
    get_settings.cache_clear()
    load_catalog.cache_clear()
    clear_jsonl_cache()


def test_an_unreadable_record_blocks_benign(monkeypatch, tmp_path):
    _jsonl(monkeypatch, tmp_path, ['{"timestamp": "2026-04-12T14:10:00Z", "username": "bob", "dst_ip": "45.83.1.9", "byt'])
    assessment = investigate(src_ip=VPN)["assessment"]
    assert assessment["verdict"] == "suspicious"
    assert any("could not be read" in gap and "firewall" in gap for gap in assessment["missing_evidence"])


@pytest.mark.parametrize(
    "stamp",
    [{"@timestamp": "2026-04-12T14:10:00Z"}, {"timestamp": 1776003000}, {"timestamp": 1776003000000}],
    ids=["elastic", "epoch-seconds", "epoch-millis"],
)
def test_common_timestamp_forms_are_read(monkeypatch, tmp_path, stamp):
    record = {key: value for key, value in EXFIL.items() if key != "timestamp"} | stamp
    _jsonl(monkeypatch, tmp_path, [json.dumps(record)])
    result = investigate(src_ip=VPN)
    assert any(item["source_type"] == "firewall" for item in result["evidence"])
    assert result["assessment"]["verdict"] == "suspicious"


# I3: writing first on a fresh database does not hang


def test_a_write_as_the_first_database_call_does_not_hang(tmp_path, monkeypatch):
    monkeypatch.setenv("FALSE_ALARM_DB_PATH", str(tmp_path / "fresh.db"))
    get_settings.cache_clear()
    worker = threading.Thread(target=db.save_alert, args=("a1", "fp", {"alert": {"id": "a1"}}), daemon=True)
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive(), "save_alert deadlocked on a fresh database"


def test_a_deleted_database_is_recreated(tmp_path, monkeypatch):
    path = tmp_path / "reset.db"
    monkeypatch.setenv("FALSE_ALARM_DB_PATH", str(path))
    get_settings.cache_clear()
    db.init_db()
    path.unlink()
    assert db.get_alert_row("missing") is None
