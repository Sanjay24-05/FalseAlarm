"""Log sources are pluggable: the demo files are one connector, JSON Lines exports are another."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from factories import ATTACKER, VPN, alert_payload, at, finance_access, intel, login

from false_alarm.agent.loop import run_investigation
from false_alarm.agent.tools import execute_tool
from false_alarm.connectors import Connector, FileConnector, JsonlConnector, QueryRequest, QueryResult, build_registry
from false_alarm.connectors.file_connector import clear_connector_cache
from false_alarm.ingest import ingest_alert
from false_alarm.scenarios import load_catalog
from false_alarm.service import load_scenario
from false_alarm.settings import get_settings
from false_alarm.util import parse_datetime

FAMILIES = {"authentication", "firewall", "endpoint", "dns", "related_alerts", "threat_intel"}
WINDOW = (datetime(2026, 4, 12, 12, tzinfo=timezone.utc), datetime(2026, 4, 12, 15, tzinfo=timezone.utc))
CONTEXT = {
    "assets": [{"hostname": "FS-FIN", "ip": "10.0.1.50", "sensitivity": "critical"}],
    "corporate_vpn_ranges": ["10.8.0.0/24"],
    "known_good_ranges": [],
    "scanner_ranges": [],
    "baselines": {"bob": {"typical_sources": [VPN]}},
}


def _export(directory: Path, **families: list) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "context.json").write_text(json.dumps(CONTEXT), encoding="utf-8")
    for name, records in families.items():
        lines = [record if isinstance(record, str) else json.dumps(record) for record in records]
        (directory / f"{name}.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return directory


def _use_jsonl(monkeypatch, directory: Path) -> None:
    monkeypatch.setenv("FALSE_ALARM_CONNECTOR", "jsonl")
    monkeypatch.setenv("FALSE_ALARM_LOGS_DIR", str(directory))
    get_settings.cache_clear()
    load_catalog.cache_clear()
    clear_connector_cache()


def test_the_default_registry_reads_the_demo_files():
    registry = build_registry(get_settings())
    assert set(registry) == FAMILIES
    assert all(isinstance(connector, FileConnector) for connector in registry.values())


def test_jsonl_is_selected_by_setting(monkeypatch, tmp_path):
    _use_jsonl(monkeypatch, _export(tmp_path / "logs"))
    registry = build_registry(get_settings())
    assert set(registry) == FAMILIES
    assert all(isinstance(connector, JsonlConnector) for connector in registry.values())


def test_jsonl_requires_a_logs_directory(monkeypatch):
    monkeypatch.setenv("FALSE_ALARM_CONNECTOR", "jsonl")
    get_settings.cache_clear()
    with pytest.raises(ValueError, match="FALSE_ALARM_LOGS_DIR"):
        get_settings()


def test_an_unknown_connector_is_a_settings_error(monkeypatch):
    monkeypatch.setenv("FALSE_ALARM_CONNECTOR", "splunk")
    get_settings.cache_clear()
    with pytest.raises(ValueError, match="FALSE_ALARM_CONNECTOR"):
        get_settings()


def test_an_investigation_reads_only_the_export_and_its_context(monkeypatch, tmp_path):
    export = _export(
        tmp_path / "logs",
        authentication=[*[login(f"13:{m:02d}", action="failure") for m in range(30, 34)], login("13:50")],
        firewall=[finance_access("13:58")],
        threat_intel=[intel(ATTACKER, "malicious")],
    )
    _use_jsonl(monkeypatch, export)
    result = run_investigation(ingest_alert(alert_payload()).alert["id"])
    assert result["evidence"], "the export was not read"
    assert {item["source"].split(":")[0] for item in result["evidence"]} == {"jsonl"}
    assert result["assessment"]["verdict"] == "confirmed_threat"


def test_the_demo_data_is_not_read_when_jsonl_is_selected(monkeypatch, tmp_path):
    _use_jsonl(monkeypatch, _export(tmp_path / "logs"))
    result = run_investigation(load_scenario("account_compromise").alert["id"])
    assert result["evidence"] == [] or all(item["source"].startswith("jsonl:") for item in result["evidence"])
    assert not any("jsmith" in item["entities"]["users"] for item in result["evidence"])


def test_the_export_context_supplies_baselines(monkeypatch, tmp_path):
    export = _export(
        tmp_path / "logs",
        authentication=[login("13:50", ip=VPN)],
        threat_intel=[intel(VPN, "clean")],
    )
    _use_jsonl(monkeypatch, export)
    result = run_investigation(ingest_alert(alert_payload(src_ip=VPN)).alert["id"])
    assert result["assessment"]["verdict"] == "likely_benign"


def test_jsonl_skips_lines_that_are_not_records(tmp_path):
    export = _export(
        tmp_path / "logs",
        authentication=["", "not json", "[1, 2]", login("12:30"), "{\"timestamp\": \"bad\"}", login("13:30")],
    )
    result = JsonlConnector(export, "authentication").query(QueryRequest(user="bob", start=WINDOW[0], end=WINDOW[1]))
    assert [event["timestamp"] for event in result.events] == [at("12:30"), at("13:30")]
    assert result.source == "jsonl:authentication"


def test_jsonl_honors_the_window_cap_and_newest_first_truncation(tmp_path):
    export = _export(tmp_path / "logs", authentication=[login(f"12:{m:02d}") for m in range(0, 50, 5)])
    connector = JsonlConnector(export, "authentication")
    result = connector.query(QueryRequest(user="bob", start=WINDOW[0], end=WINDOW[1], limit=3), hard_cap=200)
    assert result.truncated is True
    assert [event["timestamp"] for event in result.events] == [at("12:35"), at("12:40"), at("12:45")]


def test_jsonl_matches_reputation_by_indicator_without_a_window(tmp_path):
    export = _export(tmp_path / "logs", threat_intel=[intel(ATTACKER, "malicious"), intel("1.1.1.1", "clean")])
    result = JsonlConnector(export, "threat_intel").query(QueryRequest(iocs=[ATTACKER], start=WINDOW[0], end=WINDOW[1]))
    assert [event["indicator"] for event in result.events] == [ATTACKER]


def test_any_object_with_a_query_method_can_serve_a_family():
    class Fixed:
        source_type = "authentication"

        def query(self, request: QueryRequest, *, hard_cap: int = 200) -> QueryResult:
            event = {"timestamp": at("13:00"), "username": request.user, "action": "success"}
            return QueryResult(source="fixed:authentication", query={}, window={}, timestamp=at("13:00"), events=[event], truncated=False)

    assert isinstance(Fixed(), Connector)
    outcome = execute_tool(
        "query_authentication",
        {"user": "bob"},
        window_start=parse_datetime(at("12:00")),
        window_end=parse_datetime(at("14:00")),
        connectors={"authentication": Fixed()},
    )
    assert outcome["events"][0]["username"] == "bob"
    assert outcome["result"]["source"] == "fixed:authentication"
