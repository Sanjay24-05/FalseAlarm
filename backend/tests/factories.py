"""Builders for isolated log data. Each test states only the fields it cares about."""

from __future__ import annotations

import json
from pathlib import Path

from false_alarm.agent.loop import run_investigation
from false_alarm.connectors.file_connector import clear_connector_cache
from false_alarm.ingest import ingest_alert
from false_alarm.scenarios import load_catalog
from false_alarm.settings import get_settings

DAY = "2026-04-12"
ATTACKER = "45.83.1.9"
VPN = "10.8.0.5"
CONTEXT = {
    "assets": [{"hostname": "FS-FIN", "ip": "10.0.1.50", "sensitivity": "critical"}],
    "corporate_vpn_ranges": ["10.8.0.0/24"],
    "known_good_ranges": [],
    "scanner_ranges": [],
    "baselines": {"bob": {"typical_sources": [VPN]}},
}


def at(clock: str) -> str:
    return f"{DAY}T{clock}:00Z" if clock.count(":") == 1 else f"{DAY}T{clock}Z"


def login(clock: str, *, user="bob", ip=ATTACKER, action="success", host="DC-01") -> dict:
    return {"timestamp": at(clock), "username": user, "src_ip": ip, "hostname": host, "action": action}


def failures(count: int, *, start_minute=30, hour=13, user="bob", ip=ATTACKER) -> list[dict]:
    return [login(f"{hour}:{start_minute + n:02d}", user=user, ip=ip, action="failure") for n in range(count)]


def flow(clock: str, *, user="bob", host="WS-BOB", **extra) -> dict:
    record = {
        "timestamp": at(clock),
        "username": user,
        "hostname": host,
        "src_ip": "10.0.5.1",
        "action": "allow",
        "direction": "internal",
        "bytes": 5,
    }
    record.update(extra)
    return record


def finance_access(clock: str, **extra) -> dict:
    return flow(clock, dst_ip="10.0.1.50", dst_host="FS-FIN", **extra)


def intel(indicator: str, reputation: str) -> dict:
    return {"indicator": indicator, "type": "ipv4", "reputation": reputation}


def alert_payload(**overrides) -> dict:
    payload = {
        "source": "test-siem",
        "name": "Multiple failed logins followed by success",
        "description": "Sign-in anomaly.",
        "severity": "high",
        "detected_at": at("14:00"),
        "username": "bob",
        "hostname": "WS-BOB",
        "src_ip": ATTACKER,
        "mitre_techniques": ["T1110"],
    }
    payload.update(overrides)
    return {key: value for key, value in payload.items() if value is not None}


def use_logs(monkeypatch, root: Path, *, context: dict | None = None, **families: list[dict]) -> None:
    """Point the app at one scenario directory holding exactly these log families."""
    directory = root / "logs" / "case"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "context.json").write_text(json.dumps(context or CONTEXT), encoding="utf-8")
    for name, records in families.items():
        (directory / f"{name}.json").write_text(json.dumps(records), encoding="utf-8")
    monkeypatch.setenv("FALSE_ALARM_SCENARIOS_DIR", str(root / "logs"))
    get_settings.cache_clear()
    load_catalog.cache_clear()
    clear_connector_cache()


def investigate(**overrides) -> dict:
    result = ingest_alert(alert_payload(**overrides))
    assert result.errors == [], result.errors
    return run_investigation(result.alert["id"])
