"""Service facade used by the API and by tests."""

from __future__ import annotations

from false_alarm.db import (
    get_alert_row,
    get_investigation,
    latest_verdicts,
    list_alert_rows,
    list_investigations_for_alert,
)
from false_alarm.errors import ScenarioNotFound
from false_alarm.ingest import IngestResult, ingest_alert
from false_alarm.agent.loop import execute_investigation, run_investigation, start_investigation
from false_alarm.scenarios import list_scenarios, load_scenario_payload


def load_scenario(scenario_id: str) -> IngestResult:
    payload = load_scenario_payload(scenario_id)
    return ingest_alert(payload)


def list_alert_summaries() -> list[dict]:
    latest = latest_verdicts()
    summaries = []
    for row in list_alert_rows():
        alert = row["alert"]
        investigation_id, verdict = latest.get(alert["id"], (None, None))
        summaries.append(
            {
                "id": alert["id"],
                "source": alert["source"],
                "name": alert["name"],
                "severity": alert["severity"],
                "detected_at": alert["detected_at"],
                "username": alert["username"],
                "hostname": alert["hostname"],
                "src_ip": alert["src_ip"],
                "verdict": verdict,
                "latest_investigation_id": investigation_id,
            }
        )
    summaries.sort(key=lambda item: item["detected_at"], reverse=True)
    return summaries


def get_alert_view(alert_id: str) -> dict | None:
    row = get_alert_row(alert_id)
    if row is None:
        return None
    return {"alert": row["alert"], "warnings": row.get("warnings") or []}


def alert_investigations(alert_id: str) -> list[dict] | None:
    if get_alert_row(alert_id) is None:
        return None
    return list_investigations_for_alert(alert_id)


__all__ = [
    "IngestResult",
    "alert_investigations",
    "ScenarioNotFound",
    "execute_investigation",
    "get_alert_view",
    "get_investigation",
    "ingest_alert",
    "list_alert_summaries",
    "list_scenarios",
    "load_scenario",
    "run_investigation",
    "start_investigation",
]
