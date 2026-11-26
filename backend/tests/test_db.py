"""Schema migrations, cheap queue reads, and ingest off the event loop."""

import asyncio
import json
import sqlite3

import pytest
from factories import alert_payload, login, use_logs
from fastapi.testclient import TestClient

from false_alarm import db
from false_alarm.agent.loop import run_investigation
from false_alarm.ingest import ingest_alert
from false_alarm.main import create_app
from false_alarm.service import list_alert_summaries
from false_alarm.settings import get_settings

# The schema as first released, before versioned migrations.
ORIGINAL_SCHEMA = """
CREATE TABLE alerts (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, document TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE investigations (id TEXT PRIMARY KEY, alert_id TEXT NOT NULL, status TEXT NOT NULL, document TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX idx_investigations_alert ON investigations(alert_id);
"""


def test_migrations_run_once_per_database(monkeypatch):
    calls = []
    real = db._migrate
    monkeypatch.setattr(db, "_migrate", lambda connection: calls.append(1) or real(connection))
    for _ in range(5):
        db.get_alert_row("missing")
    assert len(calls) == 1


def test_a_new_database_is_at_the_latest_version():
    db.init_db()
    with sqlite3.connect(get_settings().db_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
        columns = {row[1] for row in connection.execute("PRAGMA table_info(investigations)")}
    assert {"verdict", "stop_reason"} <= columns


def test_an_original_database_is_upgraded_and_backfilled(monkeypatch, tmp_path):
    path = tmp_path / "original.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(ORIGINAL_SCHEMA)
        alert = {"alert": {**alert_payload(), "id": "a1", "iocs": [], "file_hashes": [], "domains": [], "urls": [], "raw": {}}}
        connection.execute("INSERT INTO alerts VALUES ('a1', 'fp', ?, '2026-01-01T00:00:00Z')", (json.dumps(alert),))
        for run, verdict, stamp in (("i1", "likely_benign", "01"), ("i2", "confirmed_threat", "02"), ("i3", None, "03")):
            document = {"id": run, "stop_reason": "completed" if verdict else None,
                        "assessment": {"verdict": verdict} if verdict else None}
            connection.execute(
                "INSERT INTO investigations VALUES (?, 'a1', ?, ?, ?, ?)",
                (run, "completed" if verdict else "running", json.dumps(document), f"2026-01-01T00:00:{stamp}Z", f"2026-01-01T00:00:{stamp}Z"),
            )
    monkeypatch.setenv("FALSE_ALARM_DB_PATH", str(path))
    get_settings.cache_clear()

    assert db.latest_verdicts() == {"a1": ("i2", "confirmed_threat")}
    history = db.list_investigations_for_alert("a1")
    assert [(item["id"], item["verdict"], item["stop_reason"]) for item in history] == [
        ("i3", None, None),
        ("i2", "confirmed_threat", "completed"),
        ("i1", "likely_benign", "completed"),
    ]


def test_the_queue_reads_verdicts_without_parsing_investigations(monkeypatch, tmp_path):
    use_logs(monkeypatch, tmp_path, authentication=[login("13:50")])
    for name in ("one", "two"):
        alert_id = ingest_alert(alert_payload(name=name)).alert["id"]
        run_investigation(alert_id)
    parsed = []
    real = db._loads
    monkeypatch.setattr(db, "_loads", lambda text: parsed.append(json.loads(text)) or real(text))
    summaries = list_alert_summaries()
    assert {item["verdict"] for item in summaries} == {"suspicious"}
    assert all("alert" in document for document in parsed), "an investigation document was parsed"
    parsed.clear()
    db.list_investigations_for_alert(summaries[0]["id"])
    assert parsed == []


@pytest.mark.parametrize(
    "send",
    [
        lambda c: c.post("/api/alerts", json=alert_payload()),
        lambda c: c.post("/api/alerts/upload", files={"file": ("a.json", json.dumps([alert_payload()]))}),
    ],
    ids=["alert", "upload"],
)
def test_ingest_runs_off_the_event_loop(monkeypatch, send):
    on_loop = []

    def spy(payload):
        try:
            asyncio.get_running_loop()
            on_loop.append(True)
        except RuntimeError:
            on_loop.append(False)
        return ingest_alert(payload)

    monkeypatch.setattr("false_alarm.api.routes.ingest_alert", spy)
    with TestClient(create_app()) as client:
        assert send(client).status_code in (200, 201)
    assert on_loop == [False]
