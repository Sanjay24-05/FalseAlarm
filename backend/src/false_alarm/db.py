"""SQLite persistence for alerts and investigation runs."""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any

from false_alarm.settings import get_settings
from false_alarm.util import utc_iso, utc_now

_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    document TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    status TEXT NOT NULL,
    document TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_investigations_alert ON investigations(alert_id);
"""


def connect() -> sqlite3.Connection:
    settings = get_settings()
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(settings.db_path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.executescript(SCHEMA)
    return connection


def init_db() -> None:
    connection = connect()
    connection.close()


def _dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def _loads(payload: str) -> dict[str, Any]:
    return json.loads(payload)


def save_alert(alert_id: str, fingerprint: str, document: dict[str, Any]) -> None:
    created = utc_iso(utc_now())
    with _lock:
        connection = connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO alerts (id, fingerprint, document, created_at) VALUES (?, ?, ?, ?)",
                (alert_id, fingerprint, _dumps(document), created),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def get_alert_row_by_fingerprint(fingerprint: str) -> dict[str, Any] | None:
    connection = connect()
    try:
        row = connection.execute(
            "SELECT document FROM alerts WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        return None
    return _loads(row["document"])


def get_alert_row(alert_id: str) -> dict[str, Any] | None:
    connection = connect()
    try:
        row = connection.execute(
            "SELECT document FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        return None
    return _loads(row["document"])


def alert_id_exists(alert_id: str) -> bool:
    connection = connect()
    try:
        row = connection.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    finally:
        connection.close()
    return row is not None


def list_alert_rows() -> list[dict[str, Any]]:
    connection = connect()
    try:
        rows = connection.execute("SELECT document FROM alerts").fetchall()
    finally:
        connection.close()
    return [_loads(row["document"]) for row in rows]


def latest_verdicts() -> dict[str, str]:
    connection = connect()
    try:
        rows = connection.execute(
            "SELECT alert_id, document FROM investigations ORDER BY updated_at DESC"
        ).fetchall()
    finally:
        connection.close()
    verdicts: dict[str, str] = {}
    for row in rows:
        alert_id = row["alert_id"]
        if alert_id in verdicts:
            continue
        document = _loads(row["document"])
        assessment = document.get("assessment") or {}
        verdict = assessment.get("verdict")
        if isinstance(verdict, str) and verdict:
            verdicts[alert_id] = verdict
    return verdicts


def running_investigation_ids() -> list[str]:
    connection = connect()
    try:
        rows = connection.execute("SELECT id FROM investigations WHERE status = 'running'").fetchall()
    finally:
        connection.close()
    return [row["id"] for row in rows]


def insert_investigation(document: dict[str, Any]) -> str | None:
    """Store a new run unless the alert already has one running. Returns the running run's id instead."""
    stamp = utc_iso(utc_now())
    with _lock:
        connection = connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            running = connection.execute(
                "SELECT id FROM investigations WHERE alert_id = ? AND status = 'running' ORDER BY created_at LIMIT 1",
                (document["alert_id"],),
            ).fetchone()
            if running is not None:
                connection.rollback()
                return running["id"]
            connection.execute(
                """
                INSERT INTO investigations (id, alert_id, status, document, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    document["id"],
                    document["alert_id"],
                    document["status"],
                    _dumps(document),
                    stamp,
                    stamp,
                ),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
    return None


def update_investigation(document: dict[str, Any]) -> None:
    stamp = utc_iso(utc_now())
    with _lock:
        connection = connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                UPDATE investigations
                SET alert_id = ?, status = ?, document = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    document["alert_id"],
                    document["status"],
                    _dumps(document),
                    stamp,
                    document["id"],
                ),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def get_investigation(investigation_id: str) -> dict[str, Any] | None:
    connection = connect()
    try:
        row = connection.execute(
            "SELECT document FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        return None
    return _loads(row["document"])
