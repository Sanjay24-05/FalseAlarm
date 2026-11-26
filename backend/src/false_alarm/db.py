"""SQLite persistence for alerts and investigation runs."""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any

from false_alarm.settings import get_settings
from false_alarm.util import utc_iso, utc_now

_lock = threading.Lock()

# Each entry upgrades the schema by one version. PRAGMA user_version records the version a file is at.
# Version 1 is the schema as first released, so files created before migrations existed upgrade cleanly.
MIGRATIONS: tuple[str, ...] = (
    """
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
    """,
    # The queue and history read these columns instead of parsing every investigation document.
    """
    ALTER TABLE investigations ADD COLUMN verdict TEXT;
    ALTER TABLE investigations ADD COLUMN stop_reason TEXT;
    UPDATE investigations SET
        verdict = json_extract(document, '$.assessment.verdict'),
        stop_reason = json_extract(document, '$.stop_reason');
    -- Covers the queue query, so it never reads rows whose documents fill overflow pages.
    CREATE INDEX IF NOT EXISTS idx_investigations_latest ON investigations(alert_id, updated_at, verdict, id);
    """,
)
SCHEMA_VERSION = len(MIGRATIONS)
_migrated: set[str] = set()


def _migrate(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA journal_mode=WAL")
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    for number, script in enumerate(MIGRATIONS[version:], start=version + 1):
        # executescript commits first, so the version bump is part of the same script.
        connection.executescript(f"BEGIN IMMEDIATE;\n{script}\nPRAGMA user_version = {number};\nCOMMIT;")


def connect() -> sqlite3.Connection:
    settings = get_settings()
    path = str(settings.db_path)
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA synchronous=NORMAL")
    if path not in _migrated:
        with _lock:
            if path not in _migrated:
                _migrate(connection)
                _migrated.add(path)
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


def _verdict(document: dict[str, Any]) -> str | None:
    verdict = (document.get("assessment") or {}).get("verdict")
    return verdict if isinstance(verdict, str) and verdict else None


def latest_verdicts() -> dict[str, tuple[str, str | None]]:
    """For each alert with a run: the run its queue verdict comes from, and that verdict.

    That is the most recently updated run with a verdict, or the most recent run when none has one.
    """
    connection = connect()
    try:
        rows = connection.execute(
            """
            SELECT alert_id, id, verdict FROM (
                SELECT alert_id, id, verdict, ROW_NUMBER() OVER (
                    PARTITION BY alert_id ORDER BY verdict IS NULL, updated_at DESC, rowid DESC
                ) AS rank
                FROM investigations
            ) WHERE rank = 1
            """
        ).fetchall()
    finally:
        connection.close()
    return {row["alert_id"]: (row["id"], row["verdict"]) for row in rows}


def list_investigations_for_alert(alert_id: str) -> list[dict[str, Any]]:
    """Summaries of an alert's runs, newest first."""
    connection = connect()
    try:
        rows = connection.execute(
            """
            SELECT id, status, stop_reason, verdict, created_at, updated_at FROM investigations
            WHERE alert_id = ? ORDER BY created_at DESC, rowid DESC
            """,
            (alert_id,),
        ).fetchall()
    finally:
        connection.close()
    return [dict(row) for row in rows]


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
                INSERT INTO investigations
                    (id, alert_id, status, verdict, stop_reason, document, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    document["id"],
                    document["alert_id"],
                    document["status"],
                    _verdict(document),
                    document.get("stop_reason"),
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
                SET alert_id = ?, status = ?, verdict = ?, stop_reason = ?, document = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    document["alert_id"],
                    document["status"],
                    _verdict(document),
                    document.get("stop_reason"),
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
