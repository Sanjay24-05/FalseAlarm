"""File connectors keep events inside the requested window and under the hard cap."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from false_alarm.connectors import FileConnector, QueryRequest


def _write(root, name: str, events: list[dict]) -> None:
    scenario = root / "demo"
    scenario.mkdir(parents=True)
    (scenario / name).write_text(json.dumps(events), encoding="utf-8")


def test_window_and_cap(tmp_path):
    start = datetime(2026, 4, 12, 12, 0, tzinfo=timezone.utc)
    end = datetime(2026, 4, 12, 13, 0, tzinfo=timezone.utc)
    window_root = tmp_path / "window"
    _write(
        window_root,
        "authentication.json",
        [
            {"timestamp": "2026-04-12T11:59:59Z", "username": "ada", "src_ip": "203.0.113.10", "action": "failure"},
            {"timestamp": "2026-04-12T12:00:00Z", "username": "ada", "src_ip": "203.0.113.10", "action": "failure"},
            {"timestamp": "2026-04-12T13:00:00Z", "username": "ada", "src_ip": "203.0.113.10", "action": "success"},
            {"timestamp": "2026-04-12T13:00:01Z", "username": "ada", "src_ip": "203.0.113.10", "action": "success"},
        ],
    )
    result = FileConnector(window_root, "authentication.json", "authentication").query(
        QueryRequest(start=start, end=end, limit=200),
        hard_cap=200,
    )
    assert result.source == "file:authentication"
    assert result.query["start"] == "2026-04-12T12:00:00Z"
    assert result.query["end"] == "2026-04-12T13:00:00Z"
    assert result.window == {"start": "2026-04-12T12:00:00Z", "end": "2026-04-12T13:00:00Z"}
    assert result.timestamp
    assert [event["timestamp"] for event in result.events] == [
        "2026-04-12T12:00:00Z",
        "2026-04-12T13:00:00Z",
    ]

    cap_root = tmp_path / "cap"
    _write(
        cap_root,
        "authentication.json",
        [
            {
                "timestamp": "2026-04-12T12:30:00Z",
                "username": f"user{index}",
                "src_ip": "203.0.113.10",
                "action": "failure",
            }
            for index in range(250)
        ],
    )
    capped = FileConnector(cap_root, "authentication.json", "authentication").query(
        QueryRequest(start=start, end=end, limit=500),
        hard_cap=200,
    )
    assert len(capped.events) == 200
    assert capped.truncated is True
    assert capped.query["limit"] == 200
    assert capped.source
    assert "start" in capped.window
    assert capped.timestamp
