"""HTTP shapes used by the console."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from false_alarm.main import create_app


def _client():
    return TestClient(create_app())


def test_malformed_and_duplicate_alerts_use_the_contract():
    with _client() as client:
        empty = client.post("/api/alerts", json={})
        assert empty.status_code == 422
        body = empty.json()
        assert "detail" not in body
        fields = {item["field"] for item in body["errors"]}
        assert {"source", "name", "detected_at"} <= fields
        assert all("message" in item for item in body["errors"])

        missing = client.get("/api/alerts/does-not-exist")
        assert missing.status_code == 404
        assert "detail" in missing.json()

        payload = {
            "source": "demo-siem",
            "name": "Uploaded rule",
            "description": "One alert.",
            "severity": "low",
            "detected_at": "2026-05-01T08:00:00Z",
            "src_ip": "203.0.113.80",
            "username": "uploader",
            "hostname": "WS-UP",
            "mitre_techniques": ["T1078"],
            "raw": {},
        }
        created = client.post("/api/alerts", json=payload)
        assert created.status_code == 201
        assert created.json()["duplicate"] is False
        again = client.post("/api/alerts", json=payload)
        assert again.status_code == 200
        assert again.json()["duplicate"] is True
        assert again.json()["alert"]["id"] == created.json()["alert"]["id"]

        upload = client.post(
            "/api/alerts/upload",
            files={"file": ("alerts.json", json.dumps([payload, payload]).encode("utf-8"), "application/json")},
        )
        assert upload.status_code == 200
        results = upload.json()["results"]
        assert results[0]["duplicate"] is True
        assert results[1]["duplicate"] is True

        queued = client.get("/api/alerts")
        assert queued.status_code == 200
        summary = next(item for item in queued.json()["alerts"] if item["id"] == created.json()["alert"]["id"])
        assert summary["username"] == "uploader"
        assert summary["verdict"] is None


def test_scenario_load_and_background_investigation():
    with _client() as client:
        catalog = client.get("/api/scenarios")
        assert catalog.status_code == 200
        ids = {item["id"] for item in catalog.json()["scenarios"]}
        assert {"account_compromise", "benign_vpn_login"} <= ids

        missing = client.post("/api/scenarios/not-a-scenario/load")
        assert missing.status_code == 404
        assert "detail" in missing.json()

        loaded = client.post("/api/scenarios/benign_vpn_login/load")
        assert loaded.status_code == 201
        alert_id = loaded.json()["alert"]["id"]
        absent = client.post("/api/investigations", json={"alert_id": "missing-alert"})
        assert absent.status_code == 404

        started = client.post("/api/investigations", json={"alert_id": alert_id})
        assert started.status_code == 202
        assert started.json()["status"] == "running"
        investigation_id = started.json()["id"]
        fetched = client.get(f"/api/investigations/{investigation_id}")
        assert fetched.status_code == 200
        document = fetched.json()
        assert document["status"] == "completed"
        assert document["alert_id"] == alert_id
        assert document["assessment"]["verdict"] == "likely_benign"
        assert document["assessment"]["escalate"] is False
        assert set(document["report"]) >= {
            "incident_summary",
            "alert_details",
            "triage",
            "executive_explanation",
            "timeline",
            "evidence",
            "correlated_indicators",
            "threat_intelligence",
            "attack_sequence",
            "confidence_and_gaps",
            "recommended_actions",
            "escalation",
            "audit_trail",
        }
        assert "metrics" in document
        assert document["metrics"]["tool_call_count"] >= 1
