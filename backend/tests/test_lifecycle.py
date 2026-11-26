"""Runs end in a final status even when the process does not, and one alert runs once at a time."""

from factories import alert_payload, login, use_logs
from fastapi.testclient import TestClient

from false_alarm.agent.loop import run_investigation, start_investigation
from false_alarm.db import get_investigation
from false_alarm.ingest import ingest_alert
from false_alarm.main import create_app


def _alert_id() -> str:
    return ingest_alert(alert_payload()).alert["id"]


def test_startup_fails_runs_left_running_by_a_previous_process(monkeypatch, tmp_path):
    use_logs(monkeypatch, tmp_path, authentication=[login("13:50")])
    orphan = start_investigation(_alert_id())["id"]
    with TestClient(create_app()):
        document = get_investigation(orphan)
    assert document["status"] == "failed"
    assert document["stop_reason"] == "interrupted"
    assert document["audit"][-1]["kind"] == "error"


def test_startup_leaves_finished_runs_alone(monkeypatch, tmp_path):
    use_logs(monkeypatch, tmp_path, authentication=[login("13:50")])
    finished = run_investigation(_alert_id())
    with TestClient(create_app()):
        assert get_investigation(finished["id"]) == finished


def test_a_second_start_returns_the_running_investigation(monkeypatch, tmp_path):
    use_logs(monkeypatch, tmp_path, authentication=[login("13:50")])
    alert_id = _alert_id()
    first = start_investigation(alert_id)
    second = start_investigation(alert_id)
    assert second["id"] == first["id"]
    assert first["created"] is True and second["created"] is False


def test_the_api_does_not_schedule_a_second_run(monkeypatch, tmp_path):
    use_logs(monkeypatch, tmp_path, authentication=[login("13:50")])
    alert_id = _alert_id()
    running = start_investigation(alert_id)["id"]
    ran = []
    monkeypatch.setattr("false_alarm.api.routes.execute_investigation", ran.append)
    with TestClient(create_app()) as client:
        # Startup marked the leftover run failed, so this request starts a new one.
        first = client.post("/api/investigations", json={"alert_id": alert_id})
        again = client.post("/api/investigations", json={"alert_id": alert_id})
    assert first.status_code == again.status_code == 202
    assert first.json()["id"] != running
    assert again.json() == {"id": first.json()["id"], "status": "running"}
    assert ran == [first.json()["id"]]


def test_a_new_run_can_start_after_the_last_one_finished(monkeypatch, tmp_path):
    use_logs(monkeypatch, tmp_path, authentication=[login("13:50")])
    alert_id = _alert_id()
    first = run_investigation(alert_id)
    assert start_investigation(alert_id)["id"] != first["id"]
