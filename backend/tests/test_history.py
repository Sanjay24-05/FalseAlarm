"""Past investigations of an alert can be found again."""

import pytest
from factories import alert_payload, login, use_logs
from fastapi.testclient import TestClient

from false_alarm.agent.loop import run_investigation, start_investigation
from false_alarm.ingest import ingest_alert
from false_alarm.main import create_app


@pytest.fixture
def client(monkeypatch, tmp_path):
    use_logs(monkeypatch, tmp_path, authentication=[login("13:50")])
    with TestClient(create_app()) as value:
        yield value


def test_an_alert_lists_its_investigations_newest_first(client):
    alert_id = ingest_alert(alert_payload()).alert["id"]
    first = run_investigation(alert_id)
    second = run_investigation(alert_id)
    running = start_investigation(alert_id)["id"]

    response = client.get(f"/api/alerts/{alert_id}/investigations")
    assert response.status_code == 200
    listed = response.json()["investigations"]
    assert [item["id"] for item in listed] == [running, second["id"], first["id"]]
    assert listed[0] == {
        "id": running,
        "status": "running",
        "stop_reason": None,
        "verdict": None,
        "created_at": listed[0]["created_at"],
        "updated_at": listed[0]["updated_at"],
    }
    assert listed[1]["verdict"] == second["assessment"]["verdict"]
    assert listed[1]["status"] == "completed"


def test_an_alert_with_no_runs_has_an_empty_history(client):
    alert_id = ingest_alert(alert_payload()).alert["id"]
    assert client.get(f"/api/alerts/{alert_id}/investigations").json() == {"investigations": []}


def test_an_unknown_alert_is_a_404(client):
    response = client.get("/api/alerts/nope/investigations")
    assert response.status_code == 404
    assert response.json() == {"detail": "Alert not found"}


def test_the_queue_links_each_verdict_to_its_investigation(client):
    alert_id = ingest_alert(alert_payload()).alert["id"]
    other_id = ingest_alert(alert_payload(name="Other rule")).alert["id"]
    run_investigation(alert_id)
    latest = run_investigation(alert_id)

    summaries = {item["id"]: item for item in client.get("/api/alerts").json()["alerts"]}
    assert summaries[alert_id]["verdict"] == latest["assessment"]["verdict"]
    assert summaries[alert_id]["latest_investigation_id"] == latest["id"]
    assert summaries[other_id]["latest_investigation_id"] is None
