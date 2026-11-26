"""A web page the analyst happens to visit cannot drive the local API."""

import json

import pytest
from factories import alert_payload
from fastapi.testclient import TestClient

from false_alarm.main import create_app
from false_alarm.service import list_alert_summaries
from false_alarm.settings import get_settings

BODY = json.dumps(alert_payload())
JSON = {"content-type": "application/json"}


def _client(monkeypatch, **env) -> TestClient:
    for key, value in env.items():
        monkeypatch.setenv(f"FALSE_ALARM_{key}", value)
    get_settings.cache_clear()
    return TestClient(create_app(), raise_server_exceptions=False)


@pytest.fixture
def client(monkeypatch):
    with _client(monkeypatch) as value:
        yield value


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8000", "127.0.0.1.evil.example"])
def test_an_unknown_host_header_is_refused(client, host):
    assert client.get("/api/alerts", headers={"host": host}).status_code == 400


@pytest.mark.parametrize("host", ["127.0.0.1:8000", "localhost:8000", "127.0.0.1"])
def test_local_host_headers_are_accepted(client, host):
    assert client.get("/api/alerts", headers={"host": host}).status_code == 200


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "http://localhost:5174"])
@pytest.mark.parametrize(
    "send",
    [
        lambda c, h: c.post("/api/alerts", content=BODY, headers={**JSON, **h}),
        lambda c, h: c.post("/api/alerts/upload", files={"file": ("a.json", BODY)}, headers=h),
        lambda c, h: c.post("/api/scenarios/account_compromise/load", headers=h),
        lambda c, h: c.post("/api/investigations", json={"alert_id": "x"}, headers=h),
    ],
    ids=["alert", "upload", "scenario", "investigation"],
)
def test_a_write_from_a_foreign_origin_is_refused(client, origin, send):
    response = send(client, {"origin": origin})
    assert response.status_code == 403
    assert list_alert_summaries() == []


@pytest.mark.parametrize("headers", [{"origin": "http://localhost:5173"}, {"origin": "http://127.0.0.1:5173"}, {}])
def test_writes_from_the_console_or_without_an_origin_are_accepted(client, headers):
    assert client.post("/api/alerts", content=BODY, headers={**JSON, **headers}).status_code == 201


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded", None])
def test_an_alert_body_that_is_not_json_is_refused(client, content_type):
    headers = {"content-type": content_type} if content_type else {}
    response = client.post("/api/alerts", content=BODY, headers=headers)
    assert response.status_code == 415
    assert response.json() == {"errors": [{"field": "body", "message": "Content-Type must be application/json"}]}
    assert list_alert_summaries() == []


def test_json_with_a_charset_is_accepted(client):
    headers = {"content-type": "application/json; charset=utf-8"}
    assert client.post("/api/alerts", content=BODY, headers=headers).status_code == 201


def test_the_console_preflight_is_answered_without_credentials(client):
    response = client.options(
        "/api/alerts",
        headers={"origin": "http://localhost:5173", "access-control-request-method": "POST"},
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-credentials" not in response.headers


def test_no_token_is_required_by_default(client):
    assert client.get("/api/alerts").status_code == 200


@pytest.mark.parametrize("authorization", [None, "Bearer wrong", "Bearer s3cret-token ", "Basic s3cret-token", "s3cret-token"])
def test_a_configured_token_is_required(monkeypatch, authorization):
    with _client(monkeypatch, API_TOKEN="s3cret-token") as client:
        headers = {"authorization": authorization} if authorization else {}
        response = client.get("/api/alerts", headers=headers)
        assert response.status_code == 401
        assert response.json() == {"detail": "Missing or invalid API token"}
        assert "s3cret" not in response.text


def test_the_right_token_is_accepted(monkeypatch):
    with _client(monkeypatch, API_TOKEN="s3cret-token") as client:
        headers = {"authorization": "Bearer s3cret-token"}
        assert client.get("/api/alerts", headers=headers).status_code == 200
        assert client.post("/api/alerts", content=BODY, headers={**JSON, **headers}).status_code == 201


def test_the_token_also_guards_the_api_docs(monkeypatch):
    with _client(monkeypatch, API_TOKEN="s3cret-token") as client:
        assert client.get("/openapi.json").status_code == 401
