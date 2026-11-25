"""Malformed input is a 422 with the documented shape, and it stores nothing."""

import json
import threading

import pytest
from factories import alert_payload
from fastapi.testclient import TestClient

from false_alarm.db import init_db
from false_alarm.ingest import ingest_alert
from false_alarm.main import create_app
from false_alarm.service import list_alert_summaries


@pytest.fixture
def client():
    with TestClient(create_app(), raise_server_exceptions=False) as value:
        yield value


def _body(**overrides) -> bytes:
    return json.dumps(alert_payload(**overrides)).encode()


HOSTILE = {
    "invalid-utf8": b'{"name": "\xff"}',
    "lone-surrogate": _body(name="\ud800"),
    "lone-surrogate-key": _body(raw={"\ud800": 1}),
    "date-overflow": _body(detected_at="0001-01-01T00:00:00+14:00"),
    "date-too-early": _body(detected_at="0001-01-01T01:00:00Z"),
    "date-too-late": _body(detected_at="9999-12-31T23:59:59Z"),
    "unparseable-nesting": b'{"raw": ' + b"[" * 100_000 + b"]" * 100_000 + b"}",
    "deep-nesting": _body(raw={"x": "SENTINEL"}).replace(b'"SENTINEL"', b"[" * 500 + b"]" * 500),
    "nan": _body(raw={"x": "SENTINEL"}).replace(b'"SENTINEL"', b"NaN"),
    "infinity": _body(raw={"x": "SENTINEL"}).replace(b'"SENTINEL"', b"1e999"),
    "huge-integer": _body(raw={"x": "SENTINEL"}).replace(b'"SENTINEL"', b"9" * 5000),
}


@pytest.mark.parametrize("body", HOSTILE.values(), ids=HOSTILE.keys())
def test_hostile_alert_is_rejected_and_not_stored(client, body):
    response = client.post("/api/alerts", content=body, headers={"content-type": "application/json"})
    assert response.status_code == 422
    assert list(response.json()) == ["errors"]
    assert all(set(item) == {"field", "message"} for item in response.json()["errors"])
    assert list_alert_summaries() == []


@pytest.mark.parametrize("body", HOSTILE.values(), ids=HOSTILE.keys())
def test_hostile_upload_is_not_a_server_error(client, body):
    response = client.post("/api/alerts/upload", files={"file": ("a.json", body)})
    assert response.status_code in (200, 422)
    assert list_alert_summaries() == []


def test_one_hostile_item_does_not_fail_the_upload(client):
    batch = b"[" + _body(name="good") + b"," + HOSTILE["nan"] + b"," + HOSTILE["lone-surrogate"] + b"]"
    results = client.post("/api/alerts/upload", files={"file": ("a.json", batch)}).json()["results"]
    assert ["alert" in item for item in results] == [True, False, False]


@pytest.mark.parametrize(
    "send",
    [
        lambda c: c.post("/api/investigations", json={}),
        lambda c: c.post("/api/investigations", json={"alert_id": 5}),
        lambda c: c.post("/api/alerts/upload"),
    ],
)
def test_framework_validation_uses_the_error_contract(client, send):
    response = send(client)
    assert response.status_code == 422
    assert list(response.json()) == ["errors"]
    assert all(item["field"] and item["message"] for item in response.json()["errors"])


def test_concurrent_identical_alerts_store_one_and_report_duplicates():
    init_db()
    results = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        try:
            results.append(ingest_alert(alert_payload()))
        except Exception as exc:
            results.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert [item for item in results if isinstance(item, Exception)] == []
    assert sorted(item.duplicate for item in results) == [False] + [True] * 7
    assert len({item.alert["id"] for item in results}) == 1


def test_concurrent_alerts_sharing_an_id_store_one_and_reject_the_rest():
    init_db()
    results = []
    barrier = threading.Barrier(6)

    def worker(index):
        barrier.wait()
        try:
            results.append(ingest_alert(alert_payload(id="shared", name=f"rule {index}")))
        except Exception as exc:
            results.append(exc)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert [item for item in results if isinstance(item, Exception)] == []
    assert sum(1 for item in results if not item.errors) == 1
