"""Partial alerts warn, empty alerts fail, and fingerprints collapse to the minute."""

from false_alarm.ingest import ingest_alert


def _base(**overrides):
    payload = {
        "source": "demo-siem",
        "name": "Suspicious sign-in",
        "description": "A sign-in was observed.",
        "severity": "medium",
        "detected_at": "2026-04-12T14:32:10Z",
        "src_ip": "203.0.113.10",
        "username": "jsmith",
        "hostname": "WS-1",
    }
    payload.update(overrides)
    return payload


def test_empty_payload_returns_field_errors():
    result = ingest_alert({})
    assert result.status_code == 422
    fields = {item["field"] for item in result.errors}
    assert {"source", "name", "detected_at"} <= fields
    assert all("message" in item for item in result.errors)
    assert result.alert is None


def test_non_object_is_unusable():
    result = ingest_alert(["not", "an", "alert"])
    assert result.status_code == 422
    assert result.errors[0]["field"] == "body"


def test_partial_alert_is_accepted_with_warnings():
    result = ingest_alert(
        {"source": "demo-siem", "name": "Sparse rule", "detected_at": "2026-04-12T01:00:00Z"}
    )
    assert result.errors == []
    assert result.status_code == 201
    assert result.duplicate is False
    assert result.alert["username"] is None
    assert result.warnings
    assert any(item["field"] == "username" for item in result.warnings)


def test_invalid_severity_is_rejected():
    result = ingest_alert(_base(severity="apocalyptic"))
    assert result.status_code == 422
    assert any(item["field"] == "severity" for item in result.errors)


def test_duplicate_collapses_to_the_detection_minute():
    first = ingest_alert(_base(detected_at="2026-04-12T14:32:10Z"))
    second = ingest_alert(_base(detected_at="2026-04-12T14:32:50Z", description="different text"))
    third = ingest_alert(_base(detected_at="2026-04-12T14:33:00Z"))
    assert first.status_code == 201
    assert second.status_code == 200
    assert second.duplicate is True
    assert second.alert["id"] == first.alert["id"]
    assert third.duplicate is False
    assert third.alert["id"] != first.alert["id"]
