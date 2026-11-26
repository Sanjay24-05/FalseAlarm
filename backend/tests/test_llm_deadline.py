"""Model calls fit inside the time budget, and their failures are visible without leaking secrets."""

import logging
import time

import pytest
from factories import investigate, login, use_logs

from false_alarm.planner import llm
from false_alarm.settings import get_settings


@pytest.fixture
def slow_model(monkeypatch, tmp_path):
    use_logs(monkeypatch, tmp_path, authentication=[login("13:50")])
    for key, value in {"ENABLED": "1", "BASE_URL": "http://llm.invalid", "API_KEY": "sekret-key", "MODEL": "m"}.items():
        monkeypatch.setenv(f"FALSE_ALARM_LLM_{key}", value)
    monkeypatch.setenv("FALSE_ALARM_MAX_SECONDS", "1")
    get_settings.cache_clear()
    timeouts = []

    def hang(_summary, _settings, *, timeout):
        timeouts.append(timeout)
        time.sleep(timeout)
        raise TimeoutError("read timed out for https://llm.invalid?key=sekret-key")

    monkeypatch.setattr(llm, "chat_complete", hang)
    return timeouts


def test_a_hanging_model_cannot_outlast_the_time_budget(slow_model):
    started = time.monotonic()
    result = investigate()
    assert time.monotonic() - started < 1.6
    assert result["stop_reason"] in {"time_budget", "completed"}
    assert slow_model, "the model was never called"
    assert all(0 < timeout <= 1 for timeout in slow_model)


def test_model_failures_are_audited_and_logged_by_type_only(slow_model, caplog):
    with caplog.at_level(logging.WARNING, logger="false_alarm.planner"):
        result = investigate()
    planner = [entry["details"] for entry in result["audit"] if entry["kind"] == "planner"]
    assert planner[0]["source"] == "playbook_fallback"
    assert planner[0]["llm_errors"] == ["TimeoutError", "DeadlineReached"]
    assert "TimeoutError" in caplog.text
    assert "sekret" not in caplog.text and "sekret" not in str(result)
