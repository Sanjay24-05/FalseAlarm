"""Isolate each test on its own SQLite file and keep the planner offline."""

from __future__ import annotations

import pytest

from false_alarm.connectors.file_connector import clear_connector_cache
from false_alarm.scenarios import load_catalog
from false_alarm.settings import get_settings


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("FALSE_ALARM_DB_PATH", str(tmp_path / "false_alarm.db"))
    monkeypatch.setenv("FALSE_ALARM_LLM_ENABLED", "false")
    # The test client sends Host: testserver.
    monkeypatch.setenv("FALSE_ALARM_ALLOWED_HOSTS", "127.0.0.1,localhost,testserver")
    monkeypatch.delenv("FALSE_ALARM_API_TOKEN", raising=False)
    monkeypatch.setenv("FALSE_ALARM_MAX_TOOL_CALLS", "12")
    monkeypatch.setenv("FALSE_ALARM_MAX_EVENTS", "200")
    monkeypatch.setenv("FALSE_ALARM_MAX_WINDOW_EXPANSIONS", "2")
    monkeypatch.setenv("FALSE_ALARM_MAX_SECONDS", "60")
    get_settings.cache_clear()
    clear_connector_cache()
    load_catalog.cache_clear()
    yield
    get_settings.cache_clear()
    clear_connector_cache()
    load_catalog.cache_clear()
