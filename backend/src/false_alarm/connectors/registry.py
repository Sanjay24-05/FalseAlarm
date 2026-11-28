"""Which connector serves each log family, chosen by FALSE_ALARM_CONNECTOR."""

from __future__ import annotations

from false_alarm.connectors.base import Connector
from false_alarm.connectors.file_connector import FileConnector
from false_alarm.connectors.jsonl import JsonlConnector
from false_alarm.settings import Settings

FAMILIES = ("authentication", "firewall", "endpoint", "dns", "related_alerts", "threat_intel")


def build_registry(settings: Settings) -> dict[str, Connector]:
    if settings.connector == "jsonl":
        assert settings.logs_dir is not None  # Settings refuses jsonl without it.
        return {family: JsonlConnector(settings.logs_dir, family) for family in FAMILIES}
    return {family: FileConnector(settings.scenarios_dir, f"{family}.json", family) for family in FAMILIES}
