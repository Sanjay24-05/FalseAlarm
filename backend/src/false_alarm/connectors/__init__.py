"""Log sources. Each family is served by a Connector; FALSE_ALARM_CONNECTOR picks the implementation."""

from false_alarm.connectors.base import Connector
from false_alarm.connectors.file_connector import (
    FileConnector,
    QueryRequest,
    QueryResult,
    clear_connector_cache,
    select_events,
)
from false_alarm.connectors.jsonl import JsonlConnector, clear_jsonl_cache
from false_alarm.connectors.registry import FAMILIES, build_registry

__all__ = [
    "FAMILIES",
    "Connector",
    "FileConnector",
    "JsonlConnector",
    "QueryRequest",
    "QueryResult",
    "build_registry",
    "clear_connector_cache",
    "clear_jsonl_cache",
    "select_events",
]
