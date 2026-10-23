"""Connector package. v1 is file-backed; the query contract is adapter-ready."""

from false_alarm.connectors.file_connector import (
    FileConnector,
    QueryRequest,
    QueryResult,
    clear_connector_cache,
)

__all__ = ["FileConnector", "QueryRequest", "QueryResult", "clear_connector_cache"]
