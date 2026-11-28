"""The contract every log source implements."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from false_alarm.connectors.file_connector import QueryRequest, QueryResult


@runtime_checkable
class Connector(Protocol):
    """Serves one log family (`source_type`).

    Events must use the normalized keys the rules read: timestamp, username, hostname, src_ip, dst_ip, dst_host,
    action, direction, bytes, severity, indicator, indicator_type, reputation, domains, and hashes.
    `normalize_log` and `select_events` in file_connector do that work for record-shaped sources.
    """

    source_type: str

    def query(self, request: QueryRequest, *, hard_cap: int = 200) -> QueryResult: ...
