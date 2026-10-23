"""Allowlisted tool execution. Unknown names raise before any query runs."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from false_alarm.agent.allowlist import ALLOWED_TOOLS
from false_alarm.connectors.file_connector import FileConnector, QueryRequest
from false_alarm.errors import UnknownToolError

_QUERY_TOOLS = {
    "query_authentication": ("authentication.json", "authentication"),
    "query_firewall": ("firewall.json", "firewall"),
    "query_endpoint": ("endpoint.json", "endpoint"),
    "query_dns": ("dns.json", "dns"),
    "query_related_alerts": ("related_alerts.json", "related_alerts"),
    "lookup_threat_intel": ("threat_intel.json", "threat_intel"),
}


def execute_tool(
    name: str,
    arguments: dict | None = None,
    *,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    scenarios_dir: Path | None = None,
    max_events: int = 200,
) -> dict:
    if name not in ALLOWED_TOOLS:
        raise UnknownToolError(name)
    arguments = arguments or {}
    if name == "finish":
        return {"status": "completed", "kind": "finish", "events": [], "result": None, "source_type": None}
    if name == "expand_time_window":
        return {"status": "completed", "kind": "expand", "events": [], "result": None, "source_type": None}
    if window_start is None or window_end is None or scenarios_dir is None:
        raise TypeError("query tools require a window and a scenarios directory")
    filename, source_type = _QUERY_TOOLS[name]
    try:
        requested = int(arguments.get("limit", max_events))
    except (TypeError, ValueError):
        requested = max_events
    iocs = arguments.get("iocs") or []
    if isinstance(iocs, str):
        iocs = [iocs]
    request = QueryRequest(
        iocs=[str(item) for item in iocs if item],
        user=str(arguments["user"]) if arguments.get("user") else None,
        host=str(arguments["host"]) if arguments.get("host") else None,
        start=window_start,
        end=window_end,
        limit=min(requested, max_events),
    )
    result = FileConnector(scenarios_dir, filename, source_type).query(request, hard_cap=max_events)
    return {
        "status": "completed",
        "kind": "query",
        "events": result.events,
        "result": result.model_dump(),
        "source_type": source_type,
    }
