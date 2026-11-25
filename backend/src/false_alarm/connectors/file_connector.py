"""One file-backed query interface for every log and reputation source."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from false_alarm.scenarios import scenario_dirs
from false_alarm.util import parse_datetime, unique_strings, utc_iso, utc_now

_CACHE: dict[tuple, list[dict[str, Any]]] = {}
_ACTION_ALIASES = {
    "fail": "failure",
    "failed": "failure",
    "failure": "failure",
    "success": "success",
    "succeeded": "success",
    "successful": "success",
}


class QueryRequest(BaseModel):
    """Filters a connector must be able to honor. Later SIEM adapters implement this too."""

    model_config = ConfigDict(extra="forbid")

    iocs: list[str] = Field(default_factory=list)
    user: str | None = None
    host: str | None = None
    start: datetime
    end: datetime
    limit: int = 200


class QueryResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    query: dict[str, Any]
    window: dict[str, str]
    timestamp: str
    events: list[dict[str, Any]]
    truncated: bool


def clear_connector_cache() -> None:
    _CACHE.clear()


def _blank_event(scenario: str, timestamp: str | None = None) -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "scenario": scenario,
        "username": None,
        "hostname": None,
        "src_ip": None,
        "dst_ip": None,
        "dst_host": None,
        "action": None,
        "direction": None,
        "bytes": None,
        "domains": [],
        "hashes": [],
        "name": None,
        "severity": None,
        "indicator": None,
        "indicator_type": None,
        "reputation": None,
        "query_name": None,
        "resolved_ip": None,
    }


def _text(record: dict, *keys: str) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def normalize_log(source_type: str, record: dict, scenario: str) -> dict[str, Any] | None:
    if not isinstance(record, dict):
        return None
    if source_type == "threat_intel":
        indicator = _text(record, "indicator")
        if not indicator:
            return None
        event = _blank_event(scenario, None)
        event["indicator"] = indicator
        event["indicator_type"] = (_text(record, "type", "indicator_type") or "").lower() or None
        event["reputation"] = (_text(record, "reputation") or "unknown").lower()
        return event

    raw_time = record.get("timestamp")
    if not isinstance(raw_time, str):
        return None
    try:
        timestamp = utc_iso(parse_datetime(raw_time))
    except ValueError:
        return None
    event = _blank_event(scenario, timestamp)
    event["username"] = _text(record, "username", "user")
    event["hostname"] = _text(record, "hostname", "host", "src_host")
    event["src_ip"] = _text(record, "src_ip")
    event["dst_host"] = _text(record, "dst_host")
    event["resolved_ip"] = _text(record, "resolved_ip")
    event["dst_ip"] = _text(record, "dst_ip") or event["resolved_ip"]
    action = _text(record, "action")
    if action:
        event["action"] = _ACTION_ALIASES.get(action.lower(), action.lower())
    direction = _text(record, "direction")
    event["direction"] = direction.lower() if direction else None
    if record.get("bytes") is not None:
        try:
            event["bytes"] = int(record["bytes"])
        except (TypeError, ValueError):
            event["bytes"] = None
    domains: list[str | None] = []
    query_name = _text(record, "query", "query_name", "domain")
    event["query_name"] = query_name
    if query_name:
        domains.append(query_name.lower())
    for item in record.get("domains") or []:
        if isinstance(item, str):
            domains.append(item.lower())
    event["domains"] = unique_strings(domains)
    hashes: list[str | None] = []
    file_hash = _text(record, "file_hash")
    if file_hash:
        hashes.append(file_hash.lower())
    for item in record.get("hashes") or []:
        if isinstance(item, str):
            hashes.append(item.lower())
    event["hashes"] = unique_strings(hashes)
    event["name"] = _text(record, "name")
    severity = _text(record, "severity")
    event["severity"] = severity.lower() if severity else None
    return event


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _host_values(event: dict[str, Any]) -> set[str]:
    values = set()
    for key in ("hostname", "dst_host"):
        raw = event.get(key)
        if isinstance(raw, str) and raw:
            values.add(raw.casefold())
    return values


def _ioc_values(event: dict[str, Any]) -> set[str]:
    values: list[str | None] = []
    for key in ("src_ip", "dst_ip", "resolved_ip", "hostname", "dst_host", "indicator", "query_name"):
        raw = event.get(key)
        if isinstance(raw, str):
            values.append(raw)
    values.extend(event.get("domains") or [])
    values.extend(event.get("hashes") or [])
    return {item.casefold() for item in unique_strings(values)}


def event_matches(event: dict[str, Any], request: QueryRequest, *, apply_time: bool) -> bool:
    if apply_time:
        raw_time = event.get("timestamp")
        if not isinstance(raw_time, str):
            return False
        try:
            observed = parse_datetime(raw_time)
        except ValueError:
            return False
        if observed < _aware(request.start) or observed > _aware(request.end):
            return False
    has_filter = bool(request.user or request.host or request.iocs)
    if not has_filter:
        return True
    if request.user and (event.get("username") or "").casefold() == request.user.casefold():
        return True
    if request.host and request.host.casefold() in _host_values(event):
        return True
    if request.iocs:
        wanted = {item.casefold() for item in request.iocs if item}
        if wanted & _ioc_values(event):
            return True
    return False


class FileConnector:
    """Reads one log family from every scenario directory."""

    def __init__(self, scenarios_dir: Path, filename: str, source_type: str) -> None:
        self.scenarios_dir = scenarios_dir
        self.filename = filename
        self.source_type = source_type

    def _load(self) -> list[dict[str, Any]]:
        signature: list[tuple[str, int, int]] = []
        files: list[tuple[Path, str]] = []
        for directory in scenario_dirs(self.scenarios_dir):
            path = directory / self.filename
            if not path.exists():
                continue
            stat = path.stat()
            signature.append((str(path), stat.st_mtime_ns, stat.st_size))
            files.append((path, directory.name))
        key = (str(self.scenarios_dir), self.filename, tuple(signature))
        cached = _CACHE.get(key)
        if cached is not None:
            return cached
        events: list[dict[str, Any]] = []
        for path, scenario_name in files:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, list):
                continue
            for record in payload:
                normalized = normalize_log(self.source_type, record, scenario_name)
                if normalized is not None:
                    events.append(normalized)
        _CACHE[key] = events
        return events

    def query(self, request: QueryRequest, *, hard_cap: int = 200) -> QueryResult:
        effective = max(0, min(int(request.limit), int(hard_cap)))
        apply_time = self.source_type != "threat_intel"
        matched = [
            event
            for event in self._load()
            if event_matches(event, request, apply_time=apply_time)
        ]
        if self.source_type == "threat_intel":
            wanted = {item.casefold() for item in request.iocs if item}
            matched = [
                event
                for event in matched
                if wanted and str(event.get("indicator") or "").casefold() in wanted
            ]
            matched.sort(key=lambda event: str(event.get("indicator") or ""))
        else:
            matched.sort(key=lambda event: (str(event.get("timestamp") or ""), str(event.get("username") or "")))
        truncated = len(matched) > effective
        # Keep the newest events: the activity an alert is about comes after the routine activity.
        keep_newest = truncated and self.source_type != "threat_intel"
        chosen = matched[len(matched) - effective :] if keep_newest else matched[:effective]
        observed = utc_iso(utc_now())
        if self.source_type == "threat_intel":
            stamped = []
            for event in chosen:
                copy = dict(event)
                copy["timestamp"] = observed
                stamped.append(copy)
            chosen = stamped
        start = utc_iso(_aware(request.start))
        end = utc_iso(_aware(request.end))
        return QueryResult(
            source=f"file:{self.source_type}",
            query={
                "iocs": list(request.iocs),
                "user": request.user,
                "host": request.host,
                "start": start,
                "end": end,
                "limit": effective,
            },
            window={"start": start, "end": end},
            timestamp=observed,
            events=chosen,
            truncated=truncated,
        )
