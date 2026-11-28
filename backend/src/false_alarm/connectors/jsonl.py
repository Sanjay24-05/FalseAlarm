"""Reads JSON Lines exports: one `<source_type>.jsonl` file per log family in one directory."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from false_alarm.connectors.file_connector import QueryRequest, QueryResult, normalize_log, select_events

logger = logging.getLogger("false_alarm.connectors")
_CACHE: dict[tuple, tuple[list[dict[str, Any]], int]] = {}


def clear_jsonl_cache() -> None:
    _CACHE.clear()


class JsonlConnector:
    """One family from a SIEM export, such as `authentication.jsonl`. Lines that are not records are skipped."""

    def __init__(self, logs_dir: Path, source_type: str) -> None:
        self.path = Path(logs_dir) / f"{source_type}.jsonl"
        self.source_type = source_type

    def _load(self) -> tuple[list[dict[str, Any]], int]:
        """Usable events, and the count of non-blank lines that are not usable records."""
        if not self.path.exists():
            return [], 0
        stat = self.path.stat()
        key = (str(self.path), stat.st_mtime_ns, stat.st_size)
        cached = _CACHE.get(key)
        if cached is not None:
            return cached
        events: list[dict[str, Any]] = []
        skipped = 0
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    skipped += 1
                    continue
                normalized = normalize_log(self.source_type, record, "jsonl")
                if normalized is None:
                    skipped += 1
                else:
                    events.append(normalized)
        if skipped:
            logger.warning("Skipped %d line(s) in %s that are not usable records", skipped, self.path.name)
        _CACHE[key] = (events, skipped)
        return events, skipped

    def query(self, request: QueryRequest, *, hard_cap: int = 200) -> QueryResult:
        events, skipped = self._load()
        return select_events(
            f"jsonl:{self.source_type}", self.source_type, events, request, hard_cap, skipped=skipped
        )
