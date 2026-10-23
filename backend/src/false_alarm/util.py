"""Small helpers shared by ingest, connectors, and assessment."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Iterable


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc).replace(microsecond=0)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_datetime(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def minute_bucket(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    bucket = value.astimezone(timezone.utc).replace(second=0, microsecond=0)
    return utc_iso(bucket)


def is_internal_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        address.is_private or address.is_loopback or address.is_link_local or address.is_multicast
    )


def is_external_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return not is_internal_ip(value)


def ip_in_ranges(value: str | None, ranges: Iterable[str]) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    for item in ranges:
        text = str(item).strip()
        if not text:
            continue
        try:
            if "/" in text:
                if address in ipaddress.ip_network(text, strict=False):
                    return True
            elif address == ipaddress.ip_address(text):
                return True
        except ValueError:
            continue
    return False


def unique_strings(items: Iterable[str | None]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item is None:
            continue
        text = str(item).strip()
        if not text:
            continue
        key = text.casefold()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(text)
    return ordered
