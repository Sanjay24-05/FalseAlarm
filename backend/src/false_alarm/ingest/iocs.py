"""Indicator extraction. Hashes are taken longest-first so they are not split."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

from false_alarm.domain.models import IOC

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256_RE = re.compile(r"\b[A-Fa-f0-9]{64}\b")
SHA1_RE = re.compile(r"\b[A-Fa-f0-9]{40}\b")
MD5_RE = re.compile(r"\b[A-Fa-f0-9]{32}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b"
)
HOSTNAME_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9-]*\d[A-Za-z0-9-]*\b")

_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


def _overlaps(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(not (end <= left or start >= right) for left, right in spans)


def _push(found: list[IOC], seen: set[tuple[str, str]], ioc_type: str, value: str) -> None:
    key = (ioc_type, value.casefold())
    if key in seen or not value:
        return
    seen.add(key)
    found.append(IOC(type=ioc_type, value=value))  # type: ignore[arg-type]


def _valid_ipv4(value: str) -> str | None:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return None
    return str(address)


def extract_iocs_from_text(text: str) -> list[IOC]:
    """Extract IOCs from free text. Occupied hash spans are not re-read as shorter hashes."""
    if not text:
        return []
    found: list[IOC] = []
    seen: set[tuple[str, str]] = set()
    occupied: list[tuple[int, int]] = []

    def take(pattern: re.Pattern[str], ioc_type: str, transform) -> None:
        for match in pattern.finditer(text):
            if _overlaps(match.start(), match.end(), occupied):
                continue
            value = transform(match.group(0))
            if not value:
                continue
            _push(found, seen, ioc_type, value)
            occupied.append((match.start(), match.end()))

    def url_value(raw: str) -> str:
        return raw.rstrip(".,);]>'\"")

    def ipv4_value(raw: str) -> str | None:
        return _valid_ipv4(raw)

    def lower(raw: str) -> str:
        return raw.lower()

    take(URL_RE, "url", url_value)
    take(EMAIL_RE, "email", lower)
    take(IPV4_RE, "ipv4", ipv4_value)
    take(SHA256_RE, "sha256", lower)
    take(SHA1_RE, "sha1", lower)
    take(MD5_RE, "md5", lower)
    # Domains inside URLs and emails are useful indicators, so they are not masked.
    for match in DOMAIN_RE.finditer(text):
        if _overlaps(match.start(), match.end(), occupied):
            # Allow domains that sit inside a URL or email, but not inside a hash.
            covered_by_hash = False
            for left, right in occupied:
                if match.start() >= left and match.end() <= right:
                    fragment = text[left:right]
                    if re.fullmatch(r"[A-Fa-f0-9]{32,64}", fragment):
                        covered_by_hash = True
                        break
            if covered_by_hash:
                continue
        _push(found, seen, "domain", match.group(0).lower().rstrip("."))
    for match in HOSTNAME_RE.finditer(text):
        if _overlaps(match.start(), match.end(), occupied):
            continue
        _push(found, seen, "hostname", match.group(0))
    return found


def hash_type(value: str) -> str | None:
    token = value.strip().lower()
    if re.fullmatch(r"[a-f0-9]{32,64}", token) and len(token) in _HASH_LENGTHS:
        return _HASH_LENGTHS[len(token)]
    return None


def _strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def extract_iocs(payload: dict) -> list[IOC]:
    """Extract IOCs from structured alert fields and from free text."""
    found: list[IOC] = []
    seen: set[tuple[str, str]] = set()

    def add(ioc_type: str, value: str) -> None:
        _push(found, seen, ioc_type, value)

    for key in ("src_ip", "dst_ip"):
        raw = payload.get(key)
        if isinstance(raw, str):
            parsed = _valid_ipv4(raw.strip())
            if parsed:
                add("ipv4", parsed)
    hostname = payload.get("hostname")
    if isinstance(hostname, str) and hostname.strip():
        add("hostname", hostname.strip())
    for item in payload.get("file_hashes") or []:
        if isinstance(item, str) and hash_type(item):
            add(hash_type(item) or "md5", item.strip().lower())
    for item in payload.get("domains") or []:
        if isinstance(item, str) and item.strip():
            add("domain", item.strip().lower())
    for item in payload.get("urls") or []:
        if isinstance(item, str) and item.strip():
            add("url", item.strip())
    text_parts: list[str] = []
    for key in ("name", "description", "username", "hostname"):
        raw = payload.get(key)
        if isinstance(raw, str):
            text_parts.append(raw)
    raw_object = payload.get("raw")
    if isinstance(raw_object, dict):
        text_parts.extend(_strings(raw_object))
    for text in text_parts:
        for ioc in extract_iocs_from_text(text):
            add(ioc.type, ioc.value)
    return found
