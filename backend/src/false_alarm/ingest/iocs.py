"""Indicator extraction. Hashes are taken longest-first so they are not split."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

from false_alarm.domain.models import IOC
from false_alarm.util import canonical_ip

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256_RE = re.compile(r"\b[A-Fa-f0-9]{64}\b")
SHA1_RE = re.compile(r"\b[A-Fa-f0-9]{40}\b")
MD5_RE = re.compile(r"\b[A-Fa-f0-9]{32}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b"
)
IPV6_RE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
# File extensions that are not top-level domains. Real ccTLDs such as .sh, .py, .zip and .md are kept.
_FILE_EXTENSIONS = frozenset(
    {
        "asp", "aspx", "bak", "bat", "bin", "bmp", "cfg", "cmd", "conf", "csv", "dat", "db", "dll", "doc",
        "docm", "docx", "exe", "gif", "gz", "hta", "htm", "html", "img", "ini", "iso", "jar", "jpeg", "jpg",
        "js", "jse", "json", "jsp", "lnk", "log", "msi", "pdf", "php", "png", "ppt", "pptx", "rar", "rtf", "scr",
        "sqlite", "svg", "sys", "tar", "tmp", "txt", "vbs", "xls", "xlsm", "xlsx", "xml", "yaml", "yml",
    }
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


def _ipv6(raw: str) -> str | None:
    if "::" not in raw and raw.count(":") != 7:
        return None
    try:
        address = ipaddress.IPv6Address(raw)
    except ipaddress.AddressValueError:
        return None
    return None if address.is_unspecified else str(address)


def _url_host(url: str) -> str:
    host = url.split("://", 1)[1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    return host.rsplit("@", 1)[-1].split(":", 1)[0].lower().rstrip(".")


def extract_iocs_from_text(text: str, *, not_domains: Iterable[str] = ()) -> list[IOC]:
    """Extract IOCs from free text. Occupied hash spans are not re-read as shorter hashes.

    A URL contributes only its host as a domain. Names that end in a file extension, and the
    values in `not_domains` (such as the alert's username), are not domains.
    """
    if not text:
        return []
    excluded = {item.casefold() for item in not_domains if item}
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
    take(IPV6_RE, "ipv6", _ipv6)
    take(SHA256_RE, "sha256", lower)
    take(SHA1_RE, "sha1", lower)
    take(MD5_RE, "md5", lower)
    url_hosts = [(match.start(), match.end(), _url_host(match.group(0))) for match in URL_RE.finditer(text)]
    for match in DOMAIN_RE.finditer(text):
        value = match.group(0).lower().rstrip(".")
        if value.casefold() in excluded or value.rsplit(".", 1)[-1] in _FILE_EXTENSIONS:
            continue
        inside_url = [host for left, right, host in url_hosts if left <= match.start() and match.end() <= right]
        if inside_url:
            if value != inside_url[0]:
                continue
        elif _overlaps(match.start(), match.end(), occupied):
            # Inside an email the domain is an indicator too; inside a hash or an address it is not.
            fragment = next(text[left:right] for left, right in occupied if left <= match.start() < right)
            if "@" not in fragment:
                continue
        _push(found, seen, "domain", value)
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
        parsed = canonical_ip(payload.get(key))
        if parsed:
            add("ipv4" if ":" not in parsed else "ipv6", parsed)
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
    username = payload.get("username") if isinstance(payload.get("username"), str) else ""
    for text in text_parts:
        for ioc in extract_iocs_from_text(text, not_domains=[username]):
            add(ioc.type, ioc.value)
    return found
