"""Alert normalization, validation, IOC attachment, and fingerprint dedupe."""

from __future__ import annotations

import hashlib
import math
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any, get_args
from uuid import uuid4

from false_alarm.domain.models import Alert, Severity
from false_alarm.ingest.iocs import extract_iocs
from false_alarm.db import alert_id_exists, get_alert_row_by_fingerprint, save_alert
from false_alarm.util import canonical_ip, minute_bucket, parse_datetime, utc_iso

SEVERITIES = frozenset(get_args(Severity))
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_MAX_DEPTH = 64
# Room on both sides for the investigation window and its expansions.
_YEARS = range(1970, 3000)


@dataclass
class IngestResult:
    alert: dict[str, Any] | None = None
    warnings: list[dict[str, str]] = field(default_factory=list)
    duplicate: bool = False
    errors: list[dict[str, str]] = field(default_factory=list)

    @property
    def status_code(self) -> int:
        if self.errors:
            return 422
        return 200 if self.duplicate else 201

    def public(self) -> dict[str, Any]:
        return {
            "alert": self.alert,
            "warnings": self.warnings,
            "duplicate": self.duplicate,
        }


def _error(errors: list[dict[str, str]], field_name: str, message: str) -> None:
    errors.append({"field": field_name, "message": message})


def _warn(warnings: list[dict[str, str]], field_name: str, message: str) -> None:
    warnings.append({"field": field_name, "message": message})


def _required_string(payload: dict, key: str, errors: list[dict[str, str]]) -> str | None:
    if key not in payload or payload[key] is None:
        _error(errors, key, f"{key} is required")
        return None
    value = payload[key]
    if not isinstance(value, str):
        _error(errors, key, f"{key} must be a string")
        return None
    text = value.strip()
    if not text:
        _error(errors, key, f"{key} is required")
        return None
    return text


def _optional_string(
    payload: dict,
    key: str,
    warnings: list[dict[str, str]],
    errors: list[dict[str, str]],
    *,
    warn_if_missing: bool,
) -> str | None:
    if key not in payload or payload[key] is None:
        if warn_if_missing:
            _warn(warnings, key, f"{key} was not provided")
        return None
    value = payload[key]
    if not isinstance(value, str):
        _error(errors, key, f"{key} must be a string")
        return None
    text = value.strip()
    if not text:
        if warn_if_missing:
            _warn(warnings, key, f"{key} was empty")
        return None
    return text


def _ip_field(payload: dict, key: str, warnings: list[dict[str, str]], errors: list[dict[str, str]]) -> str | None:
    """An address in canonical form. A value that is not an address is dropped with a warning, not an error."""
    text = _optional_string(payload, key, warnings, errors, warn_if_missing=True)
    if text is None:
        return None
    address = canonical_ip(text)
    if address is None:
        _warn(warnings, key, f"{key} is not an IP address and was ignored")
    return address


def _string_list(
    payload: dict,
    key: str,
    errors: list[dict[str, str]],
    *,
    transform=None,
) -> list[str] | None:
    if key not in payload or payload[key] is None:
        return []
    value = payload[key]
    if not isinstance(value, list):
        _error(errors, key, f"{key} must be a list of strings")
        return None
    items: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            _error(errors, key, f"{key}[{index}] must be a string")
            return None
        text = item.strip()
        if not text:
            continue
        items.append(transform(text) if transform else text)
    return items


def _unstorable(payload: dict[str, Any]) -> str | None:
    """Why this JSON value cannot be stored and served back, or None. Walks without recursion."""
    pending: list[tuple[Any, int]] = [(payload, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > _MAX_DEPTH:
            return f"Alert payload is nested more than {_MAX_DEPTH} levels deep"
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                return "Alert payload contains text that is not valid Unicode"
        elif isinstance(value, float):
            if not math.isfinite(value):
                return "Alert payload contains a number that is not finite"
        elif isinstance(value, dict):
            pending.extend((item, depth + 1) for pair in value.items() for item in pair)
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
    return None


def primary_entity(alert: dict[str, Any]) -> str:
    for key in ("username", "hostname", "src_ip", "dst_ip"):
        value = alert.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().casefold()
    return ""


def fingerprint_for(alert: dict[str, Any]) -> str:
    detected = parse_datetime(alert["detected_at"])
    material = "\n".join(
        [
            str(alert["source"]).strip().casefold(),
            str(alert["name"]).strip().casefold(),
            primary_entity(alert),
            minute_bucket(detected),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _stored_duplicate(fingerprint: str) -> IngestResult | None:
    existing = get_alert_row_by_fingerprint(fingerprint)
    if existing is None:
        return None
    return IngestResult(alert=existing["alert"], warnings=existing.get("warnings") or [], duplicate=True)


def _id_taken(warnings: list[dict[str, str]]) -> IngestResult:
    return IngestResult(errors=[{"field": "id", "message": "Alert id already exists"}], warnings=warnings)


def ingest_alert(payload: Any) -> IngestResult:
    if not isinstance(payload, dict):
        return IngestResult(
            errors=[{"field": "body", "message": "Alert payload must be a JSON object"}]
        )
    problem = _unstorable(payload)
    if problem:
        return IngestResult(errors=[{"field": "body", "message": problem}])
    errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []

    source = _required_string(payload, "source", errors)
    name = _required_string(payload, "name", errors)
    detected_raw = payload.get("detected_at")
    detected_at: str | None = None
    if detected_raw is None or (isinstance(detected_raw, str) and not detected_raw.strip()):
        _error(errors, "detected_at", "detected_at is required")
    elif not isinstance(detected_raw, str):
        _error(errors, "detected_at", "detected_at must be an ISO8601 string")
    else:
        try:
            detected = parse_datetime(detected_raw)
            if detected.year in _YEARS:
                detected_at = utc_iso(detected)
            else:
                _error(errors, "detected_at", f"detected_at must be between {_YEARS[0]} and {_YEARS[-1]}")
        except ValueError:
            _error(errors, "detected_at", "detected_at is not a valid ISO8601 timestamp")

    description = _optional_string(payload, "description", warnings, errors, warn_if_missing=True)
    if description is None and not any(item["field"] == "description" for item in errors):
        description = ""

    severity_raw = payload.get("severity")
    severity = "informational"
    if severity_raw is None:
        _warn(warnings, "severity", "severity was not provided; defaulted to informational")
    elif not isinstance(severity_raw, str):
        _error(errors, "severity", "severity must be a string")
    else:
        severity = severity_raw.strip().lower()
        if severity not in SEVERITIES:
            _error(
                errors,
                "severity",
                "severity must be informational, low, medium, high, or critical",
            )

    src_ip = _ip_field(payload, "src_ip", warnings, errors)
    dst_ip = _ip_field(payload, "dst_ip", warnings, errors)
    username = _optional_string(payload, "username", warnings, errors, warn_if_missing=True)
    hostname = _optional_string(payload, "hostname", warnings, errors, warn_if_missing=True)
    file_hashes = _string_list(payload, "file_hashes", errors, transform=str.lower)
    domains = _string_list(payload, "domains", errors, transform=str.lower)
    urls = _string_list(payload, "urls", errors)
    mitre = _string_list(payload, "mitre_techniques", errors, transform=str.upper)

    raw = payload.get("raw", {})
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        _error(errors, "raw", "raw must be a JSON object")
        raw = {}

    supplied_id = payload.get("id")
    alert_id: str | None = None
    if supplied_id is not None:
        if not isinstance(supplied_id, str) or not _ID_RE.fullmatch(supplied_id.strip()):
            _error(errors, "id", "id must be 1-64 characters of letters, numbers, dot, underscore, or hyphen")
        else:
            alert_id = supplied_id.strip()

    if errors or file_hashes is None or domains is None or urls is None or mitre is None:
        return IngestResult(errors=errors, warnings=warnings)

    normalized = {
        "source": source,
        "name": name,
        "description": description or "",
        "severity": severity,
        "detected_at": detected_at,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "username": username,
        "hostname": hostname,
        "file_hashes": file_hashes,
        "domains": domains,
        "urls": urls,
        "mitre_techniques": mitre,
        "raw": raw,
    }
    if not any((username, hostname, src_ip, dst_ip)):
        _warn(
            warnings,
            "entity",
            "No username, hostname, or IP was provided; dedupe and investigation context are limited",
        )
    iocs = extract_iocs(normalized)
    if not iocs:
        _warn(warnings, "iocs", "No indicators were extracted from this alert")

    fingerprint = fingerprint_for(normalized)
    duplicate = _stored_duplicate(fingerprint)
    if duplicate is not None:
        return duplicate
    if alert_id is None:
        alert_id = f"alrt-{uuid4().hex[:12]}"
    elif alert_id_exists(alert_id):
        return _id_taken(warnings)

    alert = {
        "id": alert_id,
        **normalized,
        "iocs": [item.model_dump() for item in iocs],
    }
    Alert.model_validate(alert)
    document = {"alert": alert, "warnings": warnings}
    try:
        save_alert(alert_id, fingerprint, document)
    except sqlite3.IntegrityError:
        # Another request stored the same fingerprint or id after the checks above.
        duplicate = _stored_duplicate(fingerprint)
        return duplicate if duplicate is not None else _id_taken(warnings)
    return IngestResult(alert=alert, warnings=warnings, duplicate=False)
