"""Code-generated observation text. Model output is never stored as an observation."""

from __future__ import annotations

import ipaddress
import json

from false_alarm.util import unique_strings

_HASH_TYPES = {"md5", "sha1", "sha256", "hash"}


def _indicator_bucket(indicator: str, indicator_type: str | None) -> str:
    kind = (indicator_type or "").lower()
    if kind in {"ipv4", "ip"}:
        return "ip"
    if kind in _HASH_TYPES:
        return "hash"
    if kind in {"domain", "hostname"}:
        return "domain"
    try:
        ipaddress.ip_address(indicator)
        return "ip"
    except ValueError:
        pass
    if len(indicator) in {32, 40, 64} and all(char in "0123456789abcdef" for char in indicator.lower()):
        return "hash"
    if "." in indicator:
        return "domain"
    return "other"


def entities_from_event(event: dict) -> dict[str, list[str]]:
    ips: list[str | None] = [event.get("src_ip"), event.get("dst_ip"), event.get("resolved_ip")]
    domains: list[str | None] = list(event.get("domains") or [])
    hashes: list[str | None] = list(event.get("hashes") or [])
    if event.get("query_name"):
        domains.append(event["query_name"])
    indicator = event.get("indicator")
    if isinstance(indicator, str) and indicator:
        bucket = _indicator_bucket(indicator, event.get("indicator_type"))
        if bucket == "ip":
            ips.append(indicator)
        elif bucket == "hash":
            hashes.append(indicator.lower())
        elif bucket == "domain":
            domains.append(indicator.lower())
    hosts = [event.get("hostname"), event.get("dst_host")]
    users = [event.get("username")]
    return {
        "ips": unique_strings(ips),
        "users": unique_strings(users),
        "hosts": unique_strings(hosts),
        "domains": unique_strings(domains),
        "hashes": unique_strings(hashes),
    }


def summarize_event(source_type: str, event: dict) -> str:
    """Build the only summary text that may be stored on an observation."""
    user = event.get("username") or "an unspecified user"
    if source_type == "authentication":
        action = event.get("action") or "event"
        source = event.get("src_ip") or "an unspecified address"
        return f"Authentication {action} for {user} from {source}"
    if source_type == "firewall":
        direction = event.get("direction") or "network"
        action = event.get("action") or "event"
        destination = " ".join(
            bit for bit in (event.get("dst_host"), event.get("dst_ip")) if bit
        ) or "an unspecified destination"
        byte_text = f" ({event['bytes']} bytes)" if isinstance(event.get("bytes"), int) else ""
        return f"Firewall {direction} {action} for {user} to {destination}{byte_text}"
    if source_type == "endpoint":
        action = event.get("action") or "event"
        host = event.get("hostname") or "an unspecified host"
        hashes = event.get("hashes") or []
        hash_text = f" hash {hashes[0]}" if hashes else ""
        return f"Endpoint {action} on {host} for {user}{hash_text}"
    if source_type == "dns":
        name = event.get("query_name") or "an unspecified name"
        host = event.get("hostname") or "an unspecified host"
        resolved = event.get("resolved_ip") or event.get("dst_ip") or "no address"
        return f"DNS query {name} from {host} resolved to {resolved}"
    if source_type == "related_alerts":
        name = event.get("name") or "alert"
        severity = event.get("severity") or "unspecified"
        host = event.get("hostname") or "an unspecified host"
        return f"Related alert {name} ({severity}) for {user} on {host}"
    if source_type == "threat_intel":
        indicator = event.get("indicator") or "an unspecified indicator"
        reputation = (event.get("reputation") or "unknown").lower()
        if reputation == "unknown":
            return f"No local reputation record for {indicator}; reputation is unknown, not benign"
        return f"Local threat intelligence rates {indicator} as {reputation}"
    return f"Observation from {source_type} for {user}"


def unknown_reputation_event(indicator: str, observed_at: str) -> dict:
    """A lookup miss. Reputation stays unknown rather than being treated as clean."""
    event = {
        "timestamp": observed_at,
        "scenario": None,
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
        "indicator": indicator,
        "indicator_type": None,
        "reputation": "unknown",
        "query_name": None,
        "resolved_ip": None,
    }
    bucket = _indicator_bucket(indicator, None)
    if bucket == "ip":
        event["indicator_type"] = "ipv4"
    elif bucket == "hash":
        event["indicator_type"] = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(indicator), "hash")
        event["hashes"] = [indicator.lower()]
    elif bucket == "domain":
        event["indicator_type"] = "domain"
        event["domains"] = [indicator.lower()]
    return event


def event_fingerprint(source_type: str, event: dict) -> str:
    """Identify one record by all of its fields.

    A reputation record is stamped with the lookup time, so its timestamp is not part of its identity.
    """
    ignored = {"scenario", "timestamp"} if source_type == "threat_intel" else {"scenario"}
    fields = {key: value for key, value in event.items() if key not in ignored}
    return f"{source_type}|{json.dumps(fields, sort_keys=True, default=str)}"


def make_observation(source_type: str, event: dict, *, evidence_id: str, query_id: str, source: str) -> dict:
    summary = summarize_event(source_type, event)
    observed_at = event.get("timestamp") or ""
    return {
        "id": evidence_id,
        "source": source,
        "source_type": source_type,
        "observed_at": observed_at,
        "query_id": query_id,
        "summary": summary,
        "entities": entities_from_event(event),
        "kind": "observation",
        "raw": event,
    }
