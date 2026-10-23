"""Entity links. Time overlap is recorded only when two events already share an entity."""

from __future__ import annotations

from datetime import timedelta

from false_alarm.util import is_external_ip, is_internal_ip, parse_datetime

_LOG_TYPES = {"authentication", "firewall", "endpoint", "dns", "related_alerts"}


def _shared(left: list[str], right: list[str]) -> bool:
    return bool({item.casefold() for item in left} & {item.casefold() for item in right})


def link_reasons(left: dict, right: dict) -> list[str]:
    left_entities = left.get("entities") or {}
    right_entities = right.get("entities") or {}
    reasons: list[str] = []
    pairs = (
        ("ip", "ips"),
        ("user", "users"),
        ("host", "hosts"),
        ("hash", "hashes"),
        ("domain", "domains"),
    )
    for label, key in pairs:
        if _shared(left_entities.get(key) or [], right_entities.get(key) or []):
            reasons.append(label)
    if not reasons:
        return []
    try:
        delta = abs(parse_datetime(left["observed_at"]) - parse_datetime(right["observed_at"]))
    except (TypeError, ValueError):
        return reasons
    if delta <= timedelta(hours=2):
        reasons.append("time")
    return reasons


def _linked(left: dict, right: dict) -> bool:
    return bool(link_reasons(left, right))


def _same_user(left: dict, right: dict) -> bool:
    return (left["raw"].get("username") or "").casefold() == (right["raw"].get("username") or "").casefold()


def _outbound(item: dict) -> bool:
    direction = item["raw"].get("direction")
    destination = item["raw"].get("dst_ip")
    if direction == "outbound":
        return True
    if direction == "internal":
        return False
    return bool(destination and is_external_ip(destination))


def _internal_network(item: dict) -> bool:
    if _outbound(item):
        return False
    destination = item["raw"].get("dst_ip")
    direction = item["raw"].get("direction")
    return direction == "internal" or bool(destination and is_internal_ip(destination))


def build_timeline(evidence: list[dict]) -> list[dict]:
    observed: list[dict] = []
    for item in evidence:
        if item.get("source_type") not in _LOG_TYPES:
            continue
        observed.append(
            {
                "timestamp": item["observed_at"],
                "summary": item["summary"],
                "relationship": "observed",
                "evidence_ids": [item["id"]],
                "source": item["source"],
            }
        )

    inferred: list[dict] = []
    successes = [
        item
        for item in evidence
        if item.get("source_type") == "authentication" and item["raw"].get("action") == "success"
    ]
    failures = [
        item
        for item in evidence
        if item.get("source_type") == "authentication" and item["raw"].get("action") == "failure"
    ]
    for success in successes:
        username = success["raw"].get("username")
        source_ip = success["raw"].get("src_ip")
        prior = [
            item
            for item in failures
            if _same_user(item, success)
            and item["raw"].get("src_ip") == source_ip
            and item["observed_at"] <= success["observed_at"]
            and _linked(item, success)
        ]
        if prior:
            inferred.append(
                {
                    "timestamp": success["observed_at"],
                    "summary": (
                        f"Inferred: successful authentication for {username} from {source_ip} "
                        f"followed {len(prior)} failure(s) from the same source."
                    ),
                    "relationship": "inferred",
                    "evidence_ids": [prior[0]["id"], success["id"]],
                    "source": "correlation",
                }
            )
        later_firewall = sorted(
            (
                item
                for item in evidence
                if item.get("source_type") == "firewall"
                and _same_user(item, success)
                and item["observed_at"] >= success["observed_at"]
                and _linked(success, item)
            ),
            key=lambda item: item["observed_at"],
        )
        internal = [item for item in later_firewall if _internal_network(item)]
        outbound = [item for item in later_firewall if _outbound(item)]
        if internal:
            target = internal[0]
            destination = target["raw"].get("dst_host") or target["raw"].get("dst_ip")
            inferred.append(
                {
                    "timestamp": target["observed_at"],
                    "summary": (
                        f"Inferred: {username} reached {destination} after the successful authentication."
                    ),
                    "relationship": "inferred",
                    "evidence_ids": [success["id"], target["id"]],
                    "source": "correlation",
                }
            )
        if outbound:
            target = outbound[0]
            destination = target["raw"].get("dst_ip") or target["raw"].get("dst_host")
            anchor = internal[0]["id"] if internal else success["id"]
            inferred.append(
                {
                    "timestamp": target["observed_at"],
                    "summary": (
                        f"Inferred: outbound transfer to {destination} followed earlier activity by {username}."
                    ),
                    "relationship": "inferred",
                    "evidence_ids": [anchor, target["id"]],
                    "source": "correlation",
                }
            )
        later_endpoint = sorted(
            (
                item
                for item in evidence
                if item.get("source_type") == "endpoint"
                and _same_user(item, success)
                and item["observed_at"] >= success["observed_at"]
                and _linked(success, item)
            ),
            key=lambda item: item["observed_at"],
        )
        if later_endpoint:
            target = later_endpoint[0]
            inferred.append(
                {
                    "timestamp": target["observed_at"],
                    "summary": (
                        f"Inferred: endpoint activity on {target['raw'].get('hostname')} "
                        f"followed authentication for {username}."
                    ),
                    "relationship": "inferred",
                    "evidence_ids": [success["id"], target["id"]],
                    "source": "correlation",
                }
            )

    combined = observed + inferred
    combined.sort(
        key=lambda item: (
            item["timestamp"],
            0 if item["relationship"] == "observed" else 1,
            item["summary"],
        )
    )
    for index, item in enumerate(combined, start=1):
        item["id"] = f"tl-{index:04d}"
    return combined
