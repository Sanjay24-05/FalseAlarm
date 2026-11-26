"""Entities learned from the alert and from observations. The planner reads this, not raw logs."""

from __future__ import annotations

from dataclasses import dataclass, field

from false_alarm.util import is_external_ip


@dataclass
class Context:
    username: str | None = None
    hostname: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    external_ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    needs_expansion: bool = False
    answered: set[str] = field(default_factory=set)
    empty_question_ids: set[str] = field(default_factory=set)
    looked_up: set[str] = field(default_factory=set)

    def known(self, key: str) -> bool:
        value = getattr(self, key)
        if isinstance(value, (set, list, tuple)):
            return bool(value)
        if isinstance(value, bool):
            return value
        return value is not None and str(value).strip() != ""

    def absorb(self, entities: dict) -> None:
        for ip in entities.get("ips") or []:
            if ip and is_external_ip(ip):
                self.external_ips.add(ip)
        for domain in entities.get("domains") or []:
            if domain:
                self.domains.add(str(domain).lower())
        for digest in entities.get("hashes") or []:
            if digest:
                self.hashes.add(str(digest).lower())
        if not self.username:
            users = entities.get("users") or []
            if users:
                self.username = users[0]


def context_from_alert(alert: dict) -> Context:
    context = Context(
        username=alert.get("username"),
        hostname=alert.get("hostname"),
        src_ip=alert.get("src_ip"),
        dst_ip=alert.get("dst_ip"),
    )
    if alert.get("src_ip") and is_external_ip(alert["src_ip"]):
        context.external_ips.add(alert["src_ip"])
    if alert.get("dst_ip") and is_external_ip(alert["dst_ip"]):
        context.external_ips.add(alert["dst_ip"])
    for domain in alert.get("domains") or []:
        context.domains.add(str(domain).lower())
    for digest in alert.get("file_hashes") or []:
        context.hashes.add(str(digest).lower())
    for ioc in alert.get("iocs") or []:
        ioc_type = ioc.get("type")
        value = ioc.get("value")
        if not value:
            continue
        if ioc_type in {"ipv4", "ipv6"} and is_external_ip(value):
            context.external_ips.add(value)
        elif ioc_type == "domain":
            context.domains.add(str(value).lower())
        elif ioc_type in {"md5", "sha1", "sha256"}:
            context.hashes.add(str(value).lower())
    return context
