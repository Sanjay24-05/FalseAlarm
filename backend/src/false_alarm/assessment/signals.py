"""Signals the verdict rules read: what happened at sign-in, what followed it, and what reputation says."""

from __future__ import annotations

from dataclasses import dataclass, field

from false_alarm.scenarios import Catalog
from false_alarm.util import ip_in_ranges, is_external_ip

NEGATIVE_REPUTATIONS = {"malicious", "suspicious", "negative"}
CLEAN_REPUTATIONS = {"clean", "benign", "neutral", "known_good"}
MALICIOUS_ACTIONS = {"malicious", "malicious_process", "malware", "malware_detected", "suspicious_process"}
BLOCKED_ACTIONS = {"deny", "denied", "block", "blocked", "drop", "dropped", "reject", "rejected", "reset"}
MACHINE_ACCOUNTS = {"system", "local service", "network service", "localsystem", "root"}
OUTBOUND_FLOOR = 50_000_000
REPEATED = 3


def fold(value: object) -> str:
    return value.strip().casefold() if isinstance(value, str) else ""


def is_machine_account(username: str) -> bool:
    return username.endswith("$") or username.rsplit("\\", 1)[-1] in MACHINE_ACCOUNTS


def _user_matches(event: dict, username: str | None) -> bool:
    if not username:
        return True
    return (event["raw"].get("username") or "").casefold() == username.casefold()


def _reputation(item: dict) -> str:
    return (item["raw"].get("reputation") or "").lower()


@dataclass
class Access:
    """The alert user's sign-ins and the access-stage signals they produce."""

    auth: list[dict]
    failures: list[dict]
    successes: list[dict]
    outside: list[dict]
    outside_failures: list[dict]
    compromised: list[dict]
    primary_success: dict | None
    signals: list[str]
    # Everything later activity is attributed against.
    anchor: str
    subject_users: set[str]
    subject_ips: set[str | None]

    def prior_failures(self, success: dict) -> list[dict]:
        source_ip = success["raw"].get("src_ip")
        return [
            item
            for item in self.failures
            if source_ip and item["raw"].get("src_ip") == source_ip and item["observed_at"] <= success["observed_at"]
        ]

    @property
    def supported_benign(self) -> bool:
        return bool(self.successes) and not self.outside and len(self.outside_failures) < REPEATED


def access_signals(alert: dict, evidence: list[dict], catalog: Catalog, baseline: dict) -> Access:
    username = alert.get("username")
    auth = [item for item in evidence if item["source_type"] == "authentication"]
    failures = [item for item in auth if item["raw"].get("action") == "failure" and _user_matches(item, username)]
    successes = [item for item in auth if item["raw"].get("action") == "success" and _user_matches(item, username)]
    successes.sort(key=lambda item: item["observed_at"])

    corporate = list(catalog.corporate_vpn_ranges) + list(catalog.scanner_ranges)
    known_good = list(catalog.known_good_ranges) + corporate
    supported_ranges = corporate + list(baseline.get("typical_sources") or [])

    def supported(item: dict) -> bool:
        return ip_in_ranges(item["raw"].get("src_ip"), supported_ranges)

    outside = [item for item in successes if not supported(item)]
    new_source = [
        item
        for item in outside
        if item["raw"].get("src_ip") and not ip_in_ranges(item["raw"].get("src_ip"), known_good)
    ]
    access = Access(
        auth=auth,
        failures=failures,
        successes=successes,
        outside=outside,
        outside_failures=[item for item in failures if not supported(item)],
        compromised=[],
        primary_success=None,
        signals=[],
        anchor=min((item["observed_at"] for item in (outside or successes or failures)), default=""),
        subject_users=set(),
        subject_ips={item["raw"].get("src_ip") for item in successes} | {alert.get("src_ip")},
    )
    guessed = [item for item in successes if access.prior_failures(item)]
    access.compromised = [item for item in new_source if len(access.prior_failures(item)) >= REPEATED]
    # The login the case rests on: the most suspicious one, not the first one.
    access.primary_success = next(iter(access.compromised or new_source or outside or guessed or successes), None)

    if username:
        access.subject_users = {fold(username)}
    else:
        access.subject_users = {
            fold(item["raw"].get("username")) for item in successes if item["raw"].get("src_ip") == alert.get("src_ip")
        }
    access.subject_users.discard("")

    account_ips = {item["raw"].get("src_ip") for item in successes} | {alert.get("src_ip")}
    many_accounts = any(
        len(
            {
                (item["raw"].get("username") or "").casefold()
                for item in auth
                if item["raw"].get("src_ip") == account_ip and item["raw"].get("username")
            }
        )
        >= REPEATED
        for account_ip in account_ips
        if account_ip
    )
    for name, present in (
        ("repeated_failures", len(failures) >= REPEATED),
        ("success_from_same_source", bool(guessed)),
        ("new_source_versus_baseline", bool(new_source)),
        ("many_accounts_from_one_ip", many_accounts),
    ):
        if present:
            access.signals.append(name)
    return access


@dataclass
class Intel:
    records: list[dict]
    negative: list[dict]
    unknown: list[dict]
    clean: list[dict]

    @property
    def negative_indicators(self) -> set[str]:
        return {str(item["raw"].get("indicator")).casefold() for item in self.negative if item["raw"].get("indicator")}


def intel_signals(evidence: list[dict]) -> Intel:
    records = [item for item in evidence if item["source_type"] == "threat_intel"]
    return Intel(
        records=records,
        negative=[item for item in records if _reputation(item) in NEGATIVE_REPUTATIONS],
        unknown=[item for item in records if _reputation(item) in {"", "unknown"}],
        clean=[item for item in records if _reputation(item) in CLEAN_REPUTATIONS],
    )


@dataclass
class LaterActions:
    """Harmful activity after the access. Activity that fails attribution is set aside, not discarded."""

    sensitive: list[tuple[dict, dict]] = field(default_factory=list)
    baseline_assets: list[tuple[dict, dict]] = field(default_factory=list)
    outbound: list[dict] = field(default_factory=list)
    endpoint: list[dict] = field(default_factory=list)
    related: list[dict] = field(default_factory=list)
    set_aside: list[dict] = field(default_factory=list)

    @property
    def harm(self) -> bool:
        return bool(self.sensitive or self.outbound or self.endpoint or self.related)

    @property
    def signals(self) -> list[str]:
        named = (
            ("sensitive_asset_access", self.sensitive),
            ("unusual_outbound_transfer", self.outbound),
            ("endpoint_malicious_activity", self.endpoint),
            ("related_alert", self.related),
        )
        return [name for name, items in named if items]


def later_actions(
    alert: dict, evidence: list[dict], catalog: Catalog, baseline: dict, access: Access, intel: Intel
) -> LaterActions:
    later = LaterActions()

    def attributed(item: dict) -> bool:
        """The record belongs to the alert's user, or names no person and belongs to its host or source."""
        user = fold(item["raw"].get("username"))
        if user in access.subject_users:
            return True
        if user and access.subject_users and not is_machine_account(user):
            return False
        host = fold(item["raw"].get("hostname"))
        if host and host == fold(alert.get("hostname")):
            return True
        source_ip = item["raw"].get("src_ip")
        return bool(source_ip and source_ip in access.subject_ips)

    def counts(item: dict) -> bool:
        blocked = item["source_type"] == "firewall" and fold(item["raw"].get("action")) in BLOCKED_ACTIONS
        if attributed(item) and item["observed_at"] >= access.anchor and not blocked:
            return True
        if item not in later.set_aside:
            later.set_aside.append(item)
        return False

    firewall = [item for item in evidence if item["source_type"] == "firewall"]
    servers = {str(item) for item in (baseline.get("typical_file_servers") or [])}
    for item in firewall:
        asset = catalog.match_asset(item["raw"].get("dst_ip"), item["raw"].get("dst_host"))
        if not asset:
            continue
        expected = asset.get("hostname") in servers or asset.get("ip") in servers
        if asset.get("sensitivity") in {"high", "critical"} and not expected:
            if counts(item):
                later.sensitive.append((item, asset))
        elif expected:
            later.baseline_assets.append((item, asset))

    threshold = max(OUTBOUND_FLOOR, int(baseline.get("typical_outbound_bytes") or 5_000_000) * 5)
    negative_indicators = intel.negative_indicators
    for item in firewall:
        destination = item["raw"].get("dst_ip")
        direction = item["raw"].get("direction")
        public = bool(destination and is_external_ip(destination))
        is_outbound = direction == "outbound" or (public and direction != "internal")
        nbytes = int(item["raw"].get("bytes") or 0)
        destination_negative = bool(destination and destination.casefold() in negative_indicators)
        if is_outbound and (nbytes >= threshold or destination_negative) and counts(item):
            later.outbound.append(item)

    for item in evidence:
        if item["source_type"] == "endpoint":
            malicious = (item["raw"].get("action") or "") in MALICIOUS_ACTIONS or (
                item["raw"].get("severity") or ""
            ) in {"high", "critical"}
            if malicious and counts(item):
                later.endpoint.append(item)
    for item in evidence:
        if item["source_type"] == "related_alerts":
            if (item["raw"].get("severity") or "") in {"medium", "high", "critical"} and counts(item):
                later.related.append(item)
    return later
