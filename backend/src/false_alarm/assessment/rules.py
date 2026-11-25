"""Deterministic triage. Verdicts are labels, and confidence is not a probability."""

from __future__ import annotations

from false_alarm.domain.models import Assessment, Hypothesis
from false_alarm.scenarios import Catalog
from false_alarm.util import ip_in_ranges, is_external_ip

_NEGATIVE = {"malicious", "suspicious", "negative"}
_CLEAN = {"clean", "benign", "neutral", "known_good"}
_MALICIOUS_ACTIONS = {
    "malicious",
    "malicious_process",
    "malware",
    "malware_detected",
    "suspicious_process",
}
_BLOCKED_ACTIONS = {"deny", "denied", "block", "blocked", "drop", "dropped", "reject", "rejected", "reset"}
_MACHINE_ACCOUNTS = {"system", "local service", "network service", "localsystem", "root"}
_OUTBOUND_FLOOR = 50_000_000
_REPEATED = 3


def _user_matches(event: dict, username: str | None) -> bool:
    if not username:
        return True
    return (event["raw"].get("username") or "").casefold() == username.casefold()


def _fold(value: object) -> str:
    return value.strip().casefold() if isinstance(value, str) else ""


def _is_machine_account(username: str) -> bool:
    return username.endswith("$") or username.rsplit("\\", 1)[-1] in _MACHINE_ACCOUNTS


def _statement(event: dict, clause: str) -> dict[str, str]:
    return {"evidence_id": event["id"], "statement": f"{event['summary']}. {clause}"}


def assess(
    alert: dict,
    evidence: list[dict],
    catalog: Catalog,
    unanswered: list[str],
    *,
    answered_questions: set[str],
) -> tuple[dict, list[dict], dict]:
    username = alert.get("username")
    baseline = catalog.baseline_for(username)
    auth = [item for item in evidence if item["source_type"] == "authentication"]
    firewall = [item for item in evidence if item["source_type"] == "firewall"]
    endpoint = [item for item in evidence if item["source_type"] == "endpoint"]
    related = [item for item in evidence if item["source_type"] == "related_alerts"]
    intel = [item for item in evidence if item["source_type"] == "threat_intel"]

    failures = [item for item in auth if item["raw"].get("action") == "failure" and _user_matches(item, username)]
    successes = [item for item in auth if item["raw"].get("action") == "success" and _user_matches(item, username)]
    successes.sort(key=lambda item: item["observed_at"])

    corporate = list(catalog.corporate_vpn_ranges) + list(catalog.scanner_ranges)
    known_good = list(catalog.known_good_ranges) + corporate
    typical_sources = list(baseline.get("typical_sources") or [])
    supported_ranges = corporate + typical_sources

    def supported(item: dict) -> bool:
        return ip_in_ranges(item["raw"].get("src_ip"), supported_ranges)

    def prior_failures(success: dict) -> list[dict]:
        source_ip = success["raw"].get("src_ip")
        return [
            item
            for item in failures
            if source_ip and item["raw"].get("src_ip") == source_ip and item["observed_at"] <= success["observed_at"]
        ]

    outside = [item for item in successes if not supported(item)]
    outside_failures = [item for item in failures if not supported(item)]
    new_source_successes = [
        item
        for item in outside
        if item["raw"].get("src_ip") and not ip_in_ranges(item["raw"].get("src_ip"), known_good)
    ]
    guessed = [item for item in successes if prior_failures(item)]
    compromised = [item for item in new_source_successes if len(prior_failures(item)) >= _REPEATED]
    # The login the case rests on: the most suspicious one, not the first one.
    primary_success = next(iter(compromised or new_source_successes or outside or guessed or successes), None)
    success_same = bool(guessed)
    new_source = bool(new_source_successes)

    account_ips = {item["raw"].get("src_ip") for item in successes} | {alert.get("src_ip")}
    repeated_failures = len(failures) >= _REPEATED
    many_accounts = any(
        len(
            {
                (item["raw"].get("username") or "").casefold()
                for item in auth
                if item["raw"].get("src_ip") == account_ip and item["raw"].get("username")
            }
        )
        >= _REPEATED
        for account_ip in account_ips
        if account_ip
    )

    anchor = min((item["observed_at"] for item in (outside or successes or failures)), default="")
    subject_ips = {item["raw"].get("src_ip") for item in successes} | {alert.get("src_ip")}
    if username:
        subject_users = {_fold(username)}
    else:
        subject_users = {
            _fold(item["raw"].get("username")) for item in successes if item["raw"].get("src_ip") == alert.get("src_ip")
        }
    subject_users.discard("")

    def attributed(item: dict) -> bool:
        """The record belongs to the alert's user, or names no person and belongs to its host or source."""
        user = _fold(item["raw"].get("username"))
        if user in subject_users:
            return True
        if user and subject_users and not _is_machine_account(user):
            return False
        host = _fold(item["raw"].get("hostname"))
        if host and host == _fold(alert.get("hostname")):
            return True
        source_ip = item["raw"].get("src_ip")
        return bool(source_ip and source_ip in subject_ips)

    set_aside: list[dict] = []

    def counts(item: dict) -> bool:
        blocked = item["source_type"] == "firewall" and _fold(item["raw"].get("action")) in _BLOCKED_ACTIONS
        if attributed(item) and item["observed_at"] >= anchor and not blocked:
            return True
        if item not in set_aside:
            set_aside.append(item)
        return False

    servers = {str(item) for item in (baseline.get("typical_file_servers") or [])}
    sensitive_hits: list[tuple[dict, dict]] = []
    baseline_assets: list[tuple[dict, dict]] = []
    for item in firewall:
        asset = catalog.match_asset(item["raw"].get("dst_ip"), item["raw"].get("dst_host"))
        if not asset:
            continue
        expected = asset.get("hostname") in servers or asset.get("ip") in servers
        if asset.get("sensitivity") in {"high", "critical"} and not expected:
            if counts(item):
                sensitive_hits.append((item, asset))
        elif expected:
            baseline_assets.append((item, asset))

    negative_ti = [
        item for item in intel if (item["raw"].get("reputation") or "").lower() in _NEGATIVE
    ]
    unknown_ti = [
        item for item in intel if (item["raw"].get("reputation") or "").lower() in {"", "unknown"}
    ]
    clean_ti = [item for item in intel if (item["raw"].get("reputation") or "").lower() in _CLEAN]
    negative_indicators = {
        str(item["raw"].get("indicator")).casefold()
        for item in negative_ti
        if item["raw"].get("indicator")
    }
    typical_bytes = int(baseline.get("typical_outbound_bytes") or 5_000_000)
    threshold = max(_OUTBOUND_FLOOR, typical_bytes * 5)
    outbound_hits: list[dict] = []
    for item in firewall:
        destination = item["raw"].get("dst_ip")
        direction = item["raw"].get("direction")
        public = bool(destination and is_external_ip(destination))
        is_outbound = direction == "outbound" or (public and direction != "internal")
        nbytes = int(item["raw"].get("bytes") or 0)
        destination_negative = bool(destination and destination.casefold() in negative_indicators)
        if is_outbound and (nbytes >= threshold or destination_negative) and counts(item):
            outbound_hits.append(item)

    endpoint_hits = [
        item
        for item in endpoint
        if (
            (item["raw"].get("action") or "") in _MALICIOUS_ACTIONS
            or (item["raw"].get("severity") or "") in {"high", "critical"}
        )
        and counts(item)
    ]
    related_hits = [
        item
        for item in related
        if (item["raw"].get("severity") or "") in {"medium", "high", "critical"} and counts(item)
    ]

    post_auth_harm = bool(sensitive_hits or outbound_hits or endpoint_hits or related_hits)
    negative_reputation = bool(negative_ti)
    supported_benign = bool(successes) and not outside and len(outside_failures) < _REPEATED
    strong_benign = supported_benign and not post_auth_harm and not set_aside and not negative_reputation

    access: list[str] = []
    if repeated_failures:
        access.append("repeated_failures")
    if success_same:
        access.append("success_from_same_source")
    if new_source:
        access.append("new_source_versus_baseline")
    if many_accounts:
        access.append("many_accounts_from_one_ip")
    later: list[str] = []
    if sensitive_hits:
        later.append("sensitive_asset_access")
    if outbound_hits:
        later.append("unusual_outbound_transfer")
    if endpoint_hits:
        later.append("endpoint_malicious_activity")
    if related_hits:
        later.append("related_alert")

    if strong_benign:
        verdict = "likely_benign"
    elif access and later:
        verdict = "confirmed_threat"
    else:
        verdict = "suspicious"

    if verdict == "likely_benign":
        severity = "low" if auth else "informational"
    elif sensitive_hits and outbound_hits:
        severity = "critical"
    elif sensitive_hits or outbound_hits or endpoint_hits:
        severity = "high"
    elif verdict == "confirmed_threat":
        severity = "high"
    elif verdict == "suspicious":
        severity = "medium"
    else:
        severity = "low"

    missing: list[str] = []
    material: list[str] = []
    if not auth:
        message = "No authentication events were retrieved; the access stage is incomplete."
        missing.append(message)
        material.append(message)
    intel_seen = bool(intel) or "q_ti" in answered_questions
    if not intel_seen:
        message = "Threat intelligence was not queried; missing reputation is unknown, not benign."
        missing.append(message)
        material.append(message)
    for item in unknown_ti:
        indicator = item["raw"].get("indicator")
        message = f"Reputation for {indicator} is unknown, not benign."
        missing.append(message)
        material.append(message)

    if set_aside:
        message = (
            f"Potentially harmful activity was not attributed to this sign-in ({', '.join(item['id'] for item in set_aside)}): "
            "it belongs to another account, precedes the access, or was blocked."
        )
        missing.append(message)
        material.append(message)

    sources = sorted({item["source_type"] for item in evidence})
    if not material and len(sources) >= 3 and verdict in {"confirmed_threat", "likely_benign"}:
        confidence = "high"
        rationale = (
            f"High confidence because {', '.join(sources)} agree and no material gaps remain. "
            "Confidence is a qualitative label, not a probability."
        )
    elif len(sources) <= 1 or len(material) >= 3:
        confidence = "low"
        rationale = (
            f"Low confidence because the retrieved sources ({', '.join(sources) or 'none'}) "
            "are thin or material gaps remain. Confidence is a qualitative label, not a probability."
        )
    else:
        confidence = "medium"
        rationale = (
            f"Medium confidence based on {', '.join(sources) or 'limited sources'}. "
            "Confidence is a qualitative label, not a probability."
        )

    high_impact = severity in {"high", "critical"}
    if verdict == "confirmed_threat":
        escalate = True
        escalation_reason = (
            "Escalated because the verdict is confirmed_threat: independent access-stage and "
            "later-action signals were observed without a strong benign explanation."
        )
    elif compromised:
        escalate = True
        escalation_reason = (
            "Escalated because a sign-in from a source outside the user's baseline succeeded after repeated "
            "failures from that source."
        )
    elif material and (verdict == "suspicious" or high_impact):
        escalate = True
        escalation_reason = (
            "Escalated because the case is suspicious or high impact and material evidence gaps remain."
        )
    elif verdict == "likely_benign":
        escalate = False
        escalation_reason = (
            "Not escalated: a supported benign explanation is present and no post-authentication "
            "harmful action was observed."
        )
    else:
        escalate = False
        escalation_reason = "Not escalated."

    supporting: list[dict[str, str]] = []
    contradicting: list[dict[str, str]] = []
    if verdict == "confirmed_threat":
        if failures:
            supporting.append(_statement(failures[0], f"Counted as an access-stage signal: {len(failures)} failed sign-in(s)."))
        if primary_success is not None:
            reason = (
                "the success used the same source as the failures"
                if prior_failures(primary_success)
                else "the success is the login the later activity followed"
            )
            supporting.append(_statement(primary_success, f"Counted as an access-stage signal because {reason}."))
        for item, asset in sensitive_hits:
            supporting.append(
                _statement(item, f"Counted as later action because {asset.get('hostname')} is a sensitive asset outside this user's baseline.")
            )
        for item in outbound_hits:
            supporting.append(_statement(item, "Counted as later action because the outbound transfer is unusual."))
        for item in endpoint_hits:
            supporting.append(_statement(item, "Counted as later action because the endpoint record is malicious."))
        for item in related_hits:
            supporting.append(_statement(item, "Counted as a related detection after the authentication."))
        for item in negative_ti:
            supporting.append(_statement(item, "Local reputation is negative and is not treated as benign."))
        for item in clean_ti:
            contradicting.append(_statement(item, "This reputation record does not support the threat verdict."))
    elif verdict == "likely_benign":
        if primary_success is not None:
            supporting.append(
                _statement(
                    primary_success,
                    "The successful source is a corporate VPN address or a source in the user baseline.",
                )
            )
        for item, _asset in baseline_assets:
            supporting.append(_statement(item, "The destination matches file-server use recorded for this user."))
        for item in clean_ti:
            supporting.append(_statement(item, "Local reputation is clean."))
        if failures:
            contradicting.append(
                _statement(failures[0], "Failures preceded the success but came from the same known corporate source.")
            )
    else:
        for item in evidence[:4]:
            if item["source_type"] == "threat_intel" and (item["raw"].get("reputation") or "") == "unknown":
                supporting.append(_statement(item, "A missing reputation record is unknown, not benign."))

    if verdict == "likely_benign":
        impact = (
            "Low impact: retrieved activity is explained by a known corporate source or the user baseline, "
            "with no post-authentication harmful action."
        )
        actions = [
            "Close the alert as a likely false positive.",
            "No containment action is indicated by the retrieved evidence.",
        ]
    elif severity == "critical":
        impact = (
            "Critical impact: a sensitive asset was accessed and an unusual outbound transfer was observed "
            "after authentication."
        )
        actions = [
            "Disable the affected user account until the access path is verified.",
            "Isolate the affected host from the network.",
            "Block the external source address at the perimeter.",
            "Preserve the retrieved authentication, network, endpoint, and threat-intelligence records.",
        ]
    elif sensitive_hits:
        impact = "High impact: a sensitive asset was accessed after authentication."
        actions = [
            "Disable the affected user account until the access path is verified.",
            "Preserve the retrieved records for response.",
        ]
    elif outbound_hits:
        impact = "High impact: an unusual outbound transfer was observed after authentication."
        actions = [
            "Block the external destination and isolate the host.",
            "Preserve the retrieved records for response.",
        ]
    elif endpoint_hits:
        impact = "High impact: endpoint activity was classified as malicious."
        actions = [
            "Isolate the affected host from the network.",
            "Preserve the retrieved records for response.",
        ]
    else:
        impact = "Limited impact: the retrieved activity is suspicious and the chain is incomplete."
        actions = [
            "Keep the alert open until the missing evidence is collected.",
            "Review the account activity with the user before containment.",
        ]

    threat_status = "supported" if verdict == "confirmed_threat" else "refuted" if verdict == "likely_benign" else "open"
    benign_status = "supported" if verdict == "likely_benign" else "refuted" if verdict == "confirmed_threat" else "open"
    support_ids = [item["evidence_id"] for item in supporting]
    hypotheses = [
        Hypothesis(
            id="hyp-compromise",
            statement="The authenticated account was used for later harmful action.",
            status=threat_status,
            evidence_ids=support_ids if verdict == "confirmed_threat" else [],
        ),
        Hypothesis(
            id="hyp-benign",
            statement="The activity matches a known corporate source and the user baseline, without post-authentication harmful action.",
            status=benign_status,
            evidence_ids=support_ids if verdict == "likely_benign" else [],
        ),
    ]
    assessment = Assessment(
        severity=severity,
        verdict=verdict,
        confidence=confidence,
        confidence_rationale=rationale,
        impact=impact,
        supporting_evidence=supporting,
        contradicting_evidence=contradicting,
        missing_evidence=missing,
        unresolved_questions=unanswered,
        recommended_actions=actions,
        escalate=escalate,
        escalation_reason=escalation_reason,
    )
    signals = {
        "access": access,
        "later": later,
        "strong_benign": strong_benign,
        "post_auth_harm": post_auth_harm,
        "negative_reputation": negative_reputation,
        "material_gaps": material,
    }
    return assessment.model_dump(), [item.model_dump() for item in hypotheses], signals
