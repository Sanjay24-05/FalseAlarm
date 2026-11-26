"""Deterministic triage. Verdicts are labels, and confidence is not a probability."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from false_alarm.assessment.signals import (
    Access,
    Intel,
    LaterActions,
    access_signals,
    intel_signals,
    later_actions,
)
from false_alarm.domain.models import Assessment, Hypothesis
from false_alarm.scenarios import Catalog
from false_alarm.util import defang_citations

_CONFIDENCE_NOTE = "Confidence is a qualitative label, not a probability."


@dataclass
class _Case:
    """Everything the rules below read, computed once."""

    evidence: list[dict]
    access: Access
    later: LaterActions
    intel: Intel
    truncated: Sequence[str]
    answered_questions: set[str]

    @property
    def strong_benign(self) -> bool:
        return (
            self.access.supported_benign
            and not self.later.harm
            and not self.later.set_aside
            and not self.intel.negative
            and not self.truncated
        )


def _statement(event: dict, clause: str) -> dict[str, str]:
    return {"evidence_id": event["id"], "statement": f"{event['summary']}. {clause}"}


def _verdict(case: _Case) -> str:
    if case.strong_benign:
        return "likely_benign"
    if case.access.signals and case.later.signals:
        return "confirmed_threat"
    return "suspicious"


def _severity(case: _Case, verdict: str) -> str:
    later = case.later
    if verdict == "likely_benign":
        return "low" if case.access.auth else "informational"
    if later.sensitive and later.outbound:
        return "critical"
    if later.sensitive or later.outbound or later.endpoint or verdict == "confirmed_threat":
        return "high"
    return "medium"


def _material_gaps(case: _Case) -> list[str]:
    """Gaps that limit confidence. Every gap is material, so `missing_evidence` is the same list."""
    gaps: list[str] = []
    if not case.access.auth:
        gaps.append("No authentication events were retrieved; the access stage is incomplete.")
    if not case.intel.records and "q_ti" not in case.answered_questions:
        gaps.append("Threat intelligence was not queried; missing reputation is unknown, not benign.")
    for item in case.intel.unknown:
        indicator = defang_citations(str(item["raw"].get("indicator")))
        gaps.append(f"Reputation for {indicator} is unknown, not benign.")
    for source_type in case.truncated:
        gaps.append(f"The {source_type} query reached its event limit; older matching records were not retrieved.")
    if case.later.set_aside:
        ids = ", ".join(item["id"] for item in case.later.set_aside)
        gaps.append(
            f"Potentially harmful activity was not attributed to this sign-in ({ids}): "
            "it belongs to another account, precedes the access, or was blocked."
        )
    return gaps


def _confidence(case: _Case, verdict: str, gaps: list[str]) -> tuple[str, str]:
    sources = sorted({item["source_type"] for item in case.evidence})
    if not gaps and len(sources) >= 3 and verdict in {"confirmed_threat", "likely_benign"}:
        return "high", f"High confidence because {', '.join(sources)} agree and no material gaps remain. {_CONFIDENCE_NOTE}"
    if len(sources) <= 1 or len(gaps) >= 3:
        return "low", (
            f"Low confidence because the retrieved sources ({', '.join(sources) or 'none'}) "
            f"are thin or material gaps remain. {_CONFIDENCE_NOTE}"
        )
    return "medium", f"Medium confidence based on {', '.join(sources) or 'limited sources'}. {_CONFIDENCE_NOTE}"


def _escalation(case: _Case, verdict: str, severity: str, gaps: list[str]) -> tuple[bool, str]:
    if verdict == "confirmed_threat":
        return True, (
            "Escalated because the verdict is confirmed_threat: independent access-stage and "
            "later-action signals were observed without a strong benign explanation."
        )
    if case.access.compromised:
        return True, (
            "Escalated because a sign-in from a source outside the user's baseline succeeded after repeated "
            "failures from that source."
        )
    if gaps and (verdict == "suspicious" or severity in {"high", "critical"}):
        return True, "Escalated because the case is suspicious or high impact and material evidence gaps remain."
    if verdict == "likely_benign":
        return False, (
            "Not escalated: a supported benign explanation is present and no post-authentication "
            "harmful action was observed."
        )
    return False, "Not escalated."


def _evidence_statements(case: _Case, verdict: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    access, later, intel = case.access, case.later, case.intel
    supporting: list[dict[str, str]] = []
    contradicting: list[dict[str, str]] = []
    if verdict == "confirmed_threat":
        if access.failures:
            supporting.append(
                _statement(access.failures[0], f"Counted as an access-stage signal: {len(access.failures)} failed sign-in(s).")
            )
        if access.primary_success is not None:
            reason = (
                "the success used the same source as the failures"
                if access.prior_failures(access.primary_success)
                else "the success is the login the later activity followed"
            )
            supporting.append(_statement(access.primary_success, f"Counted as an access-stage signal because {reason}."))
        for item, asset in later.sensitive:
            supporting.append(
                _statement(
                    item,
                    f"Counted as later action because {asset.get('hostname')} is a sensitive asset outside this user's baseline.",
                )
            )
        supporting += [_statement(item, "Counted as later action because the outbound transfer is unusual.") for item in later.outbound]
        supporting += [_statement(item, "Counted as later action because the endpoint record is malicious.") for item in later.endpoint]
        supporting += [_statement(item, "Counted as a related detection after the authentication.") for item in later.related]
        supporting += [_statement(item, "Local reputation is negative and is not treated as benign.") for item in intel.negative]
        contradicting += [
            _statement(item, "This reputation record does not support the threat verdict.") for item in intel.clean
        ]
    elif verdict == "likely_benign":
        if access.primary_success is not None:
            supporting.append(
                _statement(
                    access.primary_success,
                    "The successful source is a corporate VPN address or a source in the user baseline.",
                )
            )
        supporting += [
            _statement(item, "The destination matches file-server use recorded for this user.")
            for item, _asset in later.baseline_assets
        ]
        supporting += [_statement(item, "Local reputation is clean.") for item in intel.clean]
        if access.failures:
            contradicting.append(
                _statement(access.failures[0], "Failures preceded the success but came from the same known corporate source.")
            )
    else:
        for item in case.evidence[:4]:
            if item["source_type"] == "threat_intel" and (item["raw"].get("reputation") or "") == "unknown":
                supporting.append(_statement(item, "A missing reputation record is unknown, not benign."))
    return supporting, contradicting


def _impact_and_actions(case: _Case, verdict: str, severity: str) -> tuple[str, list[str]]:
    later = case.later
    if verdict == "likely_benign":
        return (
            "Low impact: retrieved activity is explained by a known corporate source or the user baseline, "
            "with no post-authentication harmful action."
        ), ["Close the alert as a likely false positive.", "No containment action is indicated by the retrieved evidence."]
    if severity == "critical":
        return (
            "Critical impact: a sensitive asset was accessed and an unusual outbound transfer was observed "
            "after authentication."
        ), [
            "Disable the affected user account until the access path is verified.",
            "Isolate the affected host from the network.",
            "Block the external source address at the perimeter.",
            "Preserve the retrieved authentication, network, endpoint, and threat-intelligence records.",
        ]
    if later.sensitive:
        return "High impact: a sensitive asset was accessed after authentication.", [
            "Disable the affected user account until the access path is verified.",
            "Preserve the retrieved records for response.",
        ]
    if later.outbound:
        return "High impact: an unusual outbound transfer was observed after authentication.", [
            "Block the external destination and isolate the host.",
            "Preserve the retrieved records for response.",
        ]
    if later.endpoint:
        return "High impact: endpoint activity was classified as malicious.", [
            "Isolate the affected host from the network.",
            "Preserve the retrieved records for response.",
        ]
    return "Limited impact: the retrieved activity is suspicious and the chain is incomplete.", [
        "Keep the alert open until the missing evidence is collected.",
        "Review the account activity with the user before containment.",
    ]


def _hypotheses(verdict: str, supporting: list[dict[str, str]]) -> list[Hypothesis]:
    support_ids = [item["evidence_id"] for item in supporting]
    threat = {"confirmed_threat": "supported", "likely_benign": "refuted"}.get(verdict, "open")
    benign = {"likely_benign": "supported", "confirmed_threat": "refuted"}.get(verdict, "open")
    return [
        Hypothesis(
            id="hyp-compromise",
            statement="The authenticated account was used for later harmful action.",
            status=threat,
            evidence_ids=support_ids if verdict == "confirmed_threat" else [],
        ),
        Hypothesis(
            id="hyp-benign",
            statement="The activity matches a known corporate source and the user baseline, without post-authentication harmful action.",
            status=benign,
            evidence_ids=support_ids if verdict == "likely_benign" else [],
        ),
    ]


def assess(
    alert: dict,
    evidence: list[dict],
    catalog: Catalog,
    unanswered: list[str],
    *,
    answered_questions: set[str],
    truncated: Sequence[str] = (),
) -> tuple[dict, list[dict], dict]:
    """The assessment, the hypotheses it tested, and the signals behind it (for the audit trail)."""
    baseline = catalog.baseline_for(alert.get("username"))
    access = access_signals(alert, evidence, catalog, baseline)
    intel = intel_signals(evidence)
    later = later_actions(alert, evidence, catalog, baseline, access, intel)
    case = _Case(evidence, access, later, intel, truncated, answered_questions)

    verdict = _verdict(case)
    severity = _severity(case, verdict)
    gaps = _material_gaps(case)
    confidence, rationale = _confidence(case, verdict, gaps)
    escalate, escalation_reason = _escalation(case, verdict, severity, gaps)
    supporting, contradicting = _evidence_statements(case, verdict)
    impact, actions = _impact_and_actions(case, verdict, severity)

    assessment = Assessment(
        severity=severity,
        verdict=verdict,
        confidence=confidence,
        confidence_rationale=rationale,
        impact=impact,
        supporting_evidence=supporting,
        contradicting_evidence=contradicting,
        missing_evidence=list(gaps),
        unresolved_questions=unanswered,
        recommended_actions=actions,
        escalate=escalate,
        escalation_reason=escalation_reason,
    )
    signals = {
        "access": access.signals,
        "later": later.signals,
        "strong_benign": case.strong_benign,
        "post_auth_harm": later.harm,
        "negative_reputation": bool(intel.negative),
        "material_gaps": gaps,
    }
    return assessment.model_dump(), [item.model_dump() for item in _hypotheses(verdict, supporting)], signals
