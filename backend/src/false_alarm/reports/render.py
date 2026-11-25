"""Report text. Claims cite stored evidence ids, or the deterministic template is used."""

from __future__ import annotations

import re

from false_alarm.util import defang_citations as plain

SECTION_KEYS = (
    "incident_summary",
    "alert_details",
    "triage",
    "executive_explanation",
    "timeline",
    "evidence",
    "correlated_indicators",
    "threat_intelligence",
    "attack_sequence",
    "confidence_and_gaps",
    "recommended_actions",
    "escalation",
    "audit_trail",
)

EVIDENCE_ID_RE = re.compile(r"\bev-\d{4,}\b")


def unknown_citations(text: str, known: set[str]) -> set[str]:
    return {item for item in EVIDENCE_ID_RE.findall(text) if item not in known}


def apply_citation_policy(
    sections: dict[str, str],
    known_ids: set[str],
    fallback: dict[str, str],
) -> dict[str, str]:
    blob = "\n".join(sections.get(key, "") for key in SECTION_KEYS)
    if unknown_citations(blob, known_ids):
        return {key: fallback[key] for key in SECTION_KEYS}
    return {key: sections[key] for key in SECTION_KEYS}


def deterministic_template(evidence: list[dict]) -> dict[str, str]:
    cite = evidence[0]["id"] if evidence else ""
    if cite:
        sentence = f"Stored evidence {cite} supports this section."
    else:
        sentence = "No stored evidence was available for this section."
    return {key: f"Deterministic template. {sentence}" for key in SECTION_KEYS}


def _cites(evidence: list[dict], limit: int = 6) -> str:
    ids = [item["id"] for item in evidence[:limit]]
    return ", ".join(ids)


def _correlated(evidence: list[dict]) -> str:
    buckets: dict[str, dict[str, list[str]]] = {
        "user": {},
        "ip": {},
        "host": {},
        "hash": {},
        "domain": {},
    }
    fields = {
        "users": "user",
        "ips": "ip",
        "hosts": "host",
        "hashes": "hash",
        "domains": "domain",
    }
    for item in evidence:
        entities = item.get("entities") or {}
        for source_field, label in fields.items():
            for value in entities.get(source_field) or []:
                bucket = buckets[label].setdefault(str(value), [])
                if item["id"] not in bucket:
                    bucket.append(item["id"])
    lines: list[str] = []
    for label, values in buckets.items():
        for value, ids in sorted(values.items()):
            if len(ids) < 2:
                continue
            lines.append(f"{label} {plain(value)} links {', '.join(ids)}.")
    return "\n".join(lines) if lines else "No shared indicators were found across stored evidence."


def compose_report(
    alert: dict,
    assessment: dict,
    evidence: list[dict],
    timeline: list[dict],
    audit: list[dict],
) -> dict[str, str]:
    known = {item["id"] for item in evidence}
    cites = _cites(evidence) or "none"
    support_lines = [
        f"{item['evidence_id']}: {plain(item['statement'])}" for item in assessment.get("supporting_evidence") or []
    ]
    contradict_lines = [
        f"{item['evidence_id']}: {plain(item['statement'])}" for item in assessment.get("contradicting_evidence") or []
    ]
    evidence_lines = [f"{item['id']} ({item['source_type']}): {plain(item['summary'])}" for item in evidence]
    timeline_lines = [
        f"{item['timestamp']} [{item['relationship']}] {plain(item['summary'])} ({', '.join(item['evidence_ids'])})"
        for item in timeline
    ]
    intel_lines = [
        f"{item['id']}: {plain(item['summary'])}" for item in evidence if item["source_type"] == "threat_intel"
    ]
    audit_lines = [f"{item['timestamp']} {item['kind']}: {plain(item['summary'])}" for item in audit]
    gaps = assessment.get("missing_evidence") or []
    unresolved = assessment.get("unresolved_questions") or []
    actions = assessment.get("recommended_actions") or []
    candidate = {
        "incident_summary": (
            f"Investigation of alert {plain(alert['id'])} ({plain(alert['name'])}) from {plain(alert['source'])} "
            f"concluded {assessment['verdict']} with {assessment['confidence']} confidence "
            f"and severity {assessment['severity']}. Observations considered include {cites}."
        ),
        "alert_details": (
            f"Source {plain(alert['source'])} reported {plain(alert['name'])} at {alert['detected_at']} "
            f"for user {plain(alert.get('username') or 'unspecified')} "
            f"on host {plain(alert.get('hostname') or 'unspecified')} "
            f"from {plain(alert.get('src_ip') or 'unspecified')}. {plain(alert.get('description') or '')} "
            f"Related observations include {cites}."
        ),
        "triage": (
            f"Verdict {assessment['verdict']}, severity {assessment['severity']}, "
            f"confidence {assessment['confidence']}. {assessment['impact']} "
            + ("\n".join(support_lines) if support_lines else f"Observations considered include {cites}.")
        ),
        "executive_explanation": (
            f"{assessment['impact']} The verdict is {assessment['verdict']}. "
            f"Evidence {cites} is the basis for that statement."
        ),
        "timeline": "\n".join(timeline_lines) if timeline_lines else "No timeline events were built from stored evidence.",
        "evidence": "\n".join(evidence_lines) if evidence_lines else "No evidence was stored.",
        "correlated_indicators": _correlated(evidence),
        "threat_intelligence": (
            "\n".join(intel_lines)
            if intel_lines
            else "Threat intelligence was not recorded. Missing reputation is unknown, not benign."
        ),
        "attack_sequence": (
            "\n".join(timeline_lines) if timeline_lines else f"No attack sequence was built. Observations: {cites}."
        ),
        "confidence_and_gaps": (
            f"{assessment['confidence_rationale']} "
            f"Missing evidence: {'; '.join(gaps) if gaps else 'none'}. "
            f"Unresolved questions: {'; '.join(unresolved) if unresolved else 'none'}. "
            f"Supporting evidence: {', '.join(item['evidence_id'] for item in assessment.get('supporting_evidence') or []) or cites}."
        ),
        "recommended_actions": "\n".join(actions) if actions else "No action was recommended.",
        "escalation": (
            f"Escalate: {str(assessment['escalate']).lower()}. {assessment['escalation_reason']} "
            f"Evidence {cites}."
        ),
        "audit_trail": "\n".join(audit_lines) if audit_lines else "No audit entries were recorded.",
    }
    if contradict_lines:
        candidate["triage"] = candidate["triage"] + "\n" + "\n".join(contradict_lines)
    return apply_citation_policy(candidate, known, deterministic_template(evidence))
