"""OpenAI-compatible planner. One invalid response is retried, then the playbook is used."""

from __future__ import annotations

import json
import logging
import re
import time

import httpx

from false_alarm.planner.actions import ToolAction
from false_alarm.settings import Settings

logger = logging.getLogger("false_alarm.planner")
_CALL_TIMEOUT = 20.0
# Below this many seconds a call cannot finish usefully, so none is started.
_MIN_CALL_SECONDS = 0.05

_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)
_SYSTEM = (
    "You are the planner for False Alarm. Choose the next allowlisted tool. "
    "Respond with one JSON object only, shaped as "
    '{"tool": "...", "arguments": {"user": null, "host": null, "iocs": []}, "question": "..."}. '
    "Allowlisted tools: query_authentication, query_firewall, query_endpoint, query_dns, "
    "query_related_alerts, lookup_threat_intel, expand_time_window, finish. "
    "Do not invent log rows, timeline events, verdicts, or evidence. "
    "Arguments may only filter by user, host, and iocs."
)


def bounded_summary(alert: dict, evidence: list[dict], open_questions: list[str]) -> str:
    """A short evidence summary. Raw log bodies are not included."""
    lines = [
        f"Alert name: {alert.get('name')}",
        f"Description: {alert.get('description')}",
        f"User: {alert.get('username')}",
        f"Host: {alert.get('hostname')}",
        f"Source IP: {alert.get('src_ip')}",
        f"Detected: {alert.get('detected_at')}",
        f"MITRE: {', '.join(alert.get('mitre_techniques') or [])}",
        "Open questions:",
    ]
    lines.extend(f"- {question}" for question in open_questions[:12])
    lines.append("Evidence summaries:")
    for item in evidence[:40]:
        entities = item.get("entities") or {}
        lines.append(
            f"{item['id']} {item['source_type']}: {item['summary']} "
            f"ips={entities.get('ips')} users={entities.get('users')}"
        )
    return "\n".join(lines)[:6000]


def chat_complete(summary: str, settings: Settings, *, timeout: float = _CALL_TIMEOUT) -> str:
    url = settings.llm_base_url.rstrip("/")
    if not url.endswith("/chat/completions"):
        url = f"{url}/chat/completions"
    payload = {
        "model": settings.llm_model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": summary},
        ],
    }
    headers = {"Authorization": f"Bearer {settings.llm_api_key}"}
    with httpx.Client(timeout=timeout) as client:
        response = client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        body = response.json()
    return body["choices"][0]["message"]["content"]


def parse_action(content: str) -> ToolAction:
    text = content.strip()
    if text.startswith("```"):
        text = _FENCE_RE.sub("", text).strip()
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("Planner response must be a JSON object")
    # Which question an action answers is decided from the query itself, never from the model.
    data.pop("question_id", None)
    return ToolAction.model_validate(data)


def propose_with_llm(
    summary: str, settings: Settings, *, deadline: float | None = None, errors: list[str] | None = None
) -> ToolAction | None:
    """Try twice within the deadline (a time.monotonic() value).

    Any failure returns None so the caller can use the playbook. Failures are recorded by exception type only:
    messages can carry the endpoint URL, the key, or the model's text.
    """
    errors = [] if errors is None else errors
    for _attempt in range(2):
        timeout = _CALL_TIMEOUT
        if deadline is not None:
            timeout = min(timeout, deadline - time.monotonic())
            if timeout < _MIN_CALL_SECONDS:
                errors.append("DeadlineReached")
                break
        try:
            return parse_action(chat_complete(summary, settings, timeout=timeout))
        except Exception as exc:
            errors.append(type(exc).__name__)
            logger.warning("Planner model call failed: %s", type(exc).__name__)
    return None


def choose_action(
    fallback: ToolAction | None, summary: str, settings: Settings, *, deadline: float | None = None
) -> tuple[ToolAction | None, str, list[str]]:
    """The next action, where it came from, and the model failures on the way."""
    errors: list[str] = []
    if settings.llm_configured():
        proposed = propose_with_llm(summary, settings, deadline=deadline, errors=errors)
        if proposed is not None:
            return proposed, "llm", errors
        if fallback is not None:
            return fallback, "playbook_fallback", errors
    return fallback, "playbook", errors
