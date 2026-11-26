"""Plan, query, and observe until the playbook finishes or a budget is spent."""

from __future__ import annotations

import json
import logging
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from uuid import uuid4

from false_alarm.agent.context import Context, context_from_alert
from false_alarm.agent.observe import event_fingerprint, make_observation, unknown_reputation_event
from false_alarm.agent.tools import execute_tool
from false_alarm.assessment.rules import assess
from false_alarm.correlation.engine import build_timeline
from false_alarm.db import get_alert_row, get_investigation, insert_investigation, update_investigation
from false_alarm.domain.models import InvestigationDocument
from false_alarm.errors import AlertNotFound, UnknownToolError, UnscopedQueryError
from false_alarm.planner.actions import ToolAction
from false_alarm.planner.llm import bounded_summary, choose_action
from false_alarm.planner.playbooks import (
    CONTROL_TOOLS,
    QuestionTemplate,
    covered_questions,
    open_question_count,
    playbook_action,
    questions_for,
    select_playbook,
)
from false_alarm.reports.render import compose_report
from false_alarm.scenarios import get_catalog
from false_alarm.settings import Settings, get_settings
from false_alarm.util import parse_datetime, utc_iso, utc_now

logger = logging.getLogger("false_alarm.agent")


@dataclass
class RunState:
    investigation_id: str
    alert: dict
    playbook: str
    questions: list[QuestionTemplate]
    context: Context
    window_start: object
    window_end: object
    expansions: int = 0
    evidence: list[dict] = field(default_factory=list)
    steps: list[dict] = field(default_factory=list)
    audit: list[dict] = field(default_factory=list)
    seen: set[str] = field(default_factory=set)
    executed: set[str] = field(default_factory=set)
    truncated: set[str] = field(default_factory=set)
    tool_calls: int = 0
    evidence_seq: int = 0
    query_seq: int = 0
    started: float = 0.0


def _audit(state: RunState, kind: str, summary: str, details: dict | None = None) -> None:
    state.audit.append(
        {
            "id": f"au-{len(state.audit) + 1:04d}",
            "kind": kind,
            "timestamp": utc_iso(utc_now()),
            "summary": summary,
            "details": details or {},
        }
    )


def _duration_ms(state: RunState) -> int:
    return max(0, int((time.perf_counter() - state.started) * 1000))


def _snapshot(
    state: RunState,
    *,
    status: str,
    stop_reason: str | None,
    assessment: dict | None = None,
    report: dict | None = None,
    timeline: list[dict] | None = None,
) -> dict:
    document = {
        "id": state.investigation_id,
        "alert_id": state.alert["id"],
        "status": status,
        "stop_reason": stop_reason,
        "metrics": {
            "duration_ms": _duration_ms(state),
            "tool_call_count": state.tool_calls,
            "event_count": len(state.evidence),
        },
        "steps": state.steps,
        "evidence": state.evidence,
        "timeline": timeline if timeline is not None else build_timeline(state.evidence),
        "assessment": assessment,
        "report": report,
        "audit": state.audit,
    }
    InvestigationDocument.model_validate(document)
    update_investigation(document)
    return document


def _enforce_arguments(action: ToolAction, state: RunState, limit: int) -> dict:
    if action.tool in CONTROL_TOOLS:
        if action.tool == "expand_time_window":
            return {"start": utc_iso(state.window_start), "end": utc_iso(state.window_end)}
        return {}
    arguments = {
        "start": utc_iso(state.window_start),
        "end": utc_iso(state.window_end),
        "limit": limit,
    }
    supplied = action.arguments or {}
    for key in ("user", "host"):
        value = supplied.get(key)
        if isinstance(value, str) and value.strip():
            arguments[key] = value.strip()
    iocs = supplied.get("iocs") or []
    if isinstance(iocs, str):
        iocs = [iocs]
    if not isinstance(iocs, list):
        iocs = []
    cleaned = [item.strip() for item in iocs if isinstance(item, str) and item.strip()]
    if cleaned:
        arguments["iocs"] = cleaned
    return arguments


def _remember(
    state: RunState, source_type: str, event: dict, query_id: str, source: str, repeats: Counter[str]
) -> dict | None:
    """Store a record once across queries. Identical rows within one query result are separate records."""
    fingerprint = event_fingerprint(source_type, event)
    repeats[fingerprint] += 1
    key = fingerprint if source_type == "threat_intel" else f"{fingerprint}#{repeats[fingerprint]}"
    if key in state.seen:
        return None
    state.seen.add(key)
    state.evidence_seq += 1
    observation = make_observation(
        source_type,
        event,
        evidence_id=f"ev-{state.evidence_seq:04d}",
        query_id=query_id,
        source=source,
    )
    state.evidence.append(observation)
    state.context.absorb(observation["entities"])
    return observation


def _expand(state: RunState) -> None:
    delta = timedelta(hours=12)
    state.window_start = state.window_start - delta
    state.window_end = state.window_end + delta
    state.expansions += 1
    for question_id in list(state.context.empty_question_ids):
        state.context.answered.discard(question_id)
    state.context.empty_question_ids.clear()
    state.context.needs_expansion = False


def _answers(state: RunState, action: ToolAction, arguments: dict) -> list[str]:
    """Questions this action answers. The playbook names its own; a model's query has to earn them."""
    if action.tool == "expand_time_window":
        return []
    if action.question_id:
        return [action.question_id]
    return covered_questions(
        state.questions, state.context, action.tool, arguments, state.window_start, state.window_end
    )


def _query_key(action: ToolAction, arguments: dict) -> str:
    filters = {key: value for key, value in arguments.items() if key != "limit"}
    return json.dumps([action.tool, filters], sort_keys=True).casefold()


def _override_reason(
    state: RunState, action: ToolAction, fallback: ToolAction | None, settings: Settings
) -> str | None:
    """Why a model's proposal must give way to the playbook, or None when it may run."""
    if fallback is None:
        return None
    remaining = settings.max_tool_calls - state.tool_calls
    does_the_same = action.tool == fallback.tool and (
        action.tool == "finish"
        or fallback.question_id in _answers(state, action, _enforce_arguments(action, state, settings.max_events))
    )
    if not does_the_same and remaining <= open_question_count(state.questions, state.context) + 1:
        return "The remaining tool calls are reserved for open playbook questions and finishing"
    if fallback.tool == "finish":
        return None
    if action.tool == "finish":
        return "The model tried to finish with questions still open"
    if action.tool == "expand_time_window":
        return None
    arguments = _enforce_arguments(action, state, settings.max_events)
    if not any(arguments.get(key) for key in ("user", "host", "iocs")):
        return "The model proposed a query with no user, host, or indicator"
    if _query_key(action, arguments) in state.executed:
        return "The model repeated a query that already ran"
    return None


def _open_questions(state: RunState) -> list[str]:
    return [
        question.text
        for question in state.questions
        if question.id not in state.context.answered and question.tool not in CONTROL_TOOLS
    ]


def _record_step(state: RunState, action: ToolAction, arguments: dict, status: str, started_at: str) -> None:
    state.steps.append(
        {
            "id": f"st-{len(state.steps) + 1:04d}",
            "question": action.question,
            "tool": action.tool,
            "arguments": arguments,
            "status": status,
            "started_at": started_at,
            "finished_at": utc_iso(utc_now()),
        }
    )


def _finalize(state: RunState, status: str, stop_reason: str) -> dict:
    timeline = build_timeline(state.evidence)
    assessment, hypotheses, signals = assess(
        state.alert,
        state.evidence,
        get_catalog(),
        _open_questions(state),
        answered_questions=set(state.context.answered),
        truncated=sorted(state.truncated),
    )
    _audit(
        state,
        "assessment",
        f"Assessment verdict is {assessment['verdict']}",
        {"signals": signals, "hypotheses": hypotheses},
    )
    report = compose_report(state.alert, assessment, state.evidence, timeline, state.audit)
    _audit(state, "report", "Report generated from stored evidence", {})
    if status == "budget_exhausted":
        _audit(state, "budget", f"Stopped because {stop_reason}", {})
    return _snapshot(
        state,
        status=status,
        stop_reason=stop_reason,
        assessment=assessment,
        report=report,
        timeline=timeline,
    )


def start_investigation(alert_id: str) -> dict:
    row = get_alert_row(alert_id)
    if row is None:
        raise AlertNotFound(alert_id)
    investigation_id = f"inv-{uuid4().hex[:12]}"
    document = {
        "id": investigation_id,
        "alert_id": alert_id,
        "status": "running",
        "stop_reason": None,
        "metrics": {"duration_ms": 0, "tool_call_count": 0, "event_count": 0},
        "steps": [],
        "evidence": [],
        "timeline": [],
        "assessment": None,
        "report": None,
        "audit": [
            {
                "id": "au-0001",
                "kind": "investigation_started",
                "timestamp": utc_iso(utc_now()),
                "summary": f"Investigation started for alert {alert_id}",
                "details": {},
            }
        ],
    }
    InvestigationDocument.model_validate(document)
    insert_investigation(document)
    return {"id": investigation_id, "status": "running"}


def execute_investigation(investigation_id: str) -> dict:
    try:
        return _execute(investigation_id)
    except Exception as exc:
        existing = get_investigation(investigation_id)
        if existing is not None:
            existing["status"] = "failed"
            existing["stop_reason"] = "failed"
            audit = list(existing.get("audit") or [])
            audit.append(
                {
                    "id": f"au-{len(audit) + 1:04d}",
                    "kind": "error",
                    "timestamp": utc_iso(utc_now()),
                    "summary": "Investigation failed",
                    "details": {"error": str(exc)},
                }
            )
            existing["audit"] = audit
            try:
                InvestigationDocument.model_validate(existing)
                update_investigation(existing)
            except Exception:
                logger.exception("Could not persist the failed investigation")
        logger.exception("Investigation %s failed", investigation_id)
        raise


def _execute(investigation_id: str) -> dict:
    existing = get_investigation(investigation_id)
    if existing is None:
        raise KeyError(investigation_id)
    if existing["status"] in {"completed", "failed", "budget_exhausted"}:
        return existing
    alert_row = get_alert_row(existing["alert_id"])
    if alert_row is None:
        raise AlertNotFound(existing["alert_id"])
    alert = alert_row["alert"]
    settings = get_settings()
    detected = parse_datetime(alert["detected_at"])
    playbook = select_playbook(alert)
    questions = questions_for(playbook)
    state = RunState(
        investigation_id=investigation_id,
        alert=alert,
        playbook=playbook,
        questions=questions,
        context=context_from_alert(alert),
        window_start=detected - timedelta(minutes=settings.window_before_minutes),
        window_end=detected + timedelta(minutes=settings.window_after_minutes),
        audit=list(existing.get("audit") or []),
        started=time.perf_counter(),
    )
    _audit(
        state,
        "playbook",
        f"Selected the {playbook} playbook",
        {
            "questions": [
                question.as_question(False).model_dump() for question in questions if question.tool != "expand_time_window"
            ]
        },
    )
    _snapshot(state, status="running", stop_reason=None, timeline=[])

    while True:
        if time.perf_counter() - state.started >= settings.max_seconds:
            return _finalize(state, "budget_exhausted", "time_budget")
        if state.tool_calls >= settings.max_tool_calls:
            return _finalize(state, "budget_exhausted", "tool_call_budget")

        fallback = playbook_action(
            state.questions,
            state.context,
            state.window_start,
            state.window_end,
            settings.max_events,
            state.expansions,
            settings.max_window_expansions,
        )
        summary = bounded_summary(alert, state.evidence, _open_questions(state))
        action, source = choose_action(fallback, summary, settings)
        if action is None:
            return _finalize(state, "completed", "completed")
        details = {}
        if source == "llm":
            reason = _override_reason(state, action, fallback, settings)
            if reason is not None:
                details = {"override_reason": reason, "proposed_tool": action.tool}
                action, source = fallback, "playbook_override"
        _audit(
            state,
            "planner",
            f"Next action is {action.tool}",
            {"source": source, "question": action.question, "question_id": action.question_id, **details},
        )
        arguments = _enforce_arguments(action, state, settings.max_events)
        answers = _answers(state, action, arguments)
        started_at = utc_iso(utc_now())

        if action.tool == "expand_time_window" and state.expansions >= settings.max_window_expansions:
            _record_step(state, action, arguments, "rejected", started_at)
            state.tool_calls += 1
            _audit(state, "tool_call", "Time window expansion was rejected because the budget is spent", {})
            _snapshot(state, status="running", stop_reason=None)
            continue

        try:
            outcome = execute_tool(
                action.tool,
                arguments,
                window_start=state.window_start,
                window_end=state.window_end,
                scenarios_dir=settings.scenarios_dir,
                max_events=settings.max_events,
            )
        except UnknownToolError as exc:
            _record_step(state, action, arguments, "rejected", started_at)
            state.tool_calls += 1
            _audit(state, "tool_call", f"Rejected unknown tool {exc.name}", {"tool": exc.name})
            return _snapshot(state, status="failed", stop_reason="unknown_tool")
        except UnscopedQueryError as exc:
            _record_step(state, action, arguments, "rejected", started_at)
            state.tool_calls += 1
            _audit(state, "tool_call", f"Rejected {exc.name} because it named no user, host, or indicator", {})
            _snapshot(state, status="running", stop_reason=None)
            continue

        state.tool_calls += 1
        _record_step(state, action, arguments, "completed", started_at)
        added = 0
        if outcome["kind"] == "query":
            state.query_seq += 1
            state.executed.add(_query_key(action, arguments))
            query_id = f"qry-{state.query_seq:04d}"
            result = outcome["result"]
            source_name = result["source"]
            if result["truncated"]:
                state.truncated.add(outcome["source_type"])
            repeats: Counter[str] = Counter()
            for event in outcome["events"]:
                if _remember(state, outcome["source_type"], event, query_id, source_name, repeats) is not None:
                    added += 1
            if outcome["source_type"] == "threat_intel":
                found = {
                    str(event.get("indicator")).casefold()
                    for event in outcome["events"]
                    if event.get("indicator")
                }
                for indicator in arguments.get("iocs") or []:
                    if str(indicator).casefold() in found:
                        continue
                    miss = unknown_reputation_event(str(indicator), result["timestamp"])
                    if _remember(state, "threat_intel", miss, query_id, source_name, repeats) is not None:
                        added += 1
                if settings.external_ti_enabled:
                    _audit(
                        state,
                        "external_ti",
                        "External threat intelligence is enabled but v1 has no external provider; the local scenario feed was used",
                        {},
                    )
            if added == 0 and not state.evidence and answers:
                state.context.needs_expansion = True
                state.context.empty_question_ids.update(answers)
            _audit(
                state,
                "tool_result",
                f"{action.tool} stored {added} new observations",
                {"query_id": query_id, "truncated": result.get("truncated", False)},
            )
        elif outcome["kind"] == "expand":
            _expand(state)
            arguments = {"start": utc_iso(state.window_start), "end": utc_iso(state.window_end)}
            state.steps[-1]["arguments"] = arguments
            _audit(state, "window_expanded", "Time window expanded", arguments)
        else:
            _audit(state, "tool_result", "Planner finished the question list", {})

        state.context.answered.update(answers)
        if action.tool == "finish":
            return _finalize(state, "completed", "completed")
        _snapshot(state, status="running", stop_reason=None)


def run_investigation(alert_id: str) -> dict:
    """Run to completion on the calling thread. Tests and the API worker both use this path."""
    started = start_investigation(alert_id)
    return execute_investigation(started["id"])
