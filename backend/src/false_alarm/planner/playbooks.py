"""Playbook selection. The highest-priority question with known inputs wins."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from false_alarm.agent.context import Context
from false_alarm.domain.models import Question
from false_alarm.planner.actions import ToolAction
from false_alarm.util import unique_strings, utc_iso

_AUTH_MITRE = {"T1110", "T1078", "T1021", "T1111"}
_MALWARE_MITRE = {"T1204", "T1059", "T1105", "T1203", "T1003"}
_OUTBOUND_MITRE = {"T1048", "T1041", "T1071", "T1571"}
_AUTH_WORDS = {"login", "logins", "logon", "auth", "authentication", "password", "brute", "failed", "signin"}
_MALWARE_WORDS = {"malware", "ransomware", "trojan", "virus", "hash"}
_OUTBOUND_WORDS = {"outbound", "exfil", "exfiltration", "beacon", "c2"}
_PREFERENCE = {"authentication": 3, "malware": 2, "outbound": 1, "generic": 0}


CONTROL_TOOLS = frozenset({"finish", "expand_time_window"})


@dataclass(frozen=True)
class QuestionTemplate:
    id: str
    priority: int
    text: str
    tool: str
    requires_any: tuple[str, ...] = ()
    requires_all: tuple[str, ...] = ()

    def as_question(self, answered: bool) -> Question:
        return Question(
            id=self.id,
            text=self.text,
            priority=self.priority,
            tool=self.tool,
            answered=answered,
        )


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def _technique_bases(techniques: list[str]) -> set[str]:
    bases = set()
    for item in techniques:
        bases.add(str(item).upper().split(".")[0])
    return bases


def select_playbook(alert: dict) -> str:
    text = f"{alert.get('name') or ''} {alert.get('description') or ''}"
    tokens = _tokens(text)
    bases = _technique_bases(alert.get("mitre_techniques") or [])
    scores = {"authentication": 0, "malware": 0, "outbound": 0, "generic": 0}
    if bases & _AUTH_MITRE:
        scores["authentication"] += 2
    if tokens & _AUTH_WORDS:
        scores["authentication"] += 2
    if bases & _MALWARE_MITRE:
        scores["malware"] += 2
    if tokens & _MALWARE_WORDS:
        scores["malware"] += 2
    if bases & _OUTBOUND_MITRE:
        scores["outbound"] += 2
    if tokens & _OUTBOUND_WORDS:
        scores["outbound"] += 2
    best = max(scores, key=lambda name: (scores[name], _PREFERENCE[name]))
    if scores[best] == 0:
        return "generic"
    return best


def _auth_questions() -> list[QuestionTemplate]:
    return [
        QuestionTemplate("q_expand", 5, "Widen the time window because a query returned no events.", "expand_time_window"),
        QuestionTemplate(
            "q_auth_user",
            10,
            "What authentication activity exists for the target account?",
            "query_authentication",
            requires_any=("username",),
        ),
        QuestionTemplate(
            "q_auth_ip",
            20,
            "What authentication activity exists from the source IP, including other accounts?",
            "query_authentication",
            requires_any=("src_ip",),
        ),
        QuestionTemplate(
            "q_firewall",
            30,
            "What network activity followed for this account, including sensitive systems and outbound transfers?",
            "query_firewall",
            requires_any=("username", "hostname", "src_ip"),
        ),
        QuestionTemplate(
            "q_endpoint",
            40,
            "Is there endpoint activity for this user or host?",
            "query_endpoint",
            requires_any=("username", "hostname", "hashes"),
        ),
        QuestionTemplate(
            "q_dns",
            50,
            "What DNS queries are associated with this user or host?",
            "query_dns",
            requires_any=("username", "hostname", "src_ip", "domains"),
        ),
        QuestionTemplate(
            "q_related",
            60,
            "Are there related alerts for this user, host, or source?",
            "query_related_alerts",
            requires_any=("username", "hostname", "src_ip"),
        ),
        QuestionTemplate(
            "q_ti",
            70,
            "What is the local reputation of the indicators tied to this alert?",
            "lookup_threat_intel",
            requires_any=("src_ip", "external_ips", "domains", "hashes"),
        ),
        QuestionTemplate("q_finish", 1000, "The available investigation questions are answered.", "finish"),
    ]


def questions_for(playbook: str) -> list[QuestionTemplate]:
    if playbook == "malware":
        return [
            QuestionTemplate("q_expand", 5, "Widen the time window because a query returned no events.", "expand_time_window"),
            QuestionTemplate("q_endpoint", 10, "Is there endpoint activity for this user, host, or file hash?", "query_endpoint", requires_any=("username", "hostname", "hashes")),
            QuestionTemplate("q_ti", 20, "What is the local reputation of the file hashes and other indicators?", "lookup_threat_intel", requires_any=("src_ip", "external_ips", "domains", "hashes")),
            QuestionTemplate("q_related", 30, "Are there related alerts for this user, host, or source?", "query_related_alerts", requires_any=("username", "hostname", "src_ip")),
            QuestionTemplate("q_auth_user", 40, "What authentication activity exists for the target account?", "query_authentication", requires_any=("username",)),
            QuestionTemplate("q_auth_ip", 50, "What authentication activity exists from the source IP, including other accounts?", "query_authentication", requires_any=("src_ip",)),
            QuestionTemplate("q_firewall", 60, "What network activity followed for this account?", "query_firewall", requires_any=("username", "hostname", "src_ip")),
            QuestionTemplate("q_dns", 70, "What DNS queries are associated with this user or host?", "query_dns", requires_any=("username", "hostname", "src_ip", "domains")),
            QuestionTemplate("q_finish", 1000, "The available investigation questions are answered.", "finish"),
        ]
    if playbook == "outbound":
        return [
            QuestionTemplate("q_expand", 5, "Widen the time window because a query returned no events.", "expand_time_window"),
            QuestionTemplate("q_firewall", 10, "What outbound and internal network activity is associated with this account?", "query_firewall", requires_any=("username", "hostname", "src_ip")),
            QuestionTemplate("q_dns", 20, "What DNS queries are associated with this user or host?", "query_dns", requires_any=("username", "hostname", "src_ip", "domains")),
            QuestionTemplate("q_ti", 30, "What is the local reputation of the external indicators?", "lookup_threat_intel", requires_any=("src_ip", "external_ips", "domains", "hashes")),
            QuestionTemplate("q_endpoint", 40, "Is there endpoint activity for this user or host?", "query_endpoint", requires_any=("username", "hostname", "hashes")),
            QuestionTemplate("q_auth_user", 50, "What authentication activity exists for the target account?", "query_authentication", requires_any=("username",)),
            QuestionTemplate("q_auth_ip", 60, "What authentication activity exists from the source IP?", "query_authentication", requires_any=("src_ip",)),
            QuestionTemplate("q_related", 70, "Are there related alerts for this user, host, or source?", "query_related_alerts", requires_any=("username", "hostname", "src_ip")),
            QuestionTemplate("q_finish", 1000, "The available investigation questions are answered.", "finish"),
        ]
    return _auth_questions()


def _unlooked_indicators(context: Context) -> list[str]:
    values: list[str | None] = [context.src_ip] if context.src_ip else []
    values.extend(sorted(context.external_ips))
    values.extend(sorted(context.domains))
    values.extend(sorted(context.hashes))
    looked_up = {item.casefold() for item in context.looked_up}
    return [item for item in unique_strings(values) if item.casefold() not in looked_up]


def _available(question: QuestionTemplate, context: Context, expansions: int, max_expansions: int) -> bool:
    if question.tool == "expand_time_window":
        return context.needs_expansion and expansions < max_expansions
    if question.tool == "lookup_threat_intel":
        # Indicators keep arriving as evidence is stored, so the lookup stays open while any are unrated.
        return bool(_unlooked_indicators(context))
    if question.id in context.answered:
        return False
    if question.requires_all and not all(context.known(key) for key in question.requires_all):
        return False
    if question.requires_any and not any(context.known(key) for key in question.requires_any):
        return False
    return True


def _covers(arguments: dict, wanted: dict) -> bool:
    """Filters are alternatives, so a query covers another when it includes every one of its filters."""
    for key in ("user", "host"):
        if wanted.get(key) and str(arguments.get(key) or "").casefold() != str(wanted[key]).casefold():
            return False
    have = {str(item).casefold() for item in arguments.get("iocs") or []}
    return {str(item).casefold() for item in wanted.get("iocs") or []} <= have


def covered_questions(
    questions: list[QuestionTemplate], context: Context, tool: str, arguments: dict, start: datetime, end: datetime
) -> list[str]:
    """Open questions that this query answers at least as fully as the playbook's own query would."""
    covered = []
    for question in questions:
        if question.tool != tool or question.tool in CONTROL_TOOLS or not _available(question, context, 0, 0):
            continue
        wanted = build_arguments(question, context, start, end, 0)
        if any(wanted.get(key) for key in ("user", "host", "iocs")) and _covers(arguments, wanted):
            covered.append(question.id)
    return covered


def open_question_count(questions: list[QuestionTemplate], context: Context) -> int:
    return sum(
        1 for question in questions if question.tool not in CONTROL_TOOLS and _available(question, context, 0, 0)
    )


def next_question(
    questions: list[QuestionTemplate],
    context: Context,
    expansions: int,
    max_expansions: int,
) -> QuestionTemplate | None:
    available = [
        question
        for question in questions
        if _available(question, context, expansions, max_expansions)
    ]
    if not available:
        return None
    return min(available, key=lambda question: (question.priority, question.id))


def build_arguments(
    question: QuestionTemplate,
    context: Context,
    start: datetime,
    end: datetime,
    limit: int,
) -> dict:
    args: dict = {"start": utc_iso(start), "end": utc_iso(end), "limit": limit}
    if question.id == "q_auth_user":
        args["user"] = context.username
        return args
    if question.id == "q_auth_ip":
        args["iocs"] = [context.src_ip] if context.src_ip else []
        return args
    if question.tool == "lookup_threat_intel":
        args["iocs"] = _unlooked_indicators(context)
        return args
    if question.tool in {"query_firewall", "query_endpoint", "query_dns", "query_related_alerts"}:
        if context.username:
            args["user"] = context.username
        if context.hostname:
            args["host"] = context.hostname
        if question.tool == "query_endpoint" and context.hashes:
            args["iocs"] = sorted(context.hashes)
        if question.tool == "query_dns" and context.domains:
            args["iocs"] = sorted(context.domains)
        # Without a host, records that carry only an address are reachable only through the source IP.
        if not context.hostname and context.src_ip:
            args["iocs"] = unique_strings([*args.get("iocs", []), context.src_ip])
        return args
    if question.tool == "expand_time_window":
        return {"start": args["start"], "end": args["end"]}
    return {}


def playbook_action(
    questions: list[QuestionTemplate],
    context: Context,
    start: datetime,
    end: datetime,
    limit: int,
    expansions: int,
    max_expansions: int,
) -> ToolAction | None:
    question = next_question(questions, context, expansions, max_expansions)
    if question is None:
        return None
    return ToolAction(
        tool=question.tool,
        arguments=build_arguments(question, context, start, end, limit),
        question=question.text,
        question_id=question.id,
    )
