"""Pydantic models for the stable investigation contract."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["informational", "low", "medium", "high", "critical"]
Verdict = Literal["likely_benign", "suspicious", "confirmed_threat"]
Confidence = Literal["low", "medium", "high"]
Relationship = Literal["observed", "inferred"]
InvestigationStatus = Literal["queued", "running", "completed", "failed", "budget_exhausted"]
IOCType = Literal["ipv4", "ipv6", "domain", "md5", "sha1", "sha256", "url", "email", "hostname"]


class IOC(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: IOCType
    value: str


class Question(BaseModel):
    """An investigation question the planner can still ask."""

    model_config = ConfigDict(extra="forbid")

    id: str
    text: str
    priority: int
    tool: str
    answered: bool = False


class Alert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    source: str
    name: str
    description: str
    severity: Severity
    detected_at: str
    src_ip: str | None
    dst_ip: str | None
    username: str | None
    hostname: str | None
    file_hashes: list[str]
    domains: list[str]
    urls: list[str]
    mitre_techniques: list[str]
    raw: dict[str, Any]
    iocs: list[IOC]


class FieldMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str
    message: str


class Entities(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ips: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    source: str
    source_type: str
    observed_at: str
    query_id: str
    summary: str
    entities: Entities
    kind: Literal["observation"]
    raw: dict[str, Any]


class TimelineEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    timestamp: str
    summary: str
    relationship: Relationship
    evidence_ids: list[str]
    source: str


class EvidenceStatement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    statement: str


class Hypothesis(BaseModel):
    """A claim the assessment is testing. Status is set by rules, not by an LLM."""

    model_config = ConfigDict(extra="forbid")

    id: str
    statement: str
    status: Literal["open", "supported", "refuted"]
    evidence_ids: list[str]


class Assessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Severity
    verdict: Verdict
    confidence: Confidence
    confidence_rationale: str
    impact: str
    supporting_evidence: list[EvidenceStatement]
    contradicting_evidence: list[EvidenceStatement]
    missing_evidence: list[str]
    unresolved_questions: list[str]
    recommended_actions: list[str]
    escalate: bool
    escalation_reason: str


class Report(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_summary: str
    alert_details: str
    triage: str
    executive_explanation: str
    timeline: str
    evidence: str
    correlated_indicators: str
    threat_intelligence: str
    attack_sequence: str
    confidence_and_gaps: str
    recommended_actions: str
    escalation: str
    audit_trail: str


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    question: str
    tool: str
    arguments: dict[str, Any]
    status: Literal["completed", "rejected", "failed"]
    started_at: str
    finished_at: str


class Metrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    duration_ms: int
    tool_call_count: int
    event_count: int


class AuditEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str
    timestamp: str
    summary: str
    details: dict[str, Any]


class InvestigationDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    alert_id: str
    status: InvestigationStatus
    stop_reason: str | None
    metrics: Metrics
    steps: list[Step]
    evidence: list[Evidence]
    timeline: list[TimelineEvent]
    assessment: Assessment | None
    report: Report | None
    audit: list[AuditEntry]
