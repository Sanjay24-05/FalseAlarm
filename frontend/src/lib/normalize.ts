import type {
  AlertDetail,
  AlertListItem,
  Assessment,
  AuditEntry,
  Evidence,
  EvidenceStatement,
  FieldError,
  IngestResult,
  Investigation,
  InvestigationStep,
  InvestigationSummary,
  Ioc,
  Report,
  Scenario,
  TimelineEvent,
  UploadResult,
} from "../types";

function asRecord(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}

export function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Unexpected response from ${label}.`);
  }
  return value as Record<string, unknown>;
}

function asString(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return "";
}

function asNullableString(value: unknown): string | null {
  if (value == null) return null;
  const text = asString(value);
  return text ? text : null;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => {
      if (typeof item === "string") return item;
      if (typeof item === "number" || typeof item === "boolean") return String(item);
      return "";
    })
    .filter((item) => item.length > 0);
}

function asNumberOrNull(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() && Number.isFinite(Number(value))) return Number(value);
  return null;
}

export function normalizeFieldMessages(value: unknown): FieldError[] {
  if (!Array.isArray(value)) return [];
  const messages: FieldError[] = [];
  for (const item of value) {
    if (typeof item === "string") {
      const message = item.trim();
      if (message) messages.push({ field: "", message });
      continue;
    }
    if (!item || typeof item !== "object") continue;
    const record = item as Record<string, unknown>;
    const field = asString(record.field).trim();
    const message = asString(record.message).trim();
    if (!field && !message) continue;
    messages.push({ field, message: message || field });
  }
  return messages;
}

export function uniqueFieldErrors(values: FieldError[]): FieldError[] {
  const seen = new Set<string>();
  const unique: FieldError[] = [];
  for (const item of values) {
    const key = `${item.field}\0${item.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(item);
  }
  return unique;
}

function normalizeIocs(value: unknown): Ioc[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (typeof item === "string") return [{ type: "ioc", value: item }];
    if (!item || typeof item !== "object") return [];
    const record = item as Record<string, unknown>;
    const iocValue = asString(record.value);
    if (!iocValue) return [];
    return [{ type: asString(record.type) || "ioc", value: iocValue }];
  });
}

export function normalizeAlertDetail(value: unknown): AlertDetail {
  const record = requireRecord(value, "alert");
  const id = asString(record.id);
  if (!id) throw new Error("Alert response is missing id.");
  return {
    id,
    source: asString(record.source),
    external_id: asNullableString(record.external_id),
    name: asString(record.name),
    description: asString(record.description),
    severity: asString(record.severity),
    detected_at: asString(record.detected_at),
    src_ip: asString(record.src_ip),
    dst_ip: asString(record.dst_ip),
    username: asString(record.username),
    hostname: asString(record.hostname),
    file_hashes: asStringArray(record.file_hashes),
    domains: asStringArray(record.domains),
    urls: asStringArray(record.urls),
    mitre_techniques: asStringArray(record.mitre_techniques),
    raw: record.raw ?? {},
    iocs: normalizeIocs(record.iocs),
    warnings: normalizeFieldMessages(record.warnings),
    fingerprint: asNullableString(record.fingerprint),
    created_at: asNullableString(record.created_at),
  };
}

export function normalizeAlertListItem(value: unknown): AlertListItem {
  const record = asRecord(value);
  return {
    id: asString(record.id),
    source: asString(record.source),
    name: asString(record.name),
    severity: asString(record.severity),
    detected_at: asString(record.detected_at),
    username: asString(record.username),
    hostname: asString(record.hostname),
    src_ip: asString(record.src_ip),
    verdict: asNullableString(record.verdict),
    latest_investigation_id: asNullableString(record.latest_investigation_id),
  };
}

export function normalizeInvestigationSummary(value: unknown): InvestigationSummary {
  const record = asRecord(value);
  return {
    id: asString(record.id),
    status: asString(record.status) || "unknown",
    stop_reason: asNullableString(record.stop_reason),
    verdict: asNullableString(record.verdict),
    created_at: asString(record.created_at),
    updated_at: asString(record.updated_at),
  };
}

export function normalizeIngest(value: unknown): IngestResult {
  const record = requireRecord(value, "ingest");
  const alert = normalizeAlertDetail(record.alert);
  const warnings = uniqueFieldErrors([...normalizeFieldMessages(record.warnings), ...alert.warnings]);
  return {
    alert: { ...alert, warnings },
    warnings,
    duplicate: record.duplicate === true,
  };
}

export function normalizeUploadResult(value: unknown): UploadResult {
  const record = requireRecord(value, "POST /api/alerts/upload item");
  const errors = normalizeFieldMessages(record.errors);
  if (record.alert == null) {
    return {
      alert: null,
      warnings: normalizeFieldMessages(record.warnings),
      duplicate: record.duplicate === true,
      errors,
    };
  }
  const ingested = normalizeIngest(record);
  return { ...ingested, errors };
}

export function normalizeScenario(value: unknown): Scenario | null {
  const record = asRecord(value);
  const id = asString(record.id);
  if (!id) return null;
  return {
    id,
    title: asString(record.title) || id,
    description: asString(record.description),
    expected_verdict: asString(record.expected_verdict),
  };
}

function normalizeStep(value: unknown): InvestigationStep {
  const record = asRecord(value);
  return {
    id: asString(record.id),
    question: asString(record.question),
    tool: asString(record.tool),
    arguments: "arguments" in record ? (record.arguments ?? null) : null,
    status: asString(record.status),
    started_at: asNullableString(record.started_at),
    finished_at: asNullableString(record.finished_at),
  };
}

function normalizeEvidence(value: unknown): Evidence {
  const record = asRecord(value);
  const entities = asRecord(record.entities);
  return {
    id: asString(record.id),
    source: asString(record.source),
    source_type: asString(record.source_type),
    observed_at: asString(record.observed_at),
    query_id: asString(record.query_id),
    summary: asString(record.summary),
    entities: {
      ips: asStringArray(entities.ips),
      users: asStringArray(entities.users),
      hosts: asStringArray(entities.hosts),
      domains: asStringArray(entities.domains),
      hashes: asStringArray(entities.hashes),
    },
    kind: asString(record.kind),
    raw: "raw" in record ? record.raw : null,
  };
}

function normalizeTimeline(value: unknown): TimelineEvent {
  const record = asRecord(value);
  return {
    id: asString(record.id),
    timestamp: asString(record.timestamp),
    summary: asString(record.summary),
    relationship: asString(record.relationship),
    evidence_ids: asStringArray(record.evidence_ids),
    source: asString(record.source),
  };
}

function normalizeStatements(value: unknown): EvidenceStatement[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => {
    const record = asRecord(item);
    return {
      evidence_id: asString(record.evidence_id),
      statement: asString(record.statement),
    };
  });
}

function normalizeAssessment(value: unknown): Assessment | null {
  if (value == null) return null;
  if (typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  return {
    severity: asString(record.severity),
    verdict: asString(record.verdict),
    confidence: record.confidence ?? null,
    confidence_rationale: asString(record.confidence_rationale),
    impact: asString(record.impact),
    supporting_evidence: normalizeStatements(record.supporting_evidence),
    contradicting_evidence: normalizeStatements(record.contradicting_evidence),
    missing_evidence: asStringArray(record.missing_evidence),
    unresolved_questions: asStringArray(record.unresolved_questions),
    recommended_actions: asStringArray(record.recommended_actions),
    escalate: typeof record.escalate === "boolean" ? record.escalate : null,
    escalation_reason: asString(record.escalation_reason),
  };
}

function normalizeReport(value: unknown): Report | null {
  if (value == null) return null;
  if (typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  return {
    incident_summary: record.incident_summary ?? null,
    alert_details: record.alert_details ?? null,
    triage: record.triage ?? null,
    executive_explanation: record.executive_explanation ?? null,
    timeline: record.timeline ?? null,
    evidence: record.evidence ?? null,
    correlated_indicators: record.correlated_indicators ?? null,
    threat_intelligence: record.threat_intelligence ?? null,
    attack_sequence: record.attack_sequence ?? null,
    confidence_and_gaps: record.confidence_and_gaps ?? null,
    recommended_actions: record.recommended_actions ?? null,
    escalation: record.escalation ?? null,
    audit_trail: record.audit_trail ?? null,
  };
}

function normalizeAudit(value: unknown): AuditEntry {
  const record = asRecord(value);
  return {
    id: asString(record.id),
    kind: asString(record.kind),
    timestamp: asString(record.timestamp),
    summary: asString(record.summary),
    details: "details" in record ? record.details : null,
  };
}

export function normalizeInvestigation(value: unknown): Investigation {
  const record = requireRecord(value, "GET /api/investigations/{id}");
  const id = asString(record.id);
  if (!id) throw new Error("Investigation response is missing id.");
  const metrics = asRecord(record.metrics);
  return {
    id,
    alert_id: asString(record.alert_id),
    status: asString(record.status) || "unknown",
    stop_reason: asNullableString(record.stop_reason),
    metrics: {
      duration_ms: asNumberOrNull(metrics.duration_ms),
      tool_call_count: asNumberOrNull(metrics.tool_call_count),
      event_count: asNumberOrNull(metrics.event_count),
    },
    steps: Array.isArray(record.steps) ? record.steps.map(normalizeStep) : [],
    evidence: Array.isArray(record.evidence) ? record.evidence.map(normalizeEvidence) : [],
    timeline: Array.isArray(record.timeline) ? record.timeline.map(normalizeTimeline) : [],
    assessment: normalizeAssessment(record.assessment),
    report: normalizeReport(record.report),
    audit: Array.isArray(record.audit) ? record.audit.map(normalizeAudit) : [],
  };
}
