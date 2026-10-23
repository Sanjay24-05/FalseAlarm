export interface FieldError {
  field: string;
  message: string;
}

export interface Ioc {
  type: string;
  value: string;
}

export interface AlertListItem {
  id: string;
  source: string;
  name: string;
  severity: string;
  detected_at: string;
  username: string;
  hostname: string;
  src_ip: string;
  verdict: string | null;
}

export interface AlertDetail {
  id: string;
  source: string;
  external_id: string | null;
  name: string;
  description: string;
  severity: string;
  detected_at: string;
  src_ip: string;
  dst_ip: string;
  username: string;
  hostname: string;
  file_hashes: string[];
  domains: string[];
  urls: string[];
  mitre_techniques: string[];
  raw: unknown;
  iocs: Ioc[];
  warnings: FieldError[];
  fingerprint: string | null;
  created_at: string | null;
}

export interface IngestResult {
  alert: AlertDetail;
  warnings: FieldError[];
  duplicate: boolean;
}

/** One item from POST /api/alerts/upload. A bad item has errors and no alert. */
export interface UploadResult {
  alert: AlertDetail | null;
  warnings: FieldError[];
  duplicate: boolean;
  errors: FieldError[];
}

export interface Scenario {
  id: string;
  title: string;
  description: string;
  expected_verdict: string;
}

export interface AlertLocationState {
  duplicate: boolean;
  warnings: FieldError[];
}

export interface InvestigationStep {
  id: string;
  question: string;
  tool: string;
  arguments: unknown;
  status: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface EvidenceEntities {
  ips: string[];
  users: string[];
  hosts: string[];
  domains: string[];
  hashes: string[];
}

export interface Evidence {
  id: string;
  source: string;
  source_type: string;
  observed_at: string;
  query_id: string;
  summary: string;
  entities: EvidenceEntities;
  kind: string;
  raw: unknown;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  summary: string;
  relationship: string;
  evidence_ids: string[];
  source: string;
}

export interface EvidenceStatement {
  evidence_id: string;
  statement: string;
}

export interface Assessment {
  severity: string;
  verdict: string;
  confidence: unknown;
  confidence_rationale: string;
  impact: string;
  supporting_evidence: EvidenceStatement[];
  contradicting_evidence: EvidenceStatement[];
  missing_evidence: string[];
  unresolved_questions: string[];
  recommended_actions: string[];
  escalate: boolean | null;
  escalation_reason: string;
}

export interface Report {
  incident_summary: unknown;
  alert_details: unknown;
  triage: unknown;
  executive_explanation: unknown;
  timeline: unknown;
  evidence: unknown;
  correlated_indicators: unknown;
  threat_intelligence: unknown;
  attack_sequence: unknown;
  confidence_and_gaps: unknown;
  recommended_actions: unknown;
  escalation: unknown;
  audit_trail: unknown;
}

export interface AuditEntry {
  id: string;
  kind: string;
  timestamp: string;
  summary: string;
  details: unknown;
}

export interface Metrics {
  duration_ms: number | null;
  tool_call_count: number | null;
  event_count: number | null;
}

export interface Investigation {
  id: string;
  alert_id: string;
  status: string;
  stop_reason: string | null;
  metrics: Metrics;
  steps: InvestigationStep[];
  evidence: Evidence[];
  timeline: TimelineEvent[];
  assessment: Assessment | null;
  report: Report | null;
  audit: AuditEntry[];
}

export const TERMINAL_STATUSES = ["completed", "failed", "budget_exhausted"] as const;

export function isTerminalStatus(status: string): boolean {
  return (TERMINAL_STATUSES as readonly string[]).includes(status);
}
