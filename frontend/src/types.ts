// API shapes come from src/generated/api.ts, which is generated from the backend's models.
// This file only names them for the console and adds the few shapes the console builds itself.
import type * as Api from "./generated/api";

export type FieldError = Api.FieldMessage;
export type Ioc = Api.IOC;
export type AlertListItem = Api.AlertSummary;
export type Scenario = Api.ScenarioSummary;
export type InvestigationSummary = Api.InvestigationSummary;
export type Investigation = Api.InvestigationDocument;
export type InvestigationStep = Api.Step;
export type Evidence = Api.Evidence;
export type TimelineEvent = Api.TimelineEvent;
export type EvidenceStatement = Api.EvidenceStatement;
export type Assessment = Api.Assessment;
export type Report = Api.Report;
export type AuditEntry = Api.AuditEntry;

/** An alert with the warnings recorded when it was ingested. */
export type AlertDetail = Api.Alert & { warnings: FieldError[] };
export type IngestResult = Api.IngestResponse;

/** One item from POST /api/alerts/upload. A bad item has errors and no alert. */
export interface UploadResult {
  alert: Api.Alert | null;
  warnings: FieldError[];
  duplicate: boolean;
  errors: FieldError[];
}

export interface AlertLocationState {
  duplicate: boolean;
  warnings: FieldError[];
}

export const TERMINAL_STATUSES = ["completed", "failed", "budget_exhausted"] as const;

export function isTerminalStatus(status: string): boolean {
  return (TERMINAL_STATUSES as readonly string[]).includes(status);
}
