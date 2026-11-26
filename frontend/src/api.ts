import type * as Api from "./generated/api";
import type {
  AlertDetail,
  AlertListItem,
  FieldError,
  IngestResult,
  Investigation,
  InvestigationSummary,
  Scenario,
  UploadResult,
} from "./types";
import { requireRecord, uniqueFieldErrors } from "./lib/normalize";

export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;
  readonly fieldErrors: FieldError[];

  constructor(status: number, body: unknown, fallback?: string) {
    super(messageFrom(status, body, fallback));
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    this.fieldErrors = fieldErrorsFrom(body);
  }
}

export function isAbortError(err: unknown): boolean {
  return err instanceof Error && err.name === "AbortError";
}

function fieldErrorsFrom(body: unknown): FieldError[] {
  if (!body || typeof body !== "object") return [];
  const errors = (body as { errors?: unknown }).errors;
  if (!Array.isArray(errors)) return [];
  return errors.flatMap((item) => {
    if (!item || typeof item !== "object") return [];
    const field = (item as { field?: unknown }).field;
    const message = (item as { message?: unknown }).message;
    if (typeof field !== "string" || typeof message !== "string") return [];
    return [{ field, message }];
  });
}

function messageFrom(status: number, body: unknown, fallback?: string): string {
  const detail = detailFrom(body);
  if (detail) return detail;
  const fields = fieldErrorsFrom(body);
  if (fields.length > 0) {
    return fields.map((item) => (item.field ? `${item.field}: ${item.message}` : item.message)).join(" ");
  }
  if (fallback) return fallback;
  if (status === 404) return "Not found.";
  if (status === 0) return "Cannot reach the API. Requests to /api are proxied to 127.0.0.1:8000.";
  return `Request failed (${status}).`;
}

function detailFrom(body: unknown): string | null {
  if (typeof body === "string" && body.trim()) return body.trim().slice(0, 500);
  if (!body || typeof body !== "object") return null;
  const record = body as Record<string, unknown>;
  if (typeof record.message === "string" && record.message.trim()) return record.message.trim();
  if (typeof record.detail === "string" && record.detail.trim()) return record.detail.trim();
  return null;
}

async function request(path: string, init?: RequestInit): Promise<unknown> {
  const headers = new Headers(init?.headers);
  const isForm = typeof FormData !== "undefined" && init?.body instanceof FormData;
  if (init?.body != null && !isForm && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (!headers.has("Accept")) headers.set("Accept", "application/json");

  let response: Response;
  try {
    response = await fetch(path, { ...init, headers });
  } catch (err) {
    if (isAbortError(err)) throw err;
    throw new ApiError(0, null);
  }

  const text = await response.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text) as unknown;
    } catch {
      data = { message: text.slice(0, 500) };
    }
  }

  if (!response.ok) throw new ApiError(response.status, data);
  if (data == null) throw new ApiError(response.status, null, "Empty response from the API.");
  return data;
}

/** The response body as the generated type, after checking it is an object with the given array or id. */
function shaped<T>(value: unknown, label: string, check: (record: Record<string, unknown>) => boolean): T {
  const record = requireRecord(value, label);
  if (!check(record)) throw new Error(`Unexpected response from ${label}.`);
  return record as T;
}

const hasArray = (key: string) => (record: Record<string, unknown>) => Array.isArray(record[key]);
const hasId = (record: Record<string, unknown>) => typeof record.id === "string" && record.id !== "";
const hasAlert = (record: Record<string, unknown>) =>
  !!record.alert && typeof record.alert === "object" && hasId(record.alert as Record<string, unknown>);

export async function listAlerts(): Promise<AlertListItem[]> {
  return shaped<Api.AlertList>(await request("/api/alerts"), "GET /api/alerts", hasArray("alerts")).alerts;
}

export async function getAlert(id: string): Promise<{ alert: AlertDetail; warnings: FieldError[] }> {
  const label = "GET /api/alerts/{id}";
  const data = shaped<Api.AlertView>(await request(`/api/alerts/${encodeURIComponent(id)}`), label, hasAlert);
  const warnings = uniqueFieldErrors(data.warnings ?? []);
  return { alert: { ...data.alert, warnings }, warnings };
}

export async function listAlertInvestigations(id: string): Promise<InvestigationSummary[]> {
  const label = "GET /api/alerts/{id}/investigations";
  const path = `/api/alerts/${encodeURIComponent(id)}/investigations`;
  return shaped<Api.InvestigationList>(await request(path), label, hasArray("investigations")).investigations;
}

function ingested(value: unknown, label: string): IngestResult {
  const data = shaped<Api.IngestResponse>(value, label, hasAlert);
  return { ...data, warnings: uniqueFieldErrors(data.warnings ?? []), duplicate: data.duplicate === true };
}

export async function createAlert(body: unknown): Promise<IngestResult> {
  return ingested(await request("/api/alerts", { method: "POST", body: JSON.stringify(body) }), "POST /api/alerts");
}

export async function uploadAlerts(file: File): Promise<UploadResult[]> {
  const form = new FormData();
  form.append("file", file);
  const label = "POST /api/alerts/upload";
  const data = shaped<Api.UploadResponse>(
    await request("/api/alerts/upload", { method: "POST", body: form }),
    label,
    hasArray("results"),
  );
  return data.results.map((item) =>
    "alert" in item
      ? { alert: item.alert, warnings: item.warnings, duplicate: item.duplicate, errors: [] }
      : { alert: null, warnings: [], duplicate: false, errors: item.errors },
  );
}

export async function listScenarios(): Promise<Scenario[]> {
  return shaped<Api.ScenarioList>(await request("/api/scenarios"), "GET /api/scenarios", hasArray("scenarios")).scenarios;
}

export async function loadScenario(id: string): Promise<IngestResult> {
  const path = `/api/scenarios/${encodeURIComponent(id)}/load`;
  return ingested(await request(path, { method: "POST" }), "POST /api/scenarios/{id}/load");
}

export async function startInvestigation(alertId: string): Promise<Api.InvestigationStarted> {
  const value = await request("/api/investigations", { method: "POST", body: JSON.stringify({ alert_id: alertId }) });
  return shaped<Api.InvestigationStarted>(value, "POST /api/investigations", hasId);
}

export async function getInvestigation(id: string, signal?: AbortSignal): Promise<Investigation> {
  const value = await request(`/api/investigations/${encodeURIComponent(id)}`, { signal });
  return shaped<Investigation>(value, "GET /api/investigations/{id}", hasId);
}
