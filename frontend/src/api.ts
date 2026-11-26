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
import {
  normalizeAlertDetail,
  normalizeAlertListItem,
  normalizeFieldMessages,
  normalizeIngest,
  normalizeInvestigation,
  normalizeInvestigationSummary,
  normalizeScenario,
  normalizeUploadResult,
  requireRecord,
  uniqueFieldErrors,
} from "./lib/normalize";

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

export async function listAlerts(): Promise<AlertListItem[]> {
  const data = requireRecord(await request("/api/alerts"), "GET /api/alerts");
  if (!Array.isArray(data.alerts)) throw new Error("Unexpected response from GET /api/alerts.");
  return data.alerts.map(normalizeAlertListItem);
}

export async function getAlert(id: string): Promise<{ alert: AlertDetail; warnings: FieldError[] }> {
  const data = requireRecord(await request(`/api/alerts/${encodeURIComponent(id)}`), "GET /api/alerts/{id}");
  const alert = normalizeAlertDetail(data.alert);
  const warnings = uniqueFieldErrors([...normalizeFieldMessages(data.warnings), ...alert.warnings]);
  return { alert: { ...alert, warnings }, warnings };
}

export async function listAlertInvestigations(id: string): Promise<InvestigationSummary[]> {
  const data = requireRecord(
    await request(`/api/alerts/${encodeURIComponent(id)}/investigations`),
    "GET /api/alerts/{id}/investigations",
  );
  if (!Array.isArray(data.investigations)) {
    throw new Error("Unexpected response from GET /api/alerts/{id}/investigations.");
  }
  return data.investigations.map(normalizeInvestigationSummary);
}

export async function createAlert(body: unknown): Promise<IngestResult> {
  return normalizeIngest(
    await request("/api/alerts", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  );
}

export async function uploadAlerts(file: File): Promise<UploadResult[]> {
  const form = new FormData();
  form.append("file", file);
  const data = requireRecord(await request("/api/alerts/upload", { method: "POST", body: form }), "POST /api/alerts/upload");
  if (!Array.isArray(data.results)) throw new Error("Unexpected response from POST /api/alerts/upload.");
  return data.results.map(normalizeUploadResult);
}

export async function listScenarios(): Promise<Scenario[]> {
  const data = requireRecord(await request("/api/scenarios"), "GET /api/scenarios");
  if (!Array.isArray(data.scenarios)) throw new Error("Unexpected response from GET /api/scenarios.");
  return data.scenarios.flatMap((item) => {
    const scenario = normalizeScenario(item);
    return scenario ? [scenario] : [];
  });
}

export async function loadScenario(id: string): Promise<IngestResult> {
  return normalizeIngest(
    await request(`/api/scenarios/${encodeURIComponent(id)}/load`, {
      method: "POST",
    }),
  );
}

export async function startInvestigation(alertId: string): Promise<{ id: string; status: string }> {
  const data = requireRecord(
    await request("/api/investigations", {
      method: "POST",
      body: JSON.stringify({ alert_id: alertId }),
    }),
    "POST /api/investigations",
  );
  const id = typeof data.id === "string" ? data.id : "";
  if (!id) throw new Error("Investigation response is missing id.");
  return { id, status: typeof data.status === "string" ? data.status : "" };
}

export async function getInvestigation(id: string, signal?: AbortSignal): Promise<Investigation> {
  return normalizeInvestigation(
    await request(`/api/investigations/${encodeURIComponent(id)}`, { signal }),
  );
}
