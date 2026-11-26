import type { FieldError } from "../types";

export function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Unexpected response from ${label}.`);
  }
  return value as Record<string, unknown>;
}

/** Field messages from untyped input, such as router location state. */
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
    const field = typeof record.field === "string" ? record.field.trim() : "";
    const message = typeof record.message === "string" ? record.message.trim() : "";
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
