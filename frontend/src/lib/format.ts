const LABELS: Record<string, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  budget_exhausted: "Budget exhausted",
  rejected: "Rejected",
  tool_call_budget: "Tool call budget",
  time_budget: "Time budget",
  unknown_tool: "Unknown tool",
  likely_benign: "Likely benign",
  suspicious: "Suspicious",
  confirmed_threat: "Confirmed threat",
  observed: "Observed",
  inferred: "Inferred",
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
  informational: "Informational",
};

export function label(value: string | null | undefined): string {
  if (!value) return "—";
  return LABELS[value] ?? value;
}

export function display(value: unknown): string {
  if (value == null) return "—";
  if (typeof value === "string") return value.trim() ? value : "—";
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return "—";
}

export function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return `${date.toISOString().slice(0, 19).replace("T", " ")} Z`;
}

export function formatCount(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value)) return "—";
  return value.toLocaleString("en-US");
}

export function formatDuration(ms: number | null | undefined): string | null {
  if (ms == null || !Number.isFinite(ms) || ms < 1000) return null;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 2 : 1)} s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  return `${minutes}m ${rest}s`;
}

export function formatScalar(value: unknown): string {
  if (value == null || value === "") return "—";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  try {
    return JSON.stringify(value);
  } catch {
    return "—";
  }
}

export function alertPath(id: string): string {
  return `/alerts/${encodeURIComponent(id)}`;
}

export function investigationPath(id: string): string {
  return `/investigations/${encodeURIComponent(id)}`;
}

export function reportPath(id: string): string {
  return `/investigations/${encodeURIComponent(id)}/report`;
}
