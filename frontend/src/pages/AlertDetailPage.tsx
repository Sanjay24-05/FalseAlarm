import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { ApiError, getAlert, listAlertInvestigations, startInvestigation } from "../api";
import { JsonBlock } from "../components/RenderValue";
import {
  Button,
  EmptyState,
  ErrorBanner,
  ErrorState,
  FieldGrid,
  LoadingState,
  PageHeader,
  SeverityBadge,
  StatusBadge,
  ValueList,
  VerdictBadge,
} from "../components/ui";
import { usePageTitle } from "../hooks/usePageTitle";
import { display, formatTimestamp, investigationPath, reportPath } from "../lib/format";
import { normalizeFieldMessages, uniqueFieldErrors } from "../lib/normalize";
import type { AlertDetail, AlertLocationState, FieldError, InvestigationSummary, Ioc } from "../types";

function readIngestState(value: unknown): AlertLocationState {
  if (!value || typeof value !== "object") return { duplicate: false, warnings: [] };
  const record = value as Record<string, unknown>;
  return { duplicate: record.duplicate === true, warnings: normalizeFieldMessages(record.warnings) };
}

function mergeWarnings(left: FieldError[], right: FieldError[]): FieldError[] {
  return uniqueFieldErrors([...left, ...right]);
}

function groupIocs(iocs: Ioc[]): Array<{ type: string; values: string[] }> {
  const grouped = new Map<string, string[]>();
  for (const ioc of iocs) {
    const type = ioc.type || "ioc";
    const values = grouped.get(type) ?? [];
    values.push(ioc.value);
    grouped.set(type, values);
  }
  return [...grouped.entries()].map(([type, values]) => ({ type, values }));
}

function PastInvestigations({ alertId }: { alertId: string }) {
  const [items, setItems] = useState<InvestigationSummary[] | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setItems(null);
    setFailed(false);
    listAlertInvestigations(alertId)
      .then((result) => {
        if (!cancelled) setItems(result);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, [alertId]);

  return (
    <section aria-labelledby="past-investigations" className="border border-line bg-panel p-3">
      <h2 id="past-investigations" className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted">
        Investigations
      </h2>
      {failed ? (
        <p className="mt-2 text-[12px] text-warn">Could not load past investigations. The alert itself is unaffected.</p>
      ) : items === null ? (
        <p className="mt-2 text-[12px] text-faint">Loading…</p>
      ) : items.length === 0 ? (
        <p className="mt-2 text-[12px] text-faint">No investigations yet.</p>
      ) : (
        <ul className="mt-2 space-y-1">
          {items.map((item) => (
            <li key={item.id} className="flex flex-wrap items-center gap-3 border border-line bg-bg px-2 py-1.5 text-[12px]">
              <Link to={investigationPath(item.id)} className="font-mono text-accent hover:underline">
                {item.id}
              </Link>
              <StatusBadge status={item.status} />
              {item.verdict ? <VerdictBadge verdict={item.verdict} /> : null}
              <span className="font-mono text-[11px] text-faint">{formatTimestamp(item.created_at)}</span>
              {item.verdict ? (
                <Link to={reportPath(item.id)} className="ml-auto text-muted hover:text-accent">
                  Report
                </Link>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function AlertDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const ingest = readIngestState(location.state);
  const [reloadToken, setReloadToken] = useState(0);
  const [alert, setAlert] = useState<AlertDetail | null>(null);
  const [warnings, setWarnings] = useState<FieldError[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);

  usePageTitle(alert?.name || "Alert");

  useEffect(() => {
    if (!id) return;
    const incoming = readIngestState(location.state).warnings;
    let cancelled = false;
    setAlert(null);
    setWarnings([]);
    setStartError(null);
    setStarting(false);
    setLoading(true);
    setError(null);
    getAlert(id)
      .then((result) => {
        if (cancelled) return;
        setAlert(result.alert);
        setWarnings(mergeWarnings(result.warnings, incoming));
        setLoading(false);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 404) setError("Alert not found.");
        else setError(err instanceof Error ? err.message : "Failed to load the alert.");
        setAlert(null);
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [id, reloadToken, location.state]);

  async function onStart() {
    if (!alert) return;
    setStarting(true);
    setStartError(null);
    try {
      const result = await startInvestigation(alert.id);
      navigate(investigationPath(result.id));
    } catch (err) {
      setStartError(err instanceof Error ? err.message : "Failed to start the investigation.");
      setStarting(false);
    }
  }

  if (!id) {
    return <EmptyState title="No alert selected." detail="Open an alert from the queue." />;
  }
  if (loading && !alert) return <LoadingState label="Loading alert" />;
  if (!alert) {
    return <ErrorState title="Could not load alert" message={error ?? "Alert unavailable."} onRetry={() => setReloadToken((value) => value + 1)} />;
  }

  const iocGroups = groupIocs(alert.iocs);

  return (
    <div className="space-y-4">
      <p className="text-[12px] text-muted">
        <Link to="/" className="hover:text-accent">
          Alert queue
        </Link>
        <span className="px-1 text-faint">/</span>
        <span className="text-text">{alert.name || alert.id}</span>
      </p>
      <PageHeader
        eyebrow={alert.source || "Alert"}
        title={alert.name || alert.id}
        description={alert.description || "No description."}
        actions={
          <Button variant="primary" disabled={starting} onClick={() => void onStart()}>
            {starting ? "Starting investigation…" : "Start investigation"}
          </Button>
        }
      />
      {startError ? <ErrorBanner message={startError} /> : null}
      {ingest.duplicate ? (
        <div className="border border-warn/40 bg-warn/10 px-3 py-2 text-[12px] leading-relaxed text-text">
          Duplicate alert. An existing record with the same fingerprint was returned
          {alert.fingerprint ? ` (${alert.fingerprint}).` : "."}
        </div>
      ) : null}

      <FieldGrid
        items={[
          { label: "id", value: display(alert.id) },
          ...(alert.external_id ? [{ label: "external_id", value: display(alert.external_id) }] : []),
          { label: "source", value: display(alert.source) },
          { label: "severity", value: <SeverityBadge severity={alert.severity} /> },
          { label: "detected_at", value: formatTimestamp(alert.detected_at) },
          ...(alert.created_at ? [{ label: "created_at", value: formatTimestamp(alert.created_at) }] : []),
          { label: "username", value: display(alert.username) },
          { label: "hostname", value: display(alert.hostname) },
          { label: "src_ip", value: display(alert.src_ip) },
          { label: "dst_ip", value: display(alert.dst_ip) },
          ...(alert.fingerprint ? [{ label: "fingerprint", value: display(alert.fingerprint) }] : []),
        ]}
      />

      <PastInvestigations alertId={alert.id} />

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="border border-line bg-panel p-3">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted">file_hashes</h2>
          <div className="mt-2">
            <ValueList values={alert.file_hashes} />
          </div>
        </section>
        <section className="border border-line bg-panel p-3">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted">domains</h2>
          <div className="mt-2">
            <ValueList values={alert.domains} />
          </div>
        </section>
        <section className="border border-line bg-panel p-3">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted">urls</h2>
          <div className="mt-2">
            <ValueList values={alert.urls} />
          </div>
        </section>
        <section className="border border-line bg-panel p-3">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted">mitre_techniques</h2>
          <div className="mt-2">
            <ValueList values={alert.mitre_techniques} tone="accent" />
          </div>
        </section>
      </div>

      <section className="border border-line bg-panel p-3">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted">Indicators of compromise</h2>
        {iocGroups.length === 0 ? (
          <div className="mt-2">
            <EmptyState title="No indicators of compromise." />
          </div>
        ) : (
          <div className="mt-3 space-y-3">
            {iocGroups.map((group) => (
              <div key={group.type}>
                <h3 className="mb-1 font-mono text-[10px] uppercase tracking-[0.14em] text-faint">{group.type}</h3>
                <ValueList values={group.values} tone="warn" />
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="border border-warn/30 bg-panel p-3">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.16em] text-warn">Warnings</h2>
        {warnings.length === 0 ? (
          <p className="mt-2 text-[12px] text-faint">No warnings.</p>
        ) : (
          <ul className="mt-2 list-disc space-y-1 pl-4 text-[13px] leading-relaxed">
            {warnings.map((warning, index) => (
              <li key={`${warning.field}-${index}`}>
                {warning.field ? <span className="font-mono text-warn">{warning.field}</span> : null}
                {warning.field ? " " : ""}
                {warning.message}
              </li>
            ))}
          </ul>
        )}
      </section>

      <details className="border border-line bg-panel">
        <summary className="cursor-pointer px-3 py-2 text-[11px] uppercase tracking-[0.16em] text-muted">Raw payload</summary>
        <div className="border-t border-line bg-bg px-3 py-2">
          <JsonBlock value={alert.raw} />
        </div>
      </details>
    </div>
  );
}
