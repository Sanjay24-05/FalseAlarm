import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, createAlert, listAlerts, listScenarios, loadScenario, uploadAlerts } from "../api";
import { ALERT_JSON_FIELDS, ALERT_JSON_SAMPLE, PRIMARY_SCENARIOS } from "../constants";
import { alertPath, formatTimestamp, investigationPath } from "../lib/format";
import type { AlertListItem, AlertLocationState, FieldError, IngestResult, Scenario, UploadResult } from "../types";
import {
  Button,
  EmptyState,
  ErrorBanner,
  ErrorState,
  FieldErrors,
  LoadingState,
  PageHeader,
  Panel,
  SeverityBadge,
  VerdictBadge,
} from "../components/ui";
import { usePageTitle } from "../hooks/usePageTitle";

function scenarioCards(remote: Scenario[]): Scenario[] {
  const byId = new Map(remote.map((item) => [item.id, item]));
  const primary = PRIMARY_SCENARIOS.map((item) => {
    const found = byId.get(item.id);
    byId.delete(item.id);
    return {
      id: item.id,
      title: found?.title || item.title,
      description: found?.description || item.description,
      expected_verdict: found?.expected_verdict ?? "",
    };
  });
  return [...primary, ...byId.values()];
}

export function AlertQueuePage() {
  const navigate = useNavigate();
  const fileRef = useRef<HTMLInputElement>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [alerts, setAlerts] = useState<AlertListItem[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [listLoading, setListLoading] = useState(true);
  const [scenarios, setScenarios] = useState<Scenario[] | null>(null);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [jsonText, setJsonText] = useState("");
  const [parseError, setParseError] = useState<string | null>(null);
  const [pasteErrors, setPasteErrors] = useState<FieldError[]>([]);
  const [pasteMessage, setPasteMessage] = useState<string | null>(null);
  const [uploadErrors, setUploadErrors] = useState<FieldError[]>([]);
  const [uploadMessage, setUploadMessage] = useState<string | null>(null);
  const [uploadResults, setUploadResults] = useState<UploadResult[] | null>(null);
  const [scenarioErrors, setScenarioErrors] = useState<FieldError[]>([]);
  const [scenarioMessage, setScenarioMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  usePageTitle("Alert queue");

  useEffect(() => {
    let cancelled = false;
    setListLoading(true);
    setListError(null);
    void (async () => {
      const [alertResult, scenarioResult] = await Promise.allSettled([listAlerts(), listScenarios()]);
      if (cancelled) return;
      if (alertResult.status === "fulfilled") {
        setAlerts(alertResult.value);
        setListError(null);
      } else {
        setListError(alertResult.reason instanceof Error ? alertResult.reason.message : "Failed to load alerts.");
      }
      if (scenarioResult.status === "fulfilled") {
        setScenarios(scenarioResult.value);
        setCatalogError(null);
      } else {
        setScenarios([]);
        setCatalogError(
          scenarioResult.reason instanceof Error
            ? scenarioResult.reason.message
            : "Scenario catalog is unavailable.",
        );
      }
      setListLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, [reloadToken]);

  function openIngest(result: IngestResult) {
    const state: AlertLocationState = { duplicate: result.duplicate, warnings: result.warnings };
    navigate(alertPath(result.alert.id), { state });
  }

  async function onScenario(id: string) {
    setScenarioErrors([]);
    setScenarioMessage(null);
    setBusy(`scenario:${id}`);
    try {
      openIngest(await loadScenario(id));
    } catch (err) {
      if (err instanceof ApiError && err.fieldErrors.length > 0) setScenarioErrors(err.fieldErrors);
      else setScenarioMessage(err instanceof Error ? err.message : "Failed to load the scenario.");
    } finally {
      setBusy(null);
    }
  }

  async function onPaste(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setParseError(null);
    setPasteErrors([]);
    setPasteMessage(null);
    const text = jsonText.trim();
    if (!text) {
      setParseError("Paste an alert JSON object first.");
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      setParseError("That text is not valid JSON.");
      return;
    }
    if (Array.isArray(parsed)) {
      setParseError("Paste one alert object. Use file upload for a batch file.");
      return;
    }
    if (!parsed || typeof parsed !== "object") {
      setParseError("Alert JSON must be an object.");
      return;
    }
    setBusy("paste");
    try {
      openIngest(await createAlert(parsed));
    } catch (err) {
      if (err instanceof ApiError && err.fieldErrors.length > 0) setPasteErrors(err.fieldErrors);
      else setPasteMessage(err instanceof Error ? err.message : "Failed to ingest the alert.");
    } finally {
      setBusy(null);
    }
  }

  async function onUpload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setUploadErrors([]);
    setUploadMessage(null);
    const file = fileRef.current?.files?.[0];
    if (!file) {
      setUploadMessage("Choose a JSON file first.");
      return;
    }
    setBusy("upload");
    try {
      const results = await uploadAlerts(file);
      setUploadResults(results);
      if (fileRef.current) fileRef.current.value = "";
      setReloadToken((value) => value + 1);
    } catch (err) {
      if (err instanceof ApiError && err.fieldErrors.length > 0) setUploadErrors(err.fieldErrors);
      else setUploadMessage(err instanceof Error ? err.message : "Upload failed.");
    } finally {
      setBusy(null);
    }
  }

  const cards = scenarioCards(scenarios ?? []);
  const countLabel =
    alerts == null ? "Load a scenario or ingest an alert." : `${alerts.length} alert${alerts.length === 1 ? "" : "s"} in the queue.`;

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Operations"
        title="Alert queue"
        description={countLabel}
        actions={
          <Button onClick={() => setReloadToken((value) => value + 1)} disabled={listLoading || busy !== null}>
            {listLoading ? "Refreshing…" : "Refresh"}
          </Button>
        }
      />

      <Panel title="Scenarios" action={<span className="font-mono text-[10px] text-faint">POST /api/scenarios/{"{id}"}/load</span>}>
        <div className="grid gap-3 md:grid-cols-2">
          {cards.map((scenario) => (
            <div key={scenario.id} className="border border-line bg-bg px-3 py-2">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-[13px] font-medium">{scenario.title}</p>
                  <p className="font-mono text-[10px] text-faint">{scenario.id}</p>
                </div>
                <Button
                  variant="primary"
                  disabled={busy !== null}
                  onClick={() => void onScenario(scenario.id)}
                >
                  {busy === `scenario:${scenario.id}` ? "Loading…" : "Load"}
                </Button>
              </div>
              {scenario.description ? <p className="mt-2 text-[12px] leading-relaxed text-muted">{scenario.description}</p> : null}
              {scenario.expected_verdict ? (
                <p className="mt-2 text-[11px] text-muted">
                  expected_verdict <VerdictBadge verdict={scenario.expected_verdict} />
                </p>
              ) : null}
            </div>
          ))}
        </div>
        {scenarios === null && !catalogError ? <p className="mt-2 text-[12px] text-faint">Loading scenario catalog…</p> : null}
        {catalogError ? (
          <p className="mt-2 text-[12px] text-warn">Scenario catalog is unavailable. Load actions still call the API.</p>
        ) : null}
        {scenarioErrors.length > 0 ? (
          <div className="mt-3">
            <FieldErrors errors={scenarioErrors} />
          </div>
        ) : null}
        {scenarioMessage ? (
          <div className="mt-3">
            <ErrorBanner message={scenarioMessage} />
          </div>
        ) : null}
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Ingest JSON" action={<span className="font-mono text-[10px] text-faint">POST /api/alerts</span>}>
          <form onSubmit={(event) => void onPaste(event)} className="space-y-3">
            <p className="text-[12px] leading-relaxed text-muted">
              Paste one alert object. Fields: <span className="font-mono text-[11px] text-faint">{ALERT_JSON_FIELDS.join(", ")}</span>
            </p>
            <textarea
              value={jsonText}
              onChange={(event) => setJsonText(event.target.value)}
              placeholder={ALERT_JSON_SAMPLE}
              spellCheck={false}
              rows={12}
              aria-label="Alert JSON"
              aria-invalid={parseError != null || pasteErrors.length > 0}
              className="w-full border border-line bg-bg px-2 py-1.5 font-mono text-[12px] leading-relaxed text-text placeholder:text-faint"
            />
            {parseError ? <ErrorBanner message={parseError} /> : null}
            <FieldErrors errors={pasteErrors} />
            {pasteMessage ? <ErrorBanner message={pasteMessage} /> : null}
            <Button type="submit" variant="primary" disabled={busy !== null}>
              {busy === "paste" ? "Ingesting…" : "Ingest alert"}
            </Button>
          </form>
        </Panel>

        <Panel title="Upload JSON file" action={<span className="font-mono text-[10px] text-faint">POST /api/alerts/upload</span>}>
          <form onSubmit={(event) => void onUpload(event)} className="space-y-3">
            <p className="text-[12px] leading-relaxed text-muted">
              Multipart field name <span className="font-mono text-text">file</span>. Each item is ingested, or returned with field errors, without failing the rest of the file.
            </p>
            <input
              ref={fileRef}
              type="file"
              accept=".json,application/json"
              aria-label="Alert JSON file"
              className="block w-full text-[12px] text-muted file:mr-3 file:border file:border-line file:bg-panel-2 file:px-2 file:py-1 file:text-[12px] file:text-text"
            />
            <FieldErrors errors={uploadErrors} />
            {uploadMessage ? <ErrorBanner message={uploadMessage} /> : null}
            <Button type="submit" variant="primary" disabled={busy !== null}>
              {busy === "upload" ? "Uploading…" : "Upload file"}
            </Button>
          </form>
          {uploadResults ? (
            <div className="mt-4 border-t border-line pt-3">
              {uploadResults.length === 0 ? (
                <EmptyState title="The upload returned no alerts." />
              ) : (
                <ul className="space-y-2">
                  {uploadResults.map((result, index) => (
                    <li key={`${result.alert?.id ?? "error"}-${index}`} className="border border-line bg-bg px-2 py-2">
                      {result.alert ? (
                        <>
                          <div className="flex flex-wrap items-baseline justify-between gap-2">
                            <Link to={alertPath(result.alert.id)} className="text-[13px] text-accent hover:underline">
                              {result.alert.name || result.alert.id}
                            </Link>
                            {result.duplicate ? <span className="text-[11px] uppercase tracking-wider text-warn">Duplicate</span> : null}
                          </div>
                          <p className="font-mono text-[10px] text-faint">{result.alert.id}</p>
                        </>
                      ) : (
                        <p className="text-[12px] text-muted">This item was not ingested.</p>
                      )}
                      {result.errors.length > 0 ? (
                        <div className="mt-2">
                          <FieldErrors errors={result.errors} />
                        </div>
                      ) : null}
                      {result.warnings.length > 0 ? (
                        <ul className="mt-1 list-disc pl-4 text-[12px] text-muted">
                          {result.warnings.map((warning, warningIndex) => (
                            <li key={warningIndex}>
                              {warning.field ? <span className="font-mono text-warn">{warning.field}</span> : null}
                              {warning.field ? " " : ""}
                              {warning.message}
                            </li>
                          ))}
                        </ul>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ) : null}
        </Panel>
      </div>

      <section aria-labelledby="alert-table-heading">
        <div className="mb-2 flex items-baseline justify-between">
          <h2 id="alert-table-heading" className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted">
            Alerts
          </h2>
          <span className="font-mono text-[10px] text-faint">GET /api/alerts</span>
        </div>
        {listLoading ? <div className="loading-bar mb-2" /> : null}
        {listError && alerts !== null ? (
          <div className="mb-2">
            <ErrorBanner message={listError} />
          </div>
        ) : null}
        {listLoading && alerts === null ? <LoadingState label="Loading alerts" /> : null}
        {!listLoading && listError && alerts === null ? (
          <ErrorState title="Could not load alerts" message={listError} onRetry={() => setReloadToken((value) => value + 1)} />
        ) : null}
        {alerts !== null && alerts.length === 0 ? (
          <EmptyState title="No alerts in the queue." detail="Load a scenario, paste alert JSON, or upload a JSON file." />
        ) : null}
        {alerts !== null && alerts.length > 0 ? (
          <div className="overflow-x-auto border border-line">
            <table className="w-full min-w-[960px] text-left text-[12px]">
              <caption className="sr-only">Alerts</caption>
              <thead className="sticky top-12 z-10 bg-panel-2 text-[10px] uppercase tracking-[0.14em] text-faint">
                <tr>
                  <th className="px-2 py-2 font-medium">Severity</th>
                  <th className="px-2 py-2 font-medium">Name</th>
                  <th className="px-2 py-2 font-medium">Source</th>
                  <th className="px-2 py-2 font-medium">Detected</th>
                  <th className="px-2 py-2 font-medium">User</th>
                  <th className="px-2 py-2 font-medium">Host</th>
                  <th className="px-2 py-2 font-medium">Src IP</th>
                  <th className="px-2 py-2 font-medium">Verdict</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert, index) => (
                  <tr
                    key={alert.id || index}
                    className="cursor-pointer border-t border-line hover:bg-panel-2"
                    onClick={() => {
                      if (alert.id) navigate(alertPath(alert.id));
                    }}
                  >
                    <td className="whitespace-nowrap px-2 py-1.5">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="px-2 py-1.5">
                      {alert.id ? (
                        <Link
                          to={alertPath(alert.id)}
                          className="text-text hover:text-accent"
                          onClick={(event) => event.stopPropagation()}
                        >
                          {alert.name || alert.id}
                        </Link>
                      ) : (
                        <span>{alert.name || "—"}</span>
                      )}
                      <div className="font-mono text-[10px] text-faint">{alert.id || "—"}</div>
                    </td>
                    <td className="whitespace-nowrap px-2 py-1.5 font-mono text-muted">{alert.source || "—"}</td>
                    <td className="whitespace-nowrap px-2 py-1.5 font-mono" title={alert.detected_at}>
                      {formatTimestamp(alert.detected_at)}
                    </td>
                    <td className="whitespace-nowrap px-2 py-1.5 font-mono">{alert.username || "—"}</td>
                    <td className="whitespace-nowrap px-2 py-1.5 font-mono">{alert.hostname || "—"}</td>
                    <td className="whitespace-nowrap px-2 py-1.5 font-mono">{alert.src_ip || "—"}</td>
                    <td className="whitespace-nowrap px-2 py-1.5">
                      {alert.latest_investigation_id ? (
                        <Link
                          to={investigationPath(alert.latest_investigation_id)}
                          className="hover:opacity-80"
                          onClick={(event) => event.stopPropagation()}
                        >
                          <VerdictBadge verdict={alert.verdict} />
                        </Link>
                      ) : (
                        <VerdictBadge verdict={alert.verdict} />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>
    </div>
  );
}
