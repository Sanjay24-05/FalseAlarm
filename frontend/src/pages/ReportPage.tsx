import { Link, useParams } from "react-router-dom";
import { RenderValue } from "../components/RenderValue";
import { EmptyState, ErrorBanner, ErrorState, LoadingState, PageHeader, StatusBadge, buttonClasses } from "../components/ui";
import { REPORT_SECTIONS } from "../constants";
import { useAlertSummary } from "../hooks/useAlertSummary";
import { useInvestigation } from "../hooks/useInvestigation";
import { usePageTitle } from "../hooks/usePageTitle";
import { alertPath, formatTimestamp, investigationPath } from "../lib/format";
import type { Investigation } from "../types";
import { isTerminalStatus } from "../types";

function ReportBody({
  data,
  polling,
  updatedAt,
  error,
}: {
  data: Investigation;
  polling: boolean;
  updatedAt: string | null;
  error: string | null;
}) {
  const alert = useAlertSummary(data.alert_id);
  const terminal = isTerminalStatus(data.status);
  usePageTitle(alert?.name ? `${alert.name} report` : "Report");

  return (
    <div className="space-y-4">
      <p className="text-[12px] text-muted">
        <Link to="/" className="hover:text-accent">
          Alert queue
        </Link>
        <span className="px-1 text-faint">/</span>
        <Link to={investigationPath(data.id)} className="hover:text-accent">
          Investigation
        </Link>
        <span className="px-1 text-faint">/</span>
        <span className="text-text">Report</span>
      </p>
      <PageHeader
        eyebrow="Report"
        title={alert?.name || "Investigation report"}
        description={data.id}
        actions={
          <>
            <StatusBadge status={data.status} />
            <Link to={investigationPath(data.id)} className={buttonClasses("secondary")}>
              Back to investigation
            </Link>
          </>
        }
      />
      <p className="text-[12px] text-muted">
        {data.alert_id ? (
          <>
            alert_id{" "}
            <Link to={alertPath(data.alert_id)} className="font-mono text-accent hover:underline">
              {data.alert_id}
            </Link>
            .{" "}
          </>
        ) : null}
        {polling ? "Updating every second." : terminal ? "Final status." : "Updates paused."}
        {updatedAt ? ` Last fetch ${formatTimestamp(updatedAt)}.` : ""}
      </p>
      {error ? <ErrorBanner message={polling ? `${error} Retrying.` : error} /> : null}

      {data.report == null ? (
        <EmptyState
          title="No report is available for this investigation."
          detail={
            terminal
              ? "The investigation reached a final status without a report."
              : "This page keeps checking about once a second until the investigation finishes."
          }
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[15rem_1fr]">
          <nav aria-label="Report sections" className="flex gap-2 overflow-x-auto border border-line bg-panel p-2 lg:sticky lg:top-16 lg:flex-col lg:self-start lg:overflow-visible">
            <ol className="flex gap-2 lg:flex-col">
              {REPORT_SECTIONS.map((section, index) => (
                <li key={section.key}>
                  <a href={`#section-${section.key}`} className="flex gap-2 px-1 py-1 text-[12px] text-muted hover:text-accent">
                    <span className="font-mono text-[10px] text-faint">{String(index + 1).padStart(2, "0")}</span>
                    <span>{section.title}</span>
                  </a>
                </li>
              ))}
            </ol>
          </nav>
          <div className="space-y-4">
            {REPORT_SECTIONS.map((section, index) => (
              <article id={`section-${section.key}`} key={section.key} className="scroll-mt-16 border border-line bg-panel">
                <header className="flex items-baseline gap-3 border-b border-line px-4 py-2">
                  <span className="font-mono text-[11px] text-faint">{String(index + 1).padStart(2, "0")}</span>
                  <h2 className="text-[13px] font-semibold">{section.title}</h2>
                  <span className="ml-auto font-mono text-[10px] text-faint">{section.key}</span>
                </header>
                <div className="px-4 py-3">
                  <RenderValue value={data.report?.[section.key]} />
                </div>
              </article>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export function ReportPage() {
  const { id } = useParams();
  const { investigation, error, loading, polling, updatedAt, retry } = useInvestigation(id);

  if (!id) return <EmptyState title="No investigation selected." detail="Open a report from an investigation." />;
  if (loading && !investigation) return <LoadingState label="Loading report" />;
  if (!investigation) {
    return (
      <ErrorState title="Could not load report" message={error?.message ?? "Investigation unavailable."} onRetry={retry} />
    );
  }

  return <ReportBody data={investigation} polling={polling} updatedAt={updatedAt} error={error?.message ?? null} />;
}
