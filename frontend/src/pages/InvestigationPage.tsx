import { Link, useParams } from "react-router-dom";
import { JsonBlock } from "../components/RenderValue";
import {
  EmptyState,
  ErrorBanner,
  ErrorState,
  LoadingState,
  PageHeader,
  SectionHeading,
  StatusBadge,
  ValueList,
  VerdictBadge,
  buttonClasses,
  Metric,
} from "../components/ui";
import { useAlertSummary } from "../hooks/useAlertSummary";
import { useInvestigation } from "../hooks/useInvestigation";
import { usePageTitle } from "../hooks/usePageTitle";
import { cx } from "../lib/cx";
import { alertPath, display, formatCount, formatDuration, formatScalar, formatTimestamp, reportPath } from "../lib/format";
import type { Assessment, Evidence, EvidenceStatement, Investigation, InvestigationStep, TimelineEvent } from "../types";
import { isTerminalStatus } from "../types";

function escalateLabel(value: boolean | null): string {
  if (value === true) return "Yes";
  if (value === false) return "No";
  return "—";
}

function StringBlock({ name, values }: { name: string; values: string[] }) {
  return (
    <div>
      <h3 className="font-mono text-[10px] uppercase tracking-[0.14em] text-faint">{name}</h3>
      {values.length === 0 ? (
        <p className="mt-1 text-[12px] text-faint">None</p>
      ) : (
        <ul className="mt-1 list-disc space-y-1 pl-4 text-[13px] leading-relaxed">
          {values.map((value, index) => (
            <li key={index} className="break-words">
              {value}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Statements({ name, items }: { name: string; items: EvidenceStatement[] }) {
  return (
    <div>
      <h3 className="font-mono text-[10px] uppercase tracking-[0.14em] text-faint">{name}</h3>
      {items.length === 0 ? (
        <p className="mt-1 text-[12px] text-faint">None</p>
      ) : (
        <ul className="mt-2 space-y-2">
          {items.map((item, index) => (
            <li key={`${item.evidence_id}-${index}`} className="border border-line bg-bg px-2 py-1.5">
              <p className="font-mono text-[10px] text-muted">{item.evidence_id || "—"}</p>
              <p className="mt-1 text-[13px] leading-relaxed">{item.statement || "—"}</p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function StepList({ steps }: { steps: InvestigationStep[] }) {
  if (steps.length === 0) {
    return <EmptyState title="No questions or tool calls yet." detail="Each step shows the question, the tool, and the arguments sent." />;
  }
  return (
    <ol className="space-y-3">
      {steps.map((step, index) => (
        <li key={step.id || index} className="border border-line bg-panel px-3 py-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-mono text-[10px] text-faint">{String(index + 1).padStart(2, "0")}</span>
            <StatusBadge status={step.status || "queued"} />
          </div>
          <p className="mt-2 text-[13px] leading-relaxed">{step.question || "—"}</p>
          <div className="mt-3 border border-line bg-bg px-2 py-2">
            <p className="text-[10px] uppercase tracking-[0.14em] text-faint">Tool call</p>
            <p className="mt-1 font-mono text-[12px] text-accent">{step.tool || "—"}</p>
            <div className="mt-2">
              <JsonBlock value={step.arguments} />
            </div>
          </div>
          <p className="mt-2 font-mono text-[10px] text-faint">
            started_at {formatTimestamp(step.started_at)} · finished_at {formatTimestamp(step.finished_at)}
            {step.id ? ` · ${step.id}` : ""}
          </p>
        </li>
      ))}
    </ol>
  );
}

function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  if (evidence.length === 0) {
    return <EmptyState title="No evidence recorded yet." detail="Each item shows its source and observed_at timestamp." />;
  }
  const groups = ["ips", "users", "hosts", "domains", "hashes"] as const;
  return (
    <div className="space-y-3">
      {evidence.map((item, index) => {
        const entityGroups = groups
          .map((key) => ({ key, values: item.entities[key] }))
          .filter((group) => group.values.length > 0);
        return (
          <article key={item.id || index} className="border border-line bg-panel">
            <header className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-3 py-2">
              <span className="font-mono text-[10px] uppercase tracking-wider text-accent">{item.kind || "evidence"}</span>
              <span className="font-mono text-[10px] text-faint">{item.id || "—"}</span>
            </header>
            <div className="space-y-3 px-3 py-2">
              <p className="text-[13px] leading-relaxed">{item.summary || "—"}</p>
              <dl className="grid grid-cols-1 gap-px bg-line sm:grid-cols-2">
                <div className="bg-bg px-2 py-1.5">
                  <dt className="text-[10px] uppercase tracking-[0.14em] text-faint">source</dt>
                  <dd className="mt-1 break-all font-mono text-[12px]">{display(item.source)}</dd>
                </div>
                <div className="bg-bg px-2 py-1.5">
                  <dt className="text-[10px] uppercase tracking-[0.14em] text-faint">observed_at</dt>
                  <dd className="mt-1 font-mono text-[12px]" title={item.observed_at}>
                    {formatTimestamp(item.observed_at)}
                  </dd>
                </div>
              </dl>
              <p className="font-mono text-[11px] text-muted">
                source_type {display(item.source_type)} · query_id {display(item.query_id)}
              </p>
              {entityGroups.length === 0 ? (
                <p className="text-[12px] text-faint">No entities.</p>
              ) : (
                <div className="space-y-2">
                  {entityGroups.map((group) => (
                    <div key={group.key}>
                      <p className="mb-1 font-mono text-[10px] uppercase tracking-[0.14em] text-faint">{group.key}</p>
                      <ValueList values={group.values} />
                    </div>
                  ))}
                </div>
              )}
              {item.raw != null ? (
                <details>
                  <summary className="cursor-pointer text-[11px] uppercase tracking-[0.14em] text-faint">raw</summary>
                  <div className="mt-2">
                    <JsonBlock value={item.raw} />
                  </div>
                </details>
              ) : null}
            </div>
          </article>
        );
      })}
    </div>
  );
}

function relationshipRank(value: string): number {
  if (value === "observed") return 0;
  if (value === "inferred") return 1;
  return 2;
}

function chronological(events: TimelineEvent[]): TimelineEvent[] {
  return [...events].sort((left, right) => {
    if (left.timestamp < right.timestamp) return -1;
    if (left.timestamp > right.timestamp) return 1;
    const relationship = relationshipRank(left.relationship) - relationshipRank(right.relationship);
    if (relationship !== 0) return relationship;
    if (left.summary < right.summary) return -1;
    if (left.summary > right.summary) return 1;
    return 0;
  });
}

function Timeline({ events }: { events: TimelineEvent[] }) {
  const ordered = chronological(events);
  if (ordered.length === 0) return <EmptyState title="No timeline events yet." />;
  return (
    <div className="space-y-3">
      <p className="text-[12px] leading-relaxed text-muted">
        Filled marker and solid rail: <span className="font-mono text-accent">observed</span>. Hollow marker and dashed rail:{" "}
        <span className="font-mono text-warn">inferred</span>.
      </p>
      <ol className="space-y-2">
        {ordered.map((event, index) => {
          const observed = event.relationship === "observed";
          const inferred = event.relationship === "inferred";
          return (
            <li
              key={event.id || index}
              data-relationship={event.relationship || "unknown"}
              className={cx(
                "py-1 pl-3",
                observed && "border-l-2 border-solid border-accent",
                inferred && "border-l-2 border-dashed border-warn bg-warn/5",
                !observed && !inferred && "border-l-2 border-solid border-line",
              )}
            >
              <div className="flex items-start gap-2">
                <span
                  aria-hidden
                  className={cx(
                    "mt-1 inline-block h-2 w-2 shrink-0",
                    observed && "bg-accent",
                    inferred && "border border-warn bg-transparent",
                    !observed && !inferred && "bg-faint",
                  )}
                />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline gap-2">
                    <time className="font-mono text-[11px] text-muted" dateTime={event.timestamp} title={event.timestamp}>
                      {formatTimestamp(event.timestamp)}
                    </time>
                    <span
                      className={cx(
                        "font-mono text-[10px] uppercase tracking-[0.14em]",
                        observed && "text-accent",
                        inferred && "text-warn",
                        !observed && !inferred && "text-faint",
                      )}
                    >
                      {event.relationship || "unknown"}
                    </span>
                    <span className="font-mono text-[10px] text-faint">{event.source || "—"}</span>
                  </div>
                  <p className="mt-1 text-[13px] leading-relaxed">{event.summary || "—"}</p>
                  {event.evidence_ids.length > 0 ? (
                    <p className="mt-1 break-all font-mono text-[10px] text-faint">evidence_ids {event.evidence_ids.join(", ")}</p>
                  ) : null}
                </div>
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function AssessmentPanel({ assessment, terminal }: { assessment: Assessment | null; terminal: boolean }) {
  if (!assessment) {
    return (
      <EmptyState
        title={terminal ? "No assessment was recorded." : "No assessment yet."}
        detail={terminal ? undefined : "Verdict, confidence rationale, gaps, and escalation reason appear when the investigation finishes."}
      />
    );
  }
  return (
    <div className="space-y-4 border border-line bg-panel p-3">
      <div className="flex flex-wrap items-center gap-3">
        <VerdictBadge verdict={assessment.verdict} />
        <span className="font-mono text-[12px] text-muted">confidence {formatScalar(assessment.confidence)}</span>
        <span className="text-[12px] text-muted">severity {display(assessment.severity)}</span>
        <span className={cx("text-[12px]", assessment.escalate ? "text-danger" : "text-muted")}>
          escalate {escalateLabel(assessment.escalate)}
        </span>
      </div>
      <div>
        <h3 className="font-mono text-[10px] uppercase tracking-[0.14em] text-faint">confidence_rationale</h3>
        {assessment.confidence_rationale.trim() ? (
          <p className="mt-1 whitespace-pre-wrap text-[13px] leading-relaxed">{assessment.confidence_rationale}</p>
        ) : (
          <p className="mt-1 text-[12px] text-faint">No confidence rationale.</p>
        )}
      </div>
      {assessment.impact.trim() ? (
        <div>
          <h3 className="font-mono text-[10px] uppercase tracking-[0.14em] text-faint">impact</h3>
          <p className="mt-1 whitespace-pre-wrap text-[13px] leading-relaxed">{assessment.impact}</p>
        </div>
      ) : null}
      <div className="grid gap-4 lg:grid-cols-2">
        <StringBlock name="missing_evidence" values={assessment.missing_evidence} />
        <StringBlock name="unresolved_questions" values={assessment.unresolved_questions} />
      </div>
      <div className={cx("border px-3 py-2", assessment.escalate ? "border-danger/40 bg-danger/10" : "border-line bg-bg")}>
        <h3 className="font-mono text-[10px] uppercase tracking-[0.14em] text-faint">escalation_reason</h3>
        <p className="mt-1 whitespace-pre-wrap text-[13px] leading-relaxed">{display(assessment.escalation_reason)}</p>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Statements name="supporting_evidence" items={assessment.supporting_evidence} />
        <Statements name="contradicting_evidence" items={assessment.contradicting_evidence} />
      </div>
      <StringBlock name="recommended_actions" values={assessment.recommended_actions} />
    </div>
  );
}

function InvestigationBody({
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
  usePageTitle(alert?.name || "Investigation");

  return (
    <div className="space-y-4">
      <p className="text-[12px] text-muted">
        <Link to="/" className="hover:text-accent">
          Alert queue
        </Link>
        <span className="px-1 text-faint">/</span>
        {data.alert_id ? (
          <Link to={alertPath(data.alert_id)} className="hover:text-accent">
            {alert?.name || data.alert_id}
          </Link>
        ) : (
          <span>Alert</span>
        )}
        <span className="px-1 text-faint">/</span>
        <span className="text-text">Investigation</span>
      </p>
      <PageHeader
        eyebrow="Investigation"
        title={alert?.name || data.id}
        description={data.id}
        actions={
          <>
            <StatusBadge status={data.status} />
            <Link to={reportPath(data.id)} className={buttonClasses(data.report ? "primary" : "secondary")}>
              View report
            </Link>
          </>
        }
      />
      <p className="text-[12px] text-muted" aria-live="polite">
        {polling ? "Updating every second." : terminal ? "Final status." : "Updates paused."}
        {updatedAt ? ` Last fetch ${formatTimestamp(updatedAt)}.` : ""}
        {data.alert_id ? (
          <>
            {" "}
            alert_id <Link to={alertPath(data.alert_id)} className="font-mono text-accent hover:underline">{data.alert_id}</Link>
          </>
        ) : null}
      </p>
      {data.stop_reason || data.status === "failed" || data.status === "budget_exhausted" ? (
        <p className="border border-line bg-panel px-3 py-2 text-[12px]">
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-faint">stop_reason</span>{" "}
          <span className="text-text">{display(data.stop_reason)}</span>
        </p>
      ) : null}
      {error ? <ErrorBanner message={polling ? `${error} Retrying.` : error} /> : null}

      <dl className="grid grid-cols-1 gap-px bg-line sm:grid-cols-3">
        <Metric
          label="duration_ms"
          value={data.metrics.duration_ms == null ? "—" : `${formatCount(data.metrics.duration_ms)} ms`}
          hint={formatDuration(data.metrics.duration_ms)}
        />
        <Metric label="tool_call_count" value={formatCount(data.metrics.tool_call_count)} />
        <Metric label="event_count" value={formatCount(data.metrics.event_count)} />
      </dl>

      {data.assessment ? (
        <div className="grid grid-cols-1 gap-px bg-line sm:grid-cols-3">
          <div className="bg-panel px-3 py-2">
            <p className="text-[10px] uppercase tracking-[0.14em] text-faint">verdict</p>
            <div className="mt-1">
              <VerdictBadge verdict={data.assessment.verdict} />
            </div>
          </div>
          <div className="bg-panel px-3 py-2">
            <p className="text-[10px] uppercase tracking-[0.14em] text-faint">confidence</p>
            <p className="mt-1 font-mono text-[13px]">{formatScalar(data.assessment.confidence)}</p>
          </div>
          <div className="bg-panel px-3 py-2">
            <p className="text-[10px] uppercase tracking-[0.14em] text-faint">escalate</p>
            <p className={cx("mt-1 text-[13px]", data.assessment.escalate ? "text-danger" : "text-text")}>
              {escalateLabel(data.assessment.escalate)}
            </p>
          </div>
        </div>
      ) : null}

      <nav aria-label="Investigation sections" className="flex flex-wrap gap-3 text-[11px] uppercase tracking-[0.14em]">
        <a href="#inv-steps" className="text-muted hover:text-accent">Questions</a>
        <a href="#inv-evidence" className="text-muted hover:text-accent">Evidence</a>
        <a href="#inv-timeline" className="text-muted hover:text-accent">Timeline</a>
        <a href="#inv-assessment" className="text-muted hover:text-accent">Assessment</a>
        <a href="#inv-audit" className="text-muted hover:text-accent">Audit</a>
      </nav>

      <section id="inv-steps" className="scroll-mt-16">
        <SectionHeading title="Questions and tool calls" count={data.steps.length} />
        <StepList steps={data.steps} />
      </section>
      <section id="inv-evidence" className="scroll-mt-16">
        <SectionHeading title="Evidence" count={data.evidence.length} />
        <EvidenceList evidence={data.evidence} />
      </section>
      <section id="inv-timeline" className="scroll-mt-16">
        <SectionHeading title="Timeline" count={data.timeline.length} />
        <Timeline events={data.timeline} />
      </section>
      <section id="inv-assessment" className="scroll-mt-16">
        <SectionHeading title="Assessment" />
        <AssessmentPanel assessment={data.assessment} terminal={terminal} />
      </section>
      <section id="inv-audit" className="scroll-mt-16">
        <SectionHeading title="Audit" count={data.audit.length} />
        {data.audit.length === 0 ? (
          <EmptyState title="No audit events yet." />
        ) : (
          <ol className="space-y-2">
            {data.audit.map((entry, index) => (
              <li key={entry.id || index} className="border border-line bg-panel px-3 py-2">
                <div className="flex flex-wrap items-baseline gap-2">
                  <time className="font-mono text-[11px] text-muted" dateTime={entry.timestamp} title={entry.timestamp}>
                    {formatTimestamp(entry.timestamp)}
                  </time>
                  <span className="font-mono text-[10px] uppercase tracking-wider text-accent">{entry.kind || "event"}</span>
                  <span className="font-mono text-[10px] text-faint">{entry.id}</span>
                </div>
                <p className="mt-1 text-[13px] leading-relaxed">{entry.summary || "—"}</p>
                {entry.details != null ? (
                  <details className="mt-2">
                    <summary className="cursor-pointer text-[11px] uppercase tracking-[0.14em] text-faint">details</summary>
                    <div className="mt-2">
                      <JsonBlock value={entry.details} />
                    </div>
                  </details>
                ) : null}
              </li>
            ))}
          </ol>
        )}
      </section>
    </div>
  );
}

export function InvestigationPage() {
  const { id } = useParams();
  const { investigation, error, loading, polling, updatedAt, retry } = useInvestigation(id);

  if (!id) return <EmptyState title="No investigation selected." detail="Start an investigation from an alert." />;
  if (loading && !investigation) return <LoadingState label="Loading investigation" />;
  if (!investigation) {
    return (
      <ErrorState
        title="Could not load investigation"
        message={error?.message ?? "Investigation unavailable."}
        onRetry={retry}
      />
    );
  }

  return (
    <InvestigationBody
      data={investigation}
      polling={polling}
      updatedAt={updatedAt}
      error={error?.message ?? null}
    />
  );
}
