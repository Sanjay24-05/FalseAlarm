import type { ButtonHTMLAttributes, ReactNode } from "react";
import type { FieldError } from "../types";
import { cx } from "../lib/cx";
import { label } from "../lib/format";

type ButtonVariant = "primary" | "secondary";

export function buttonClasses(variant: ButtonVariant = "secondary", className?: string): string {
  return cx(
    "inline-flex items-center justify-center gap-2 border px-3 py-1.5 text-[12px] font-medium tracking-wide transition-colors disabled:cursor-not-allowed disabled:opacity-50",
    variant === "primary" && "border-accent bg-accent text-bg hover:bg-accent/90",
    variant === "secondary" && "border-line bg-panel-2 text-text hover:border-muted",
    className,
  );
}

export function Button({
  variant = "secondary",
  className,
  type = "button",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return <button type={type} className={buttonClasses(variant, className)} {...props} />;
}

export function Chip({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "accent" | "warn" }) {
  return (
    <span
      className={cx(
        "inline-flex max-w-full items-center break-all border px-1.5 py-0.5 font-mono text-[11px]",
        tone === "neutral" && "border-line bg-panel-2 text-text",
        tone === "accent" && "border-accent/40 bg-accent/10 text-accent",
        tone === "warn" && "border-warn/40 bg-warn/10 text-warn",
      )}
    >
      {children}
    </span>
  );
}

export function ValueList({ values, tone = "neutral" }: { values: string[]; tone?: "neutral" | "accent" | "warn" }) {
  if (values.length === 0) return <span className="text-[12px] text-faint">None</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {values.map((value, index) => (
        <Chip key={`${value}-${index}`} tone={tone}>
          {value}
        </Chip>
      ))}
    </div>
  );
}

export function LoadingState({ label: text }: { label: string }) {
  return (
    <div role="status" aria-live="polite" className="border border-line bg-panel">
      <div className="loading-bar" />
      <p className="px-3 py-6 text-[13px] text-muted">{text}</p>
    </div>
  );
}

export function EmptyState({ title, detail }: { title: string; detail?: string }) {
  return (
    <div className="border border-dashed border-line bg-panel px-3 py-6">
      <p className="text-[13px] text-text">{title}</p>
      {detail ? <p className="mt-1 max-w-2xl text-[12px] leading-relaxed text-muted">{detail}</p> : null}
    </div>
  );
}

export function ErrorState({ title, message, onRetry }: { title: string; message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="border border-danger/50 bg-danger/10 px-3 py-4">
      <p className="text-[13px] font-medium text-danger">{title}</p>
      <p className="mt-1 text-[12px] leading-relaxed text-text">{message}</p>
      {onRetry ? (
        <div className="mt-3">
          <Button onClick={onRetry}>Retry</Button>
        </div>
      ) : null}
    </div>
  );
}

export function ErrorBanner({ message }: { message: string }) {
  return (
    <div role="alert" className="border border-danger/50 bg-danger/10 px-3 py-2 text-[12px] text-text">
      {message}
    </div>
  );
}

export function FieldMessageList({ items }: { items: FieldError[] }) {
  if (items.length === 0) return null;
  return (
    <ul className="space-y-1">
      {items.map((item, index) => (
        <li key={`${item.field}-${index}`} className="text-[12px] leading-relaxed">
          {item.field ? <span className="font-mono text-warn">{item.field}</span> : null}
          <span className="text-text">{item.field ? " " : ""}{item.message}</span>
        </li>
      ))}
    </ul>
  );
}

export function FieldErrors({ errors }: { errors: FieldError[] }) {
  if (errors.length === 0) return null;
  return (
    <div role="alert" className="border border-danger/50 bg-danger/10 px-3 py-2">
      <p className="text-[12px] font-medium text-danger">The API returned field errors.</p>
      <div className="mt-2">
        <FieldMessageList items={errors} />
      </div>
    </div>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <p className="text-[10px] uppercase tracking-[0.16em] text-faint">{eyebrow}</p>
        <h1 className="truncate text-lg font-semibold tracking-tight">{title}</h1>
        {description ? <p className="mt-1 max-w-3xl text-[12px] leading-relaxed text-muted">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function Panel({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="border border-line bg-panel">
      <header className="flex items-center justify-between gap-3 border-b border-line px-3 py-2">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted">{title}</h2>
        {action}
      </header>
      <div className="p-3">{children}</div>
    </section>
  );
}

export function SectionHeading({ id, title, count, meta }: { id?: string; title: string; count?: number; meta?: string }) {
  return (
    <div className="mb-2 flex items-baseline justify-between gap-3">
      <h2 id={id} className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted">
        {title}
      </h2>
      <span className="font-mono text-[11px] text-faint">{meta ?? (count != null ? String(count) : "")}</span>
    </div>
  );
}

export function FieldGrid({ items }: { items: Array<{ label: string; value: ReactNode }> }) {
  return (
    <dl className="grid grid-cols-1 gap-px bg-line sm:grid-cols-2 xl:grid-cols-3">
      {items.map((item) => (
        <div key={item.label} className="bg-panel px-3 py-2">
          <dt className="text-[10px] uppercase tracking-[0.14em] text-faint">{item.label}</dt>
          <dd className="mt-1 break-all font-mono text-[12px]">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const tone =
    status === "running"
      ? "border-accent/40 bg-accent/10 text-accent"
      : status === "completed"
        ? "border-ok/40 bg-ok/10 text-ok"
        :     status === "failed"
      ? "border-danger/50 bg-danger/10 text-danger"
      : status === "rejected" || status === "budget_exhausted"
        ? "border-warn/40 bg-warn/10 text-warn"
        : "border-line bg-panel-2 text-muted";
  return (
    <span title={status} className={cx("inline-flex items-center gap-1.5 border px-1.5 py-0.5 text-[11px]", tone)}>
      <span className={cx("h-1.5 w-1.5", status === "running" ? "animate-pulse bg-accent" : "bg-current")} />
      {label(status)}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string | null | undefined }) {
  if (!severity) return <span className="text-faint">—</span>;
  const tone =
    severity === "critical"
      ? "border-danger/50 bg-danger/15 text-danger"
      : severity === "high"
        ? "border-warn/50 bg-warn/15 text-warn"
        : severity === "medium"
          ? "border-info/40 bg-info/10 text-info"
          : severity === "low"
            ? "border-ok/40 bg-ok/10 text-ok"
            : "border-line bg-panel-2 text-muted";
  return (
    <span title={severity} className={cx("inline-flex border px-1.5 py-0.5 text-[11px] uppercase tracking-wide", tone)}>
      {label(severity)}
    </span>
  );
}

export function VerdictBadge({ verdict }: { verdict: string | null | undefined }) {
  if (!verdict) return <span className="text-[12px] text-faint">Unassessed</span>;
  const tone =
    verdict === "likely_benign"
      ? "border-ok/40 bg-ok/10 text-ok"
      : verdict === "suspicious"
        ? "border-warn/40 bg-warn/10 text-warn"
        : verdict === "confirmed_threat"
          ? "border-danger/50 bg-danger/10 text-danger"
          : "border-line bg-panel-2 text-text";
  return (
    <span title={verdict} className={cx("inline-flex border px-1.5 py-0.5 text-[11px]", tone)}>
      {label(verdict)}
    </span>
  );
}

export function Metric({ label: name, value, hint }: { label: string; value: string; hint?: string | null }) {
  return (
    <div className="bg-panel px-3 py-2">
      <dt className="font-mono text-[10px] uppercase tracking-[0.14em] text-faint">{name}</dt>
      <dd className="mt-1 font-mono text-[13px] tabular-nums text-text">
        {value}
        {hint ? <span className="ml-2 text-[11px] text-muted">{hint}</span> : null}
      </dd>
    </div>
  );
}
