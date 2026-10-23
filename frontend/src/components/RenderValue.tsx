import { safeStringify } from "../lib/json";

const MAX_DEPTH = 8;

export function RenderValue({ value, depth = 0 }: { value: unknown; depth?: number }) {
  if (value == null) return <p className="text-[13px] text-faint">No content.</p>;

  if (typeof value === "string") {
    if (!value.trim()) return <p className="text-[13px] text-faint">No content.</p>;
    const paragraphs = value.split(/\n{2,}/);
    return (
      <div className="space-y-2">
        {paragraphs.map((paragraph, index) => (
          <p key={index} className="whitespace-pre-wrap break-words text-[13px] leading-relaxed">
            {paragraph}
          </p>
        ))}
      </div>
    );
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return <p className="font-mono text-[13px]">{String(value)}</p>;
  }

  if (depth > MAX_DEPTH) {
    return <JsonBlock value={value} />;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) return <p className="text-[13px] text-faint">None.</p>;
    const primitives = value.every(
      (item) => item == null || typeof item === "string" || typeof item === "number" || typeof item === "boolean",
    );
    if (primitives) {
      return (
        <ul className="list-disc space-y-1 pl-4 text-[13px] leading-relaxed">
          {value.map((item, index) => (
            <li key={index} className="break-words">
              {item == null || item === "" ? "—" : String(item)}
            </li>
          ))}
        </ul>
      );
    }
    return (
      <div className="space-y-2">
        {value.map((item, index) => (
          <div key={index} className="border border-line bg-bg px-3 py-2">
            <p className="mb-2 font-mono text-[10px] uppercase tracking-[0.14em] text-faint">Item {index + 1}</p>
            <RenderValue value={item} depth={depth + 1} />
          </div>
        ))}
      </div>
    );
  }

  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return <p className="text-[13px] text-faint">None.</p>;
    return (
      <div className="space-y-2">
        {entries.map(([key, entry]) => (
          <div key={key} className="grid grid-cols-1 gap-1 border-b border-line pb-2 md:grid-cols-[14rem_1fr]">
            <div className="break-all font-mono text-[11px] text-muted">{key}</div>
            <div className="min-w-0">
              <RenderValue value={entry} depth={depth + 1} />
            </div>
          </div>
        ))}
      </div>
    );
  }

  return <p className="break-all font-mono text-[12px]">{String(value)}</p>;
}

export function JsonBlock({ value }: { value: unknown }) {
  if (value == null) return <p className="text-[12px] text-faint">None</p>;
  if (typeof value === "string") {
    return <pre className="whitespace-pre-wrap break-all font-mono text-[11px] leading-relaxed text-muted">{value}</pre>;
  }
  return (
    <pre className="overflow-x-auto whitespace-pre-wrap break-all font-mono text-[11px] leading-relaxed text-muted">
      {safeStringify(value)}
    </pre>
  );
}
