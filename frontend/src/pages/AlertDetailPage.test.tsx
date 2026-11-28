import { cleanup, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AlertDetailPage } from "./AlertDetailPage";

const ALERT = {
  id: "alrt-1",
  source: "demo-siem",
  name: "Suspicious sign-in",
  description: "x",
  severity: "high",
  detected_at: "2026-04-12T14:26:00Z",
  src_ip: "203.0.113.50",
  dst_ip: null,
  username: "jsmith",
  hostname: "WS-JSMITH",
  file_hashes: [],
  domains: [],
  urls: [],
  mitre_techniques: [],
  raw: {},
  iocs: [],
};

function api(investigations: unknown[] | null) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: string) => {
      if (path === "/api/alerts/alrt-1") return new Response(JSON.stringify({ alert: ALERT, warnings: [] }));
      if (path === "/api/alerts/alrt-1/investigations") {
        return investigations === null
          ? new Response(JSON.stringify({ detail: "boom" }), { status: 500 })
          : new Response(JSON.stringify({ investigations }));
      }
      return new Response(JSON.stringify({ detail: "unexpected" }), { status: 404 });
    }),
  );
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/alerts/alrt-1"]}>
      <Routes>
        <Route path="/alerts/:id" element={<AlertDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("AlertDetailPage investigations", () => {
  it("lists past investigations with links to each run and report", async () => {
    api([
      { id: "inv-2", status: "running", stop_reason: null, verdict: null, created_at: "2026-11-26T10:05:00Z", updated_at: "2026-11-26T10:05:01Z" },
      { id: "inv-1", status: "completed", stop_reason: "completed", verdict: "likely_benign", created_at: "2026-11-26T10:00:00Z", updated_at: "2026-11-26T10:00:02Z" },
    ]);
    renderPage();
    const section = await screen.findByRole("region", { name: "Investigations" });
    const rows = await within(section).findAllByRole("listitem");
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByRole("link", { name: "inv-2" }).getAttribute("href")).toBe("/investigations/inv-2");
    expect(within(rows[0]).getByText("Running")).toBeTruthy();
    expect(within(rows[1]).getByText("Likely benign")).toBeTruthy();
    expect(within(rows[1]).getByRole("link", { name: "Report" }).getAttribute("href")).toBe("/investigations/inv-1/report");
  });

  it("says when there are no investigations yet", async () => {
    api([]);
    renderPage();
    const section = await screen.findByRole("region", { name: "Investigations" });
    expect(await within(section).findByText("No investigations yet.")).toBeTruthy();
  });

  it("keeps the page usable when the history fails to load", async () => {
    api(null);
    renderPage();
    const section = await screen.findByRole("region", { name: "Investigations" });
    expect(await within(section).findByText(/Could not load past investigations/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Start investigation" })).toBeTruthy();
  });
});
