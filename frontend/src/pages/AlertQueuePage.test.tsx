import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AlertQueuePage } from "./AlertQueuePage";

type Handler = (path: string, init?: RequestInit) => [number, unknown];

function api(handler: Handler) {
  const fetch = vi.fn(async (path: string, init?: RequestInit) => {
    const [status, body] = handler(path, init);
    return new Response(JSON.stringify(body), { status });
  });
  vi.stubGlobal("fetch", fetch);
  return fetch;
}

function Where() {
  return <p data-testid="where">{useLocation().pathname}</p>;
}

function renderQueue() {
  return render(
    <MemoryRouter initialEntries={["/"]}>
      <Routes>
        <Route path="/" element={<AlertQueuePage />} />
        <Route path="*" element={<Where />} />
      </Routes>
    </MemoryRouter>,
  );
}

const ALERT = {
  id: "alrt-1",
  source: "demo-siem",
  name: "Multiple failed logins followed by success",
  severity: "high",
  detected_at: "2026-04-12T14:26:00Z",
  username: "jsmith",
  hostname: "WS-JSMITH",
  src_ip: "203.0.113.50",
  verdict: "confirmed_threat",
};

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("AlertQueuePage", () => {
  it("lists alerts with their verdict", async () => {
    api((path) => (path === "/api/alerts" ? [200, { alerts: [ALERT] }] : [200, { scenarios: [] }]));
    renderQueue();
    expect(await screen.findByText(ALERT.name)).toBeTruthy();
    expect(screen.getByText("jsmith")).toBeTruthy();
    expect(screen.getByText("Confirmed threat")).toBeTruthy();
  });

  it("links the verdict to the investigation it came from", async () => {
    api((path) =>
      path === "/api/alerts"
        ? [200, { alerts: [{ ...ALERT, latest_investigation_id: "inv-7" }] }]
        : [200, { scenarios: [] }],
    );
    renderQueue();
    const verdict = await screen.findByRole("link", { name: /Confirmed threat/ });
    expect(verdict.getAttribute("href")).toBe("/investigations/inv-7");
  });

  it("shows an error with a retry that reloads the list", async () => {
    let failing = true;
    const fetch = api((path) => {
      if (path === "/api/scenarios") return [200, { scenarios: [] }];
      return failing ? [500, { detail: "database is locked" }] : [200, { alerts: [ALERT] }];
    });
    renderQueue();
    expect(await screen.findByText("database is locked")).toBeTruthy();

    failing = false;
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText(ALERT.name)).toBeTruthy();
    expect(fetch.mock.calls.filter(([path]) => path === "/api/alerts")).toHaveLength(2);
  });

  it("opens the alert after a scenario loads", async () => {
    api((path, init) => {
      if (path === "/api/alerts") return [200, { alerts: [] }];
      if (path === "/api/scenarios") return [200, { scenarios: [] }];
      if (path === "/api/scenarios/account_compromise/load" && init?.method === "POST") {
        return [201, { alert: { id: "alrt-9" }, warnings: [], duplicate: false }];
      }
      return [404, { detail: "unexpected" }];
    });
    renderQueue();
    await screen.findByText("No alerts in the queue.");
    fireEvent.click(screen.getAllByRole("button", { name: "Load" })[0]);
    await waitFor(() => expect(screen.getByTestId("where").textContent).toBe("/alerts/alrt-9"));
  });

  it("shows field errors when pasted JSON is rejected", async () => {
    api((path, init) => {
      if (path === "/api/alerts" && init?.method === "POST") {
        return [422, { errors: [{ field: "detected_at", message: "detected_at is required" }] }];
      }
      if (path === "/api/alerts") return [200, { alerts: [] }];
      return [200, { scenarios: [] }];
    });
    renderQueue();
    await screen.findByText("No alerts in the queue.");
    fireEvent.change(screen.getByLabelText("Alert JSON"), { target: { value: '{"name": "x"}' } });
    fireEvent.click(screen.getByRole("button", { name: "Ingest alert" }));
    expect(await screen.findByText("detected_at is required")).toBeTruthy();
  });
});
