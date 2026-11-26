import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, createAlert, getInvestigation, listAlerts } from "./api";

function respond(status: number, body: unknown) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return vi.fn(async () => new Response(text, { status }));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("request errors", () => {
  it("uses the API's detail message for a 404", async () => {
    vi.stubGlobal("fetch", respond(404, { detail: "Alert not found" }));
    const error = await createAlert({}).catch((err: unknown) => err);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(404);
    expect((error as ApiError).message).toBe("Alert not found");
  });

  it("exposes field errors from a 422", async () => {
    vi.stubGlobal(
      "fetch",
      respond(422, { errors: [{ field: "source", message: "source is required" }] }),
    );
    const error = (await createAlert({}).catch((err: unknown) => err)) as ApiError;
    expect(error.fieldErrors).toEqual([{ field: "source", message: "source is required" }]);
    expect(error.message).toBe("source: source is required");
  });

  it("reports an unreachable API as status 0", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("Failed to fetch"))));
    const error = (await listAlerts().catch((err: unknown) => err)) as ApiError;
    expect(error.status).toBe(0);
    expect(error.message).toMatch(/Cannot reach the API/);
  });

  it("keeps a non-JSON error body as the message", async () => {
    vi.stubGlobal("fetch", respond(502, "Bad gateway from proxy"));
    const error = (await listAlerts().catch((err: unknown) => err)) as ApiError;
    expect(error.status).toBe(502);
    expect(error.message).toBe("Bad gateway from proxy");
  });
});

describe("requests", () => {
  it("sends JSON with a content type", async () => {
    const fetch = respond(201, { alert: { id: "a1" }, warnings: [], duplicate: false });
    vi.stubGlobal("fetch", fetch);
    await createAlert({ name: "x" });
    const [path, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(path).toBe("/api/alerts");
    expect(new Headers(init.headers).get("Content-Type")).toBe("application/json");
    expect(init.body).toBe(JSON.stringify({ name: "x" }));
  });

  it("encodes ids in the path and forwards the abort signal", async () => {
    const fetch = respond(200, { id: "inv/1", status: "running" });
    vi.stubGlobal("fetch", fetch);
    const controller = new AbortController();
    await getInvestigation("inv/1", controller.signal);
    const [path, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(path).toBe("/api/investigations/inv%2F1");
    expect(init.signal).toBe(controller.signal);
  });

  it("rejects a response with the wrong shape", async () => {
    vi.stubGlobal("fetch", respond(200, { alerts: "nope" }));
    await expect(listAlerts()).rejects.toThrow(/Unexpected response/);
  });
});
