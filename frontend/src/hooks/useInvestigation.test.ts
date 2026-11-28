import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useInvestigation } from "./useInvestigation";

function document(status: string) {
  return { id: "inv-1", alert_id: "a1", status, metrics: {}, steps: [], evidence: [], timeline: [], audit: [] };
}

function serve(...replies: Array<[number, unknown]>) {
  const queue = [...replies];
  const fetch = vi.fn(async () => {
    const [status, body] = queue.length > 1 ? queue.shift()! : queue[0];
    return new Response(JSON.stringify(body), { status });
  });
  vi.stubGlobal("fetch", fetch);
  return fetch;
}

async function tick(ms = 1000) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("useInvestigation", () => {
  it("polls every second until the status is final", async () => {
    const fetch = serve([200, document("running")], [200, document("running")], [200, document("completed")]);
    const { result } = renderHook(() => useInvestigation("inv-1"));
    await tick(0);
    expect(result.current.investigation?.status).toBe("running");
    expect(result.current.polling).toBe(true);

    await tick();
    await tick();
    expect(result.current.investigation?.status).toBe("completed");
    expect(result.current.polling).toBe(false);

    await tick(5000);
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it("keeps retrying after a server error and reports it", async () => {
    const fetch = serve([500, { detail: "boom" }], [200, document("completed")]);
    const { result } = renderHook(() => useInvestigation("inv-1"));
    await tick(0);
    expect(result.current.error?.status).toBe(500);
    expect(result.current.polling).toBe(true);

    await tick();
    expect(result.current.error).toBeNull();
    expect(result.current.investigation?.status).toBe("completed");
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("stops on a 404", async () => {
    const fetch = serve([404, { detail: "Investigation not found" }]);
    const { result } = renderHook(() => useInvestigation("missing"));
    await tick(0);
    expect(result.current.error).toEqual({ message: "Investigation not found.", status: 404 });
    expect(result.current.polling).toBe(false);

    await tick(5000);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("stops polling when unmounted", async () => {
    const fetch = serve([200, document("running")]);
    const { unmount } = renderHook(() => useInvestigation("inv-1"));
    await tick(0);
    unmount();
    await tick(5000);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
