import { useEffect, useState } from "react";
import { ApiError, getInvestigation, isAbortError } from "../api";
import type { Investigation } from "../types";
import { isTerminalStatus } from "../types";

export interface InvestigationError {
  message: string;
  status: number | null;
}

export function useInvestigation(id: string | undefined) {
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [error, setError] = useState<InvestigationError | null>(null);
  const [loading, setLoading] = useState(true);
  const [polling, setPolling] = useState(false);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);

  useEffect(() => {
    if (!id) {
      setInvestigation(null);
      setLoading(false);
      setPolling(false);
      setError({ message: "Missing investigation id.", status: null });
      return;
    }

    const controller = new AbortController();
    let cancelled = false;
    let timer = 0;
    setInvestigation(null);
    setUpdatedAt(null);
    setLoading(true);
    setError(null);
    setPolling(false);

    const run = async () => {
      try {
        const next = await getInvestigation(id, controller.signal);
        if (cancelled) return;
        setInvestigation(next);
        setError(null);
        setLoading(false);
        setUpdatedAt(new Date().toISOString());
        if (isTerminalStatus(next.status)) {
          setPolling(false);
          return;
        }
        setPolling(true);
      } catch (err) {
        if (cancelled || isAbortError(err)) return;
        const status = err instanceof ApiError ? err.status : null;
        const message =
          status === 404
            ? "Investigation not found."
            : err instanceof Error
              ? err.message
              : "Failed to load the investigation.";
        setError({ message, status });
        setLoading(false);
        const retry = err instanceof ApiError && (err.status === 0 || err.status >= 500);
        if (!retry) {
          setPolling(false);
          return;
        }
        setPolling(true);
      }
      if (cancelled) return;
      timer = window.setTimeout(() => {
        void run();
      }, 1000);
    };

    void run();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [id, reloadToken]);

  return {
    investigation,
    error,
    loading,
    polling,
    updatedAt,
    retry: () => setReloadToken((value) => value + 1),
  };
}
