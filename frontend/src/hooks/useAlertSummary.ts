import { useEffect, useState } from "react";
import { getAlert } from "../api";
import type { AlertDetail } from "../types";

export function useAlertSummary(alertId: string | null | undefined) {
  const [alert, setAlert] = useState<AlertDetail | null>(null);

  useEffect(() => {
    if (!alertId) {
      setAlert(null);
      return;
    }
    let cancelled = false;
    setAlert(null);
    getAlert(alertId)
      .then((result) => {
        if (!cancelled) setAlert(result.alert);
      })
      .catch(() => {
        if (!cancelled) setAlert(null);
      });
    return () => {
      cancelled = true;
    };
  }, [alertId]);

  return alert;
}
