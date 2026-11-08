import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { DEFAULT_RANGE } from "../lib/range";
import { useLanes } from "../lib/queries";
import { LANE_CAP } from "./Lanes";
import { recentKev } from "../lib/recentKev";
import { Text } from "../lib/text";
import { useNow } from "../lib/useNow";

const DISMISS_KEY = "cvenom-alert-dismissed";

function readDismissed(): string | null {
  try {
    return sessionStorage.getItem(DISMISS_KEY);
  } catch {
    return null;
  }
}

/**
 * Newest KEV addition (today or yesterday, UTC). Clicking sets `?cve=<id>`, which the
 * drawer (Task 7) opens from and which makes the link shareable. Dismissal is per CVE for
 * this browser session: a newer CVE shows again.
 */
export function AlertBar() {
  const lanes = useLanes(DEFAULT_RANGE, LANE_CAP);
  const now = useNow();
  const [, setSearchParams] = useSearchParams();
  const [dismissed, setDismissed] = useState<string | null>(readDismissed);

  const cve = recentKev(lanes.data, now);
  if (!cve || cve.cve_id === dismissed) return null;

  const open = () =>
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set("cve", cve.cve_id);
      return next;
    });
  const dismiss = () => {
    try {
      sessionStorage.setItem(DISMISS_KEY, cve.cve_id);
    } catch {
      // storage blocked: dismissed for this view only
    }
    setDismissed(cve.cve_id);
  };

  return (
    <aside className="alertbar gutter" aria-label="Newly exploited vulnerability">
      <button type="button" className="alert-open" onClick={open}>
        <span className="alert-tag" aria-hidden="true">
          KEV
        </span>
        <strong className="alert-id">{`${cve.cve_id} added to KEV`}</strong>
        <Text className="alert-snippet" value={cve.summary} />
      </button>
      <button type="button" className="alert-dismiss" onClick={dismiss} aria-label="Dismiss alert">
        <span aria-hidden="true">×</span>
      </button>
    </aside>
  );
}
