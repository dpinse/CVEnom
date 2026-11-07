import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";

/** Dashboard range control (24h | 7d | 14d | 30d). Dashboard-only: Threats uses its own filters. */
export const RANGES = ["24h", "7d", "14d", "30d"] as const;
export type RangeKey = (typeof RANGES)[number];
export const DEFAULT_RANGE: RangeKey = "7d";

export const RANGE_LABEL: Record<RangeKey, string> = {
  "24h": "24 hours",
  "7d": "7 days",
  "14d": "14 days",
  "30d": "30 days",
};

/** Exact, case-sensitive match; anything else is null. */
export function parseRange(s: string | null): RangeKey | null {
  return (RANGES as readonly string[]).includes(s ?? "") ? (s as RangeKey) : null;
}

const STORAGE_KEY = "cvenom.range";

function stored(): RangeKey | null {
  try {
    return parseRange(localStorage.getItem(STORAGE_KEY));
  } catch {
    return null;
  }
}

/** Current Dashboard range: `?range=` first, then localStorage, then the default. */
export function useRange(): { range: RangeKey; setRange: (r: RangeKey) => void } {
  const [sp, setSp] = useSearchParams();
  const range = parseRange(sp.get("range")) ?? stored() ?? DEFAULT_RANGE;
  const setRange = useCallback(
    (r: RangeKey) => {
      setSp(
        (prev) => {
          const next = new URLSearchParams(prev);
          next.set("range", r);
          return next;
        },
        { replace: true },
      );
      try {
        localStorage.setItem(STORAGE_KEY, r);
      } catch {
        /* storage unavailable: the URL still carries the choice */
      }
    },
    [setSp],
  );
  return { range, setRange };
}
