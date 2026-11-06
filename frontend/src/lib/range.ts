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
