import type { CveItem, LanesOut } from "./types";

export type SituationLevel = "Calm" | "Elevated" | "High" | "Severe";
export interface Situation {
  level: SituationLevel;
  /** Lit gauge bars, 0..4. Calm lights one (dim) bar so the instrument never looks dead. */
  lit: 0 | 1 | 2 | 3 | 4;
}

const DAY_MS = 86_400_000;
const isoDate = (d: Date) => d.toISOString().slice(0, 10);

/**
 * `kev_added` is a DATE with no time, so "within the last 24h" cannot be exact. We treat it
 * as: the date is today or yesterday in UTC. That never misses a KEV added in the last 24h
 * and may include up to 48h-old additions made late yesterday; for a threat radar that
 * errs on the safe (louder) side.
 */
export function isRecentKevDate(kevAdded: string | null, now: Date): boolean {
  if (!kevAdded) return false;
  return kevAdded === isoDate(now) || kevAdded === isoDate(new Date(now.getTime() - DAY_MS));
}

const ISO_DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * By `kev_added` (UTC dates; the lane is already the 30-day EXPLOITED window):
 * Severe = any listing today/yesterday (isRecentKevDate) or >= 6 in the last 7 days;
 * High = >= 3 in the last 7 days; Elevated = any listing; Calm = none.
 * A malformed date never counts toward the 7-day span (lexical comparison would let junk through).
 */
export function situationLevel(exploited: CveItem[], now: Date): Situation {
  const weekStart = isoDate(new Date(now.getTime() - 7 * DAY_MS));
  let week = 0;
  let recent = false;
  for (const c of exploited) {
    const d = c.kev_added;
    if (isRecentKevDate(d, now)) recent = true;
    if (d && ISO_DAY_RE.test(d) && d >= weekStart) week++;
  }
  if (recent || week >= 6) return { level: "Severe", lit: 4 };
  if (week >= 3) return { level: "High", lit: 3 };
  if (exploited.length >= 1) return { level: "Elevated", lit: 2 };
  return { level: "Calm", lit: 1 };
}

/** The newest in-window KEV across every lane (ties keep the first seen), or null. */
export function recentKev(lanes: LanesOut | undefined, now: Date): CveItem | null {
  if (!lanes) return null;
  let best: CveItem | null = null;
  for (const lane of [lanes.EXPLOITED, lanes.LIKELY, lanes.LOUD, lanes.FRESH]) {
    for (const c of lane ?? []) {
      if (!isRecentKevDate(c.kev_added, now)) continue;
      if (!best || (c.kev_added ?? "") > (best.kev_added ?? "")) best = c;
    }
  }
  return best;
}
