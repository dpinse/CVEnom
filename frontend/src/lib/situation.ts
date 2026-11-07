import type { CveItem, LanesOut, SummaryOut } from "./types";

export type SituationLevel = "Calm" | "Elevated" | "High" | "Severe";
export interface Situation {
  level: SituationLevel;
  /** Lit gauge bars, 0..4. Calm lights one (dim) bar so the instrument never looks dead. */
  lit: 0 | 1 | 2 | 3 | 4;
}

const DAY_MS = 86_400_000;
const ISO_DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
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

const KEV_DAYS_ELEVATED = 30;

/**
 * From the 7-day summary (`new_kev` = KEV listings in range, `latest_kev_added` = newest KEV date):
 * Severe = a listing today/yesterday (isRecentKevDate) or >= 6 new; High = >= 3 new;
 * Elevated = the newest listing is within 30 UTC days; Calm = otherwise.
 * A malformed date never counts.
 */
export function situationLevel(s: Pick<SummaryOut, "new_kev" | "latest_kev_added">, now: Date): Situation {
  if (isRecentKevDate(s.latest_kev_added, now) || s.new_kev >= 6) return { level: "Severe", lit: 4 };
  if (s.new_kev >= 3) return { level: "High", lit: 3 };
  const d = s.latest_kev_added;
  const cutoff = isoDate(new Date(now.getTime() - KEV_DAYS_ELEVATED * DAY_MS));
  if (d && ISO_DAY_RE.test(d) && d >= cutoff) return { level: "Elevated", lit: 2 };
  return { level: "Calm", lit: 1 };
}

/** The newest in-window KEV across every lane (ties keep the first seen), or null. */
export function recentKev(lanes: LanesOut | undefined, now: Date): CveItem | null {
  if (!lanes) return null;
  let best: CveItem | null = null;
  for (const lane of [lanes.EXPLOITED, lanes.LIKELY, lanes.LOUD, lanes.FRESH]) {
    for (const c of lane?.items ?? []) {
      if (!isRecentKevDate(c.kev_added, now)) continue;
      if (!best || (c.kev_added ?? "") > (best.kev_added ?? "")) best = c;
    }
  }
  return best;
}
