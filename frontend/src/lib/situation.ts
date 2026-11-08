import type { CveItem, LanesOut } from "./types";

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
