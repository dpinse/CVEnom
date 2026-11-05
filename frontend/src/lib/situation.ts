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

/** Calm 0, Elevated 1-2, High 3-5, Severe >= 6 or any KEV added within the window. */
export function situationLevel(exploited: CveItem[], now: Date): Situation {
  const n = exploited.length;
  if (n >= 6 || exploited.some((c) => isRecentKevDate(c.kev_added, now))) return { level: "Severe", lit: 4 };
  if (n >= 3) return { level: "High", lit: 3 };
  if (n >= 1) return { level: "Elevated", lit: 2 };
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
