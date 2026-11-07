/**
 * Pure helpers over the /api/geo summary that do NOT need the bundled world geometry.
 * Kept apart from globeData.ts so the main bundle (legend, static fallback) never pulls in
 * the TopoJSON atlas or MapLibre; globeData.ts re-exports everything here.
 */
import type { GeoSummaryItem } from "../lib/types";

export const GEO_KINDS = ["scan", "outage", "victim", "c2", "bgp"] as const;
export type GeoKind = (typeof GEO_KINDS)[number];

export function isGeoKind(k: unknown): k is GeoKind {
  return typeof k === "string" && (GEO_KINDS as readonly string[]).includes(k);
}

/**
 * THE colour mapping per hotspot kind, shared by the map paint (globeMap.ts), the legend and
 * the fallback swatches (GlobeChrome.tsx). Every kind gets a distinct token: --sev-crit is not
 * used because it is perceptually almost identical to --live (CIEDE2000 6.0 dark / 2.9 light).
 * Closest remaining pair is outage vs c2 (18.7 dark / 16.3 light), clearly distinguishable.
 */
export const KIND_TOKEN: Readonly<Record<GeoKind, string>> = {
  scan: "--live",
  outage: "--sev-high",
  victim: "--scope",
  c2: "--sev-med",
  bgp: "--sev-low",
};

/** Legend wording (singular, as in the approved mockup). */
export const KIND_LABEL: Record<GeoKind, string> = {
  scan: "exploit scanning",
  outage: "infrastructure outage",
  victim: "victim disclosure",
  c2: "C2 infrastructure",
  bgp: "BGP anomaly",
};

/**
 * Strict ISO 3166-1 alpha-2 check. The backend contract is upper-case ISO-2; anything else
 * (null, lower-case, alpha-3, empty) is malformed and skipped rather than guessed at.
 */
export function isIso2(code: unknown): code is string {
  return typeof code === "string" && /^[A-Z]{2}$/.test(code);
}

// ---- choropleth ---------------------------------------------------------------

/** Share of the alert colour mixed into the land colour, per bucket 0..4 (darker = more alerts). */
export const CHORO_STEPS = [0.16, 0.32, 0.5, 0.7, 0.9] as const;
export type Bucket = 0 | 1 | 2 | 3 | 4;

/** sqrt-scaled bucket of `n` against `max`; null when there is nothing to paint (n or max not positive, or NaN). */
export function choroplethBucket(n: number, max: number): Bucket | null {
  if (!(n > 0) || !(max > 0)) return null;
  return Math.min(4, Math.floor(Math.sqrt(n / max) * 5)) as Bucket;
}

/** Events per valid ISO-2 across all kinds. "XX" (unknown) is skipped; non-finite or negative counts as 0. */
export function countryTotals(items: readonly GeoSummaryItem[]): Map<string, number> {
  const out = new Map<string, number>();
  for (const it of items) {
    if (!it || !isIso2(it.country_code) || it.country_code === "XX") continue;
    const v = Number(it.events);
    out.set(it.country_code, (out.get(it.country_code) ?? 0) + (Number.isFinite(v) && v > 0 ? v : 0));
  }
  return out;
}

// ---- names, ranking, summaries ----------------------------------------------------

let regionNames: Intl.DisplayNames | null | undefined;
/** English country name for an ISO-2 code, falling back to the code itself. */
export function countryName(iso2: string): string {
  if (regionNames === undefined) {
    try {
      regionNames = new Intl.DisplayNames(["en"], { type: "region" });
    } catch {
      regionNames = null;
    }
  }
  try {
    return regionNames?.of(iso2) ?? iso2;
  } catch {
    return iso2;
  }
}

export interface RankedCountry {
  iso2: string;
  name: string;
  events: number;
}

/** Countries ranked by total events (ties: code). Countries with no events are dropped. */
export function rankCountries(totals: ReadonlyMap<string, number>, limit = 10): RankedCountry[] {
  return [...totals]
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, Math.max(0, limit))
    .map(([iso2, events]) => ({ iso2, name: countryName(iso2), events }));
}

/** Accessible name for the map, e.g. "Threat map: 3 countries with activity; most active United States, 40 events". */
export function describeGeo(totals: ReadonlyMap<string, number>, rangeLabel: string): string {
  const top = rankCountries(totals, 1)[0];
  if (!top) return `Threat map: no geolocated threat activity in the last ${rangeLabel}`;
  const n = [...totals.values()].filter((v) => v > 0).length;
  return `Threat map: ${n} ${n === 1 ? "country" : "countries"} with activity in the last ${rangeLabel}; most active ${top.name}, ${top.events} events`;
}

// ---- colour -----------------------------------------------------------------

function parseColor(c: string): [number, number, number] | null {
  const s = c.trim();
  let m = /^#([0-9a-f]{3})$/i.exec(s);
  if (m) return [...m[1]].map((h) => parseInt(h + h, 16)) as [number, number, number];
  m = /^#([0-9a-f]{6})$/i.exec(s);
  if (m) return [0, 2, 4].map((i) => parseInt(m![1].slice(i, i + 2), 16)) as [number, number, number];
  m = /^rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)/i.exec(s);
  if (m) return [Number(m[1]), Number(m[2]), Number(m[3])];
  return null;
}

const hex2 = (n: number) =>
  Math.round(Math.min(255, Math.max(0, n)))
    .toString(16)
    .padStart(2, "0");

/** `over` composited at `alpha` onto `base`, as #rrggbb. Unparseable `over` returns `base` unchanged. */
export function mixColor(base: string, over: string, alpha: number): string {
  const b = parseColor(base);
  const o = parseColor(over);
  if (!b) return base;
  if (!o) return `#${b.map(hex2).join("")}`;
  const a = Math.min(1, Math.max(0, alpha));
  return `#${b.map((v, i) => hex2(v + (o[i] - v) * a)).join("")}`;
}
