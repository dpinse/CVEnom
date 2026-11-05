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

/** Colour token per hotspot kind. Hue is reserved for signal (plan: Global Constraints). */
export const KIND_TOKEN: Record<GeoKind, string> = {
  scan: "--live",
  outage: "--sev-high",
  victim: "--sev-crit",
  c2: "--sev-med",
  bgp: "--scope",
};

/** Legend wording (singular, as in the approved mockup). */
export const KIND_LABEL: Record<GeoKind, string> = {
  scan: "exploit scanning",
  outage: "infrastructure outage",
  victim: "victim disclosure",
  c2: "C2 infrastructure",
  bgp: "BGP anomaly",
};

/** Phrase used in the accessible summary: "N countries with <phrase>". */
const KIND_PHRASE: Record<GeoKind, string> = {
  outage: "outages",
  scan: "exploit scanning",
  victim: "victim disclosures",
  c2: "C2 infrastructure",
  bgp: "BGP anomalies",
};

/**
 * Strict ISO 3166-1 alpha-2 check. The backend contract is upper-case ISO-2; anything else
 * (null, lower-case, alpha-3, empty) is malformed and skipped rather than guessed at.
 */
export function isIso2(code: unknown): code is string {
  return typeof code === "string" && /^[A-Z]{2}$/.test(code);
}

// ---- outage shading ---------------------------------------------------------

/** Outage magnitude below this is shading level 1 (light tint). */
export const OUTAGE_LEVEL_1_MAX = 2;
/** Outage magnitude below this (and >= OUTAGE_LEVEL_1_MAX) is level 2; at or above it, level 3. */
export const OUTAGE_LEVEL_2_MAX = 5;

export type ShadeLevel = 0 | 1 | 2 | 3;

/** 0 = none (no outage, or a non-positive / non-finite magnitude), 1 = < 2, 2 = < 5, 3 = >= 5. */
export function outageLevel(magnitude: number): ShadeLevel {
  if (!Number.isFinite(magnitude) || magnitude <= 0) return 0;
  if (magnitude < OUTAGE_LEVEL_1_MAX) return 1;
  if (magnitude < OUTAGE_LEVEL_2_MAX) return 2;
  return 3;
}

/** Country -> shading level from the **outage** items only. Duplicates keep the highest level. */
export function toCountryShading(items: readonly GeoSummaryItem[]): Map<string, ShadeLevel> {
  const out = new Map<string, ShadeLevel>();
  for (const it of items) {
    if (it?.kind !== "outage" || !isIso2(it.country_code)) continue;
    const level = outageLevel(Number(it.magnitude));
    out.set(it.country_code, Math.max(out.get(it.country_code) ?? 0, level) as ShadeLevel);
  }
  return out;
}

/** Alpha of --sev-high blended over --land for shading levels 0..3. */
export const SHADE_ALPHA: readonly [number, number, number, number] = [0, 0.3, 0.55, 0.8];

// ---- hotspot radius -----------------------------------------------------------

export const RADIUS_MIN = 3;
export const RADIUS_MAX = 18;
/** px per natural-log unit of (1 + magnitude). */
export const RADIUS_SCALE = 4;

/** Circle radius in px: RADIUS_MIN + RADIUS_SCALE * ln(1 + magnitude), clamped to [3, 18]. */
export function circleRadius(magnitude: number): number {
  const m = Number.isFinite(magnitude) && magnitude > 0 ? magnitude : 0;
  const r = RADIUS_MIN + RADIUS_SCALE * Math.log1p(m);
  return Math.min(RADIUS_MAX, Math.max(RADIUS_MIN, r));
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

function finite(n: unknown): number {
  const v = Number(n);
  return Number.isFinite(v) ? v : 0;
}

/** Valid items only: ISO-2 country and a known kind. */
export function validItems(items: readonly GeoSummaryItem[]): GeoSummaryItem[] {
  return items.filter((it) => it && isIso2(it.country_code) && isGeoKind(it.kind));
}

export interface RankedCountry {
  iso2: string;
  name: string;
  magnitude: number;
  events: number;
  kinds: GeoKind[];
}

/** Countries ranked by total magnitude across kinds (ties: more events, then code). */
export function rankCountries(items: readonly GeoSummaryItem[], limit = 10): RankedCountry[] {
  const by = new Map<string, RankedCountry>();
  for (const it of validItems(items)) {
    const row = by.get(it.country_code) ?? { iso2: it.country_code, name: "", magnitude: 0, events: 0, kinds: [] };
    row.magnitude += Math.max(0, finite(it.magnitude));
    row.events += Math.max(0, finite(it.events));
    if (!row.kinds.includes(it.kind as GeoKind)) row.kinds.push(it.kind as GeoKind);
    by.set(it.country_code, row);
  }
  return [...by.values()]
    .sort((a, b) => b.magnitude - a.magnitude || b.events - a.events || a.iso2.localeCompare(b.iso2))
    .slice(0, Math.max(0, limit))
    .map((r) => ({ ...r, name: countryName(r.iso2), kinds: GEO_KINDS.filter((k) => r.kinds.includes(k)) }));
}

/** Individual (country, kind) hotspots ranked by magnitude, for the screen-reader list. */
export function topHotspots(items: readonly GeoSummaryItem[], limit = 10): GeoSummaryItem[] {
  return validItems(items)
    .sort((a, b) => finite(b.magnitude) - finite(a.magnitude) || finite(b.events) - finite(a.events))
    .slice(0, Math.max(0, limit));
}

const plural = (n: number) => (n === 1 ? "country" : "countries");

/** Accessible name for the globe, e.g. "Global threat map: 3 countries with outages, 12 countries with exploit scanning". */
export function describeGeo(items: readonly GeoSummaryItem[]): string {
  const valid = validItems(items);
  const parts: string[] = [];
  for (const kind of ["outage", "scan", "victim", "c2", "bgp"] as const) {
    const n = new Set(
      valid.filter((it) => it.kind === kind && (kind !== "outage" || outageLevel(finite(it.magnitude)) > 0)).map((it) => it.country_code),
    ).size;
    if (n > 0) parts.push(`${n} ${plural(n)} with ${KIND_PHRASE[kind]}`);
  }
  if (parts.length === 0) return "Global threat map: no geolocated threat activity in the last 24 hours";
  return `Global threat map: ${parts.join(", ")}`;
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

const hex2 = (n: number) => Math.round(Math.min(255, Math.max(0, n))).toString(16).padStart(2, "0");

/** `over` composited at `alpha` onto `base`, as #rrggbb. Unparseable `over` returns `base` unchanged. */
export function mixColor(base: string, over: string, alpha: number): string {
  const b = parseColor(base);
  const o = parseColor(over);
  if (!b) return base;
  if (!o) return `#${b.map(hex2).join("")}`;
  const a = Math.min(1, Math.max(0, alpha));
  return `#${b.map((v, i) => hex2(v + (o[i] - v) * a)).join("")}`;
}
