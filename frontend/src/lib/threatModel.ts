import type { AffectedVersion, CveDetail, CveEvent, CveEventKind } from "./types";
import { decodeEntities } from "./text";

const HOUR = 36e5;

/** Signed distance of `at` from `t0`: "t = 0", "+5h", "+3d", "−9d" (U+2212). Hours under 48h, whole days after. */
export function offsetLabel(at: string, t0: string): string {
  const delta = Date.parse(at) - Date.parse(t0);
  if (!Number.isFinite(delta)) return "";
  if (delta === 0) return "t = 0";
  const sign = delta < 0 ? "−" : "+";
  const abs = Math.abs(delta);
  return abs < 48 * HOUR ? `${sign}${Math.round(abs / HOUR)}h` : `${sign}${Math.round(abs / (24 * HOUR))}d`;
}

/** The kind's own wording; the row appends the real source ("Published · NVD"), nothing is hard-coded. */
const KIND_LABEL: Record<CveEventKind, string> = {
  published: "Published",
  reserved: "CVE ID reserved",
  nvd_modified: "Record updated",
  poc_published: "Public exploit released",
  detection: "Detection template published",
  first_news: "First news coverage",
  kev_added: "Added to KEV, exploited in the wild",
  epss_crossed: "EPSS crossed p95",
};
const KEY_KINDS: ReadonlySet<string> = new Set<CveEventKind>(["published", "poc_published", "kev_added"]);

export interface TimelineRow {
  at: string;
  offset: string | null;
  label: string;
  source: string;
  key: boolean;
}

/** Chronological rows, one per kind+source as stored; only the earliest `first_news` is kept. */
export function timelineRows(events: CveEvent[], published: string | null): TimelineRow[] {
  const byTime = [...events].sort((a, b) => Date.parse(a.occurred_at) - Date.parse(b.occurred_at));
  let sawNews = false;
  const rows: TimelineRow[] = [];
  for (const e of byTime) {
    if (e.kind === "first_news") {
      if (sawNews) continue;
      sawNews = true;
    }
    rows.push({
      at: e.occurred_at,
      offset: published === null ? null : offsetLabel(e.occurred_at, published),
      label: KIND_LABEL[e.kind] ?? e.kind,
      source: e.source,
      key: KEY_KINDS.has(e.kind),
    });
  }
  return rows;
}

const isoDay = (iso: string | null): string => {
  const t = iso === null ? NaN : Date.parse(iso);
  return Number.isFinite(t) ? new Date(t).toISOString().slice(0, 10) : "";
};

const earliest = (events: CveEvent[], kind: CveEventKind): CveEvent | undefined =>
  events.filter((e) => e.kind === kind).sort((a, b) => Date.parse(a.occurred_at) - Date.parse(b.occurred_at))[0];

const NUCLEI_PREFIX = "/projectdiscovery/nuclei-templates/";
/** Same rule as the backend's is_nuclei_reference: github.com and the nuclei-templates repo path. */
function isNucleiReference(raw: string): boolean {
  try {
    const u = new URL(decodeEntities(raw));
    return u.hostname.toLowerCase() === "github.com" && u.pathname.toLowerCase().startsWith(NUCLEI_PREFIX);
  } catch {
    return false;
  }
}

const KEV_LABEL: Record<string, string> = { cisa: "CISA KEV", vulncheck: "VulnCheck KEV" };

export interface LadderStage {
  name: string;
  reached: boolean;
  evidence: string;
}

/** Five exploitation-evidence stages, weakest to strongest; each uses the earliest event of its kind. */
export function ladderStages(d: CveDetail): LadderStage[] {
  const events = d.events ?? [];
  const pub = earliest(events, "published");
  const disclosedDate = isoDay(pub?.occurred_at ?? d.published);
  const detectable =
    earliest(events, "detection") !== undefined || (d.references ?? []).some((r) => isNucleiReference(r.url));
  const poc = earliest(events, "poc_published");
  const kevName = (d.kev_source !== null && KEV_LABEL[d.kev_source]) || "KEV";
  return [
    {
      name: "Disclosed",
      reached: true,
      evidence: `${disclosedDate || "Date unknown"} · ${pub?.source ?? "NVD"}`,
    },
    { name: "Detectable", reached: detectable, evidence: detectable ? "Nuclei template" : "Not yet" },
    {
      name: "Public exploit",
      reached: d.poc_badge || poc !== undefined,
      evidence: poc
        ? `${poc.source} · ${isoDay(poc.occurred_at)}`
        : d.poc_badge
          ? "Public exploit known"
          : "None found",
    },
    {
      name: "Exploited in the wild",
      reached: d.kev,
      evidence: d.kev ? [kevName, isoDay(d.kev_added)].filter(Boolean).join(" · ") : "No reports",
    },
    {
      name: "Ransomware use",
      reached: d.kev_ransomware === true,
      evidence: d.kev_ransomware === true ? "KEV: known" : "Not known",
    },
  ];
}

export function versionText(v: AffectedVersion): { affected: string; fixed: string } {
  let affected = "all versions";
  if (v.fixed) {
    affected = v.introduced ? `from ${v.introduced} before ${v.fixed}` : `before ${v.fixed}`;
  } else if (v.last_affected) {
    affected =
      v.introduced === v.last_affected
        ? v.last_affected
        : v.introduced
          ? `from ${v.introduced} through ${v.last_affected}`
          : `through ${v.last_affected}`;
  }
  return { affected, fixed: v.fixed ?? "No fix listed" };
}

const HEADLINE_MAX = 140;

/** "Product: first sentence of the summary", decoded once; render it as a plain string. */
export function headline(d: CveDetail): string {
  const text = decodeEntities(d.summary ?? "")
    .replace(/\s+/g, " ")
    .trim();
  const stop = text.indexOf(". ");
  const sentence = text.slice(0, Math.min(stop === -1 ? text.length : stop, HEADLINE_MAX)).trim();
  const product = d.product ? decodeEntities(d.product).trim() : "";
  if (product && sentence) return `${product}: ${sentence}`;
  return product || sentence || d.cve_id;
}
