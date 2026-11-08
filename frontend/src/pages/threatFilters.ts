import type { CveQuery, SevKey, StatusKey, ThreatsSort, AddedKey } from "../lib/types";
import { cleanQ, PAGE_SIZE, parseAdded, parsePage } from "./threatsShared";

export const STATUSES: { key: StatusKey; label: string }[] = [
  { key: "all", label: "All" },
  { key: "exploited", label: "Exploited" },
  { key: "likely", label: "Likely next" },
  { key: "news", label: "In the news" },
  { key: "critical", label: "Critical" },
];
export const SEVERITIES: { key: SevKey; label: string }[] = [
  { key: "low", label: "Low" },
  { key: "med", label: "Medium" },
  { key: "high", label: "High" },
  { key: "crit", label: "Critical" },
];
export const SORTS: { key: ThreatsSort; label: string; hint: string }[] = [
  { key: "newest", label: "Newest", hint: "Most recently published first" },
  { key: "hot", label: "Hot", hint: "Exploited first, then EPSS, CVSS and news" },
  { key: "trending", label: "Trending", hint: "Most news stories in the last 7 days" },
  {
    key: "priority",
    label: "Priority",
    hint: "Added in the last 48h first, then ransomware, EPSS, CVSS, PoC, no patch",
  },
  { key: "due", label: "KEV due", hint: "Soonest CISA deadline first" },
];

export interface ThreatFilters {
  q?: string;
  added: AddedKey;
  status: StatusKey;
  /** Dashboard deep link: hide KEV entries (new critical, not yet exploited). */
  excludeKev: boolean;
  /** Dashboard deep link: KEV deadline within 7 days. */
  due: boolean;
  sev: SevKey[];
  poc: boolean;
  nopatch: boolean;
  sort: ThreatsSort;
  page: number;
}

/** Every URL param the CVEs tab owns (the drawer selection params are not in this list). */
export const FILTER_KEYS = [
  "q",
  "added",
  "status",
  "exclude_kev",
  "due",
  "sev",
  "poc",
  "nopatch",
  "sort",
  "page",
] as const;

/** Pure: reads filters from URL params; every invalid value falls back to its default. */
export function parseThreatFilters(sp: URLSearchParams): ThreatFilters {
  const status = sp.get("status");
  const sort = sp.get("sort");
  const sevParam = new Set((sp.get("sev") ?? "").split(","));
  return {
    q: cleanQ(sp.get("q")),
    added: parseAdded(sp.get("added")),
    status: STATUSES.some((s) => s.key === status) ? (status as StatusKey) : "all",
    excludeKev: sp.get("exclude_kev") === "1",
    due: sp.get("due") === "7d",
    sev: SEVERITIES.map((s) => s.key).filter((k) => sevParam.has(k)),
    poc: sp.get("poc") === "1",
    nopatch: sp.get("nopatch") === "1",
    sort: SORTS.some((s) => s.key === sort) ? (sort as ThreatsSort) : "newest",
    page: parsePage(sp.get("page")),
  };
}

/** Pure: the API query for a filter set. Defaults are omitted. */
export function toCveQuery(f: ThreatFilters): CveQuery {
  const out: CveQuery = { page: f.page, page_size: PAGE_SIZE };
  if (f.q) out.q = f.q;
  if (f.added !== "any") out.added = f.added;
  if (f.status !== "all") out.status = f.status;
  if (f.excludeKev) out.exclude_kev = true;
  if (f.due) out.due = "7d";
  if (f.sev.length) out.sev = f.sev.join(",");
  if (f.poc) out.poc = true;
  if (f.nopatch) out.nopatch = true;
  if (f.sort !== "newest") out.sort = f.sort;
  return out;
}
