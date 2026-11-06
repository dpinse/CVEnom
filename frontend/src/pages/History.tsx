import { useEffect, useMemo, useState } from "react";
import type { KeyboardEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { ApiError, RateLimited } from "../lib/api";
import { useCveSearch } from "../lib/queries";
import { relTime } from "../lib/relTime";
import { useSelection } from "../lib/selection";
import { Text } from "../lib/text";
import type { CveItem, CveQuery, Lane } from "../lib/types";
import { severityOf } from "../components/LaneRow";
import {
  cleanQ,
  DEBOUNCE_MS,
  MAX_Q,
  OutOfRange,
  PAGE_SIZE,
  Pager,
  parsePage,
  useDebouncedQ,
  usePager,
  useUpdateParams,
  validDate,
  type Patch,
} from "./historyShared";
import HistoryStories, { STORY_FILTER_KEYS } from "./HistoryStories";

export { DEBOUNCE_MS, MAX_Q, PAGE_SIZE };

const LANES: Lane[] = ["EXPLOITED", "LIKELY", "LOUD", "FRESH"];
const SOURCES = ["cisa", "vulncheck"] as const;
const SORTS = ["kev_added", "published", "cvss"] as const;
type Sort = (typeof SORTS)[number];
const SORT_LABELS: Record<Sort, string> = {
  kev_added: "Newest KEV listing",
  published: "Newest published",
  cvss: "Highest CVSS",
};
const FILTER_KEYS = ["q", "lane", "source", "min_cvss", "kev", "from", "to", "kev_from", "kev_to", "sort", "page"] as const;
/** Every param either tab owns; switching tabs clears them (the cve / story / country selection survives). */
const TAB_PARAMS = [...new Set<string>([...FILTER_KEYS, ...STORY_FILTER_KEYS, "tab"])];

type Tab = "cves" | "stories";
const TABS: { key: Tab; label: string }[] = [
  { key: "cves", label: "CVEs" },
  { key: "stories", label: "Stories" },
];

function validCvss(s: string | null): number | undefined {
  if (s === null || s.trim() === "") return undefined;
  const n = Number(s);
  return Number.isFinite(n) && n >= 0 && n <= 10 ? n : undefined;
}

/** Pure: reads filters from URL params, silently dropping every invalid value. */
export function parseFilters(sp: URLSearchParams): CveQuery & { page: number } {
  const out: CveQuery & { page: number } = { page: parsePage(sp.get("page")) };
  const q = cleanQ(sp.get("q"));
  if (q) out.q = q;
  const lane = sp.get("lane");
  if (lane && (LANES as string[]).includes(lane)) out.lane = lane as Lane;
  const source = sp.get("source");
  if (source && (SOURCES as readonly string[]).includes(source)) out.source = source as (typeof SOURCES)[number];
  const cvss = validCvss(sp.get("min_cvss"));
  if (cvss !== undefined) out.min_cvss = cvss;
  if (sp.get("kev") === "true") out.kev = true;
  const from = validDate(sp.get("from"));
  if (from) out.from = from;
  const to = validDate(sp.get("to"));
  if (to) out.to = to;
  const kevFrom = validDate(sp.get("kev_from"));
  if (kevFrom) out.kev_from = kevFrom;
  const kevTo = validDate(sp.get("kev_to"));
  if (kevTo) out.kev_to = kevTo;
  const sort = sp.get("sort");
  if (sort && (SORTS as readonly string[]).includes(sort)) out.sort = sort;
  return out;
}

function ResultRow({ item, now, onSelect }: { item: CveItem; now: Date; onSelect: (id: string) => void }) {
  const sev = severityOf(item.cvss);
  return (
    <tr className="srow" role="row" data-sev={sev} data-testid="search-row" onClick={() => onSelect(item.cve_id)}>
      {/* eslint-disable-next-line jsx-a11y/no-interactive-element-to-noninteractive-role -- mobile display:block table semantics */}
      <td role="cell" className="c-id" data-label="CVE">
        <button
          type="button"
          className="sid"
          onClick={(e) => {
            e.stopPropagation();
            onSelect(item.cve_id);
          }}
        >
          {item.cve_id}
        </button>
      </td>
      {/* eslint-disable-next-line jsx-a11y/no-interactive-element-to-noninteractive-role -- mobile display:block table semantics */}
      <td role="cell" data-label="CVSS">
        {item.cvss !== null && <span className={`chip num ${sev}`}>{item.cvss.toFixed(1)}</span>}
      </td>
      {/* eslint-disable-next-line jsx-a11y/no-interactive-element-to-noninteractive-role -- mobile display:block table semantics */}
      <td role="cell" data-label="EPSS">
        {item.epss_percentile !== null && <span className="chip num">p{Math.round(item.epss_percentile * 100)}</span>}
      </td>
      {/* eslint-disable-next-line jsx-a11y/no-interactive-element-to-noninteractive-role -- mobile display:block table semantics */}
      <td role="cell" data-label="KEV">
        {item.kev && (
          <span className="chip kev" title={item.kev_source ?? undefined}>
            KEV{item.kev_added ? ` · ${item.kev_added}` : ""}
          </span>
        )}
      </td>
      {/* eslint-disable-next-line jsx-a11y/no-interactive-element-to-noninteractive-role -- mobile display:block table semantics */}
      <td role="cell" className="c-pub" data-label="Published">
        {relTime(item.published, now)}
      </td>
      {/* eslint-disable-next-line jsx-a11y/no-interactive-element-to-noninteractive-role -- mobile display:block table semantics */}
      <td role="cell" className="c-sum" data-label="Summary">
        <Text className="sum" value={item.summary} />
      </td>
    </tr>
  );
}

function HistoryCves() {
  const [sp, setSp] = useSearchParams();
  const { select } = useSelection();
  const filters = useMemo(() => parseFilters(sp), [sp]);
  const { page } = filters;

  // Sticky: the 422 notice outlives the automatic page reset's refetch; any user edit clears it.
  const [invalidSeen, setInvalidSeen] = useState(false);
  const write = useUpdateParams();
  const update = (patch: Patch, push = false) => {
    setInvalidSeen(false);
    write(patch, push);
  };

  const q = useDebouncedQ(filters.q ?? "", (v) => update({ q: v }));

  // min CVSS: local text so partial input ("7.") survives.
  const [cvssText, setCvssText] = useState(filters.min_cvss === undefined ? "" : String(filters.min_cvss));
  const [seenCvss, setSeenCvss] = useState(filters.min_cvss);
  if (seenCvss !== filters.min_cvss) {
    setSeenCvss(filters.min_cvss);
    if (validCvss(cvssText) !== filters.min_cvss) setCvssText(filters.min_cvss === undefined ? "" : String(filters.min_cvss));
  }

  const params: CveQuery = { ...filters, page_size: PAGE_SIZE };
  const { data, error, isFetching, isPlaceholderData } = useCveSearch(params);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const now = useMemo(() => new Date(), [data]);

  const invalid = error instanceof ApiError && error.status === 422;
  if (invalid && !invalidSeen) setInvalidSeen(true);
  useEffect(() => {
    if (!invalid || page === 1) return;
    setSp(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete("page");
        return next;
      },
      { replace: true },
    );
  }, [invalid, page, setSp]);

  const { countRef, setPage } = usePager(update);
  const dateOrder = filters.from && filters.to && filters.from > filters.to;
  const kevOrder = filters.kev_from && filters.kev_to && filters.kev_from > filters.kev_to;
  const total = data?.total ?? 0;
  const items = data?.items ?? [];
  const first = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const last = Math.min(page * PAGE_SIZE, total);
  // The server's default order follows the backend rule (kev_added only for KEV without a lane), so only a differing choice goes in the URL.
  const defaultSort: Sort = filters.kev && !filters.lane ? "kev_added" : "published";
  const shownSort = (filters.sort as Sort | undefined) ?? defaultSort;

  let errorText: string | null = null;
  if (error || invalidSeen) {
    if (invalid || invalidSeen) errorText = "Some filters aren't valid";
    else if (error instanceof RateLimited) errorText = `Rate limited. Try again in ${error.retryAfter} s.`;
    else errorText = "Couldn't load results. Try again shortly.";
  }

  const clear = () => {
    q.reset();
    setInvalidSeen(false);
    setCvssText("");
    setSp((prev) => {
      const next = new URLSearchParams(prev);
      for (const k of FILTER_KEYS) next.delete(k);
      return next;
    });
  };

  const outOfRange = data !== undefined && items.length === 0 && total > 0 && page > 1;

  return (
    <>
      <form className="sfilters" role="search" onSubmit={(e) => e.preventDefault()}>
        <label className="f f-q">
          <span>Search CVEs</span>
          <input type="search" maxLength={MAX_Q} value={q.qText} onChange={(e) => q.onChange(e.target.value)} autoComplete="off" />
        </label>
        <label className="f">
          <span>Lane</span>
          <select value={filters.lane ?? ""} onChange={(e) => update({ lane: e.target.value }, true)}>
            <option value="">All lanes</option>
            {LANES.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
        </label>
        <label className="f">
          <span>Source</span>
          <select value={filters.source ?? ""} onChange={(e) => update({ source: e.target.value }, true)}>
            <option value="">Any source</option>
            <option value="cisa">CISA</option>
            <option value="vulncheck">VulnCheck</option>
          </select>
        </label>
        <label className="f">
          <span>Min CVSS</span>
          <input
            type="number"
            step={0.1}
            min={0}
            max={10}
            value={cvssText}
            onChange={(e) => {
              setCvssText(e.target.value);
              const n = validCvss(e.target.value);
              update({ min_cvss: n === undefined ? undefined : String(n) });
            }}
          />
        </label>
        <label className="f">
          <span>From</span>
          <input type="date" value={filters.from ?? ""} onChange={(e) => update({ from: e.target.value })} />
        </label>
        <label className="f">
          <span>To</span>
          <input type="date" value={filters.to ?? ""} onChange={(e) => update({ to: e.target.value })} />
        </label>
        <label className="f">
          <span>KEV added from</span>
          <input type="date" value={filters.kev_from ?? ""} onChange={(e) => update({ kev_from: e.target.value })} />
        </label>
        <label className="f">
          <span>KEV added to</span>
          <input type="date" value={filters.kev_to ?? ""} onChange={(e) => update({ kev_to: e.target.value })} />
        </label>
        <label className="f">
          <span>Sort</span>
          <select
            value={shownSort}
            onChange={(e) => update({ sort: e.target.value === defaultSort ? undefined : e.target.value }, true)}
          >
            {SORTS.map((s) => (
              <option key={s} value={s}>
                {SORT_LABELS[s]}
              </option>
            ))}
          </select>
        </label>
        <label className="f f-check">
          <input
            type="checkbox"
            checked={filters.kev === true}
            onChange={(e) => update({ kev: e.target.checked ? "true" : undefined }, true)}
          />
          <span>KEV only</span>
        </label>
        <button type="button" className="sclear" onClick={clear}>
          Clear filters
        </button>
      </form>
      {dateOrder && (
        <p className="shint" role="note">
          The From date is after the To date, so nothing can match.
        </p>
      )}
      {kevOrder && (
        <p className="shint" role="note">
          The KEV added from date is after the KEV added to date, so nothing can match.
        </p>
      )}
      {errorText && (
        <p className="serror" role="alert">
          {errorText}
        </p>
      )}
      <p className="scount" aria-live="polite" tabIndex={-1} ref={countRef}>
        {data ? (total === 0 ? "0 results" : outOfRange ? "" : `Showing ${first}–${last} of ${total}`) : isFetching ? "Loading…" : ""}
      </p>
      {data && items.length === 0 && !errorText && (outOfRange ? <OutOfRange /> : <p className="sempty">No CVEs match these filters</p>)}
      {items.length > 0 && (
        <div className="stable-wrap" aria-busy={isPlaceholderData}>
          <table className="stable" role="table">
            {/* eslint-disable-next-line jsx-a11y/no-redundant-roles -- mobile display:block table semantics */}
            <thead role="rowgroup">
              <tr role="row">
                <th scope="col" role="columnheader">CVE</th>
                <th scope="col" role="columnheader">CVSS</th>
                <th scope="col" role="columnheader">EPSS</th>
                <th scope="col" role="columnheader">KEV</th>
                <th scope="col" role="columnheader">Published</th>
                <th scope="col" role="columnheader">Summary</th>
              </tr>
            </thead>
            {/* eslint-disable-next-line jsx-a11y/no-redundant-roles -- mobile display:block table semantics */}
            <tbody role="rowgroup">
              {items.map((it) => (
                <ResultRow key={it.cve_id} item={it} now={now} onSelect={(id) => select({ kind: "cve", id })} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Pager page={page} total={total} setPage={setPage} />
    </>
  );
}

export default function History() {
  const [sp, setSp] = useSearchParams();
  const tab: Tab = sp.get("tab") === "stories" ? "stories" : "cves";

  const choose = (next: Tab) => {
    if (next === tab) return;
    setSp((prev) => {
      const out = new URLSearchParams(prev);
      for (const k of TAB_PARAMS) out.delete(k);
      if (next === "stories") out.set("tab", "stories");
      return out;
    });
  };
  const onKey = (e: KeyboardEvent, i: number) => {
    if (e.key === "Home" || e.key === "End") {
      e.preventDefault();
      choose(TABS[e.key === "Home" ? 0 : TABS.length - 1].key);
    } else if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      e.preventDefault();
      const to = TABS[(i + (e.key === "ArrowRight" ? 1 : TABS.length - 1)) % TABS.length].key;
      choose(to);
      document.getElementById(`htab-${to}`)?.focus();
    }
  };

  return (
    <section className="page gutter search">
      <h1>History</h1>
      <div className="htabs" role="tablist" aria-label="History">
        {TABS.map((t, i) => (
          <button
            key={t.key}
            type="button"
            role="tab"
            id={`htab-${t.key}`}
            aria-selected={tab === t.key}
            aria-controls="htab-panel"
            tabIndex={tab === t.key ? 0 : -1}
            className="htab"
            onClick={() => choose(t.key)}
            onKeyDown={(e) => onKey(e, i)}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div id="htab-panel" role="tabpanel" aria-labelledby={`htab-${tab}`} className="htab-panel">
        {tab === "stories" ? <HistoryStories /> : <HistoryCves />}
      </div>
    </section>
  );
}
