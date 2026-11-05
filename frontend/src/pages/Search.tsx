/* Explicit table roles are deliberate: the mobile stylesheet sets display:block, which drops native table semantics in some browsers. */
/* eslint-disable jsx-a11y/no-redundant-roles, jsx-a11y/no-interactive-element-to-noninteractive-role */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ApiError, RateLimited } from "../lib/api";
import { useCveSearch } from "../lib/queries";
import { relTime } from "../lib/relTime";
import { useSelection } from "../lib/selection";
import { Text } from "../lib/text";
import type { CveItem, CveQuery, Lane } from "../lib/types";
import { severityOf } from "../components/LaneRow";

export const PAGE_SIZE = 50;
export const MAX_Q = 200;
export const DEBOUNCE_MS = 300;
const LANES: Lane[] = ["EXPLOITED", "LIKELY", "LOUD", "FRESH"];
const SOURCES = ["cisa", "vulncheck"] as const;
const FILTER_KEYS = ["q", "lane", "source", "min_cvss", "kev", "from", "to", "page"] as const;

function validDate(s: string | null): string | undefined {
  if (s === null || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return undefined;
  const [y, m, d] = s.split("-").map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  const ok = dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
  return ok ? s : undefined;
}

function validCvss(s: string | null): number | undefined {
  if (s === null || s.trim() === "") return undefined;
  const n = Number(s);
  return Number.isFinite(n) && n >= 0 && n <= 10 ? n : undefined;
}

/** Pure: reads filters from URL params, silently dropping every invalid value. */
export function parseFilters(sp: URLSearchParams): CveQuery & { page: number } {
  const out: CveQuery & { page: number } = { page: 1 };
  const q = sp.get("q");
  const tq = q?.trim().slice(0, MAX_Q).trim();
  if (tq) out.q = tq;
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
  const pageRaw = sp.get("page");
  if (pageRaw !== null && /^\d+$/.test(pageRaw)) {
    const p = Number(pageRaw);
    if (p >= 1 && p <= 10000) out.page = p;
  }
  return out;
}

type Patch = Partial<Record<(typeof FILTER_KEYS)[number], string | undefined>>;

function ResultRow({ item, now, onSelect }: { item: CveItem; now: Date; onSelect: (id: string) => void }) {
  const sev = severityOf(item.cvss);
  return (
    <tr className="srow" role="row" data-sev={sev} data-testid="search-row" onClick={() => onSelect(item.cve_id)}>
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
      <td role="cell" data-label="CVSS">
        {item.cvss !== null && <span className={`chip num ${sev}`}>{item.cvss.toFixed(1)}</span>}
      </td>
      <td role="cell" data-label="EPSS">
        {item.epss_percentile !== null && <span className="chip num">p{Math.round(item.epss_percentile * 100)}</span>}
      </td>
      <td role="cell" data-label="KEV">
        {item.kev && (
          <span className="chip kev" title={item.kev_source ?? undefined}>
            KEV{item.kev_added ? ` · ${item.kev_added}` : ""}
          </span>
        )}
      </td>
      <td role="cell" className="c-pub" data-label="Published">
        {relTime(item.published, now)}
      </td>
      <td role="cell" className="c-sum" data-label="Summary">
        <Text className="sum" value={item.summary} />
      </td>
    </tr>
  );
}

export default function Search() {
  const [sp, setSp] = useSearchParams();
  const { select } = useSelection();
  const filters = useMemo(() => parseFilters(sp), [sp]);
  const { page } = filters;

  // Sticky: the 422 notice outlives the automatic page reset's refetch; any user edit clears it.
  const [invalidSeen, setInvalidSeen] = useState(false);

  const update = useCallback(
    (patch: Patch, push = false) => {
      setInvalidSeen(false);
      setSp(
        (prev) => {
          const next = new URLSearchParams(prev); // keeps cve / story
          for (const [k, v] of Object.entries(patch)) {
            if (v === undefined || v === "") next.delete(k);
            else next.set(k, v);
          }
          if (!("page" in patch)) next.delete("page");
          return next;
        },
        push ? undefined : { replace: true },
      );
    },
    [setSp],
  );

  // q: local text, debounced into the URL (replace).
  const [qText, setQText] = useState(filters.q ?? "");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const cancel = () => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
  };
  useEffect(() => cancel, []);
  const urlQ = filters.q ?? "";
  const [seenQ, setSeenQ] = useState(urlQ);
  const [lastWritten, setLastWritten] = useState(urlQ);
  const [epoch, setEpoch] = useState(0);
  const epochRef = useRef(0);
  useEffect(() => {
    epochRef.current = epoch;
    cancel(); // a stale debounce must not fire after an external URL change
  }, [epoch]);
  if (seenQ !== urlQ) {
    setSeenQ(urlQ);
    if (urlQ !== lastWritten) {
      // changed externally (back/forward, link): the URL wins
      setLastWritten(urlQ);
      setQText(urlQ);
      setEpoch((e) => e + 1);
    }
  }
  const onQ = (v: string) => {
    const value = v.slice(0, MAX_Q);
    setQText(value);
    cancel();
    const mine = epochRef.current;
    timer.current = setTimeout(() => {
      timer.current = null;
      if (mine !== epochRef.current) return;
      const written = value.trim();
      setLastWritten(written);
      update({ q: written });
    }, DEBOUNCE_MS);
  };

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

  const countRef = useRef<HTMLParagraphElement>(null);
  const setPage = (p: number) => {
    update({ page: p <= 1 ? undefined : String(p) }, true);
    const el = countRef.current;
    if (el) {
      el.focus({ preventScroll: true });
      const reduce = typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      el.scrollIntoView?.({ behavior: reduce ? "auto" : "smooth", block: "start" });
    }
  };
  const dateOrder = filters.from && filters.to && filters.from > filters.to;
  const total = data?.total ?? 0;
  const items = data?.items ?? [];
  const first = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const last = Math.min(page * PAGE_SIZE, total);

  let errorText: string | null = null;
  if (error || invalidSeen) {
    if (invalid || invalidSeen) errorText = "Some filters aren't valid";
    else if (error instanceof RateLimited) errorText = `Rate limited. Try again in ${error.retryAfter} s.`;
    else errorText = "Couldn't load results. Try again shortly.";
  }

  const clear = () => {
    cancel();
    setInvalidSeen(false);
    setLastWritten("");
    setQText("");
    setCvssText("");
    setSp((prev) => {
      const next = new URLSearchParams(prev);
      for (const k of FILTER_KEYS) next.delete(k);
      return next;
    });
  };

  return (
    <section className="page gutter search">
      <h1>Search</h1>
      <form className="sfilters" role="search" onSubmit={(e) => e.preventDefault()}>
        <label className="f f-q">
          <span>Search CVEs</span>
          <input type="search" maxLength={MAX_Q} value={qText} onChange={(e) => onQ(e.target.value)} autoComplete="off" />
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
      {errorText && (
        <p className="serror" role="alert">
          {errorText}
        </p>
      )}
      <p className="scount" aria-live="polite" tabIndex={-1} ref={countRef}>
        {data ? (total === 0 ? "0 results" : `Showing ${first}–${last} of ${total}`) : isFetching ? "Loading…" : ""}
      </p>
      {data && items.length === 0 && !errorText && <p className="sempty">No CVEs match these filters</p>}
      {items.length > 0 && (
        <div className="stable-wrap" aria-busy={isPlaceholderData}>
          <table className="stable" role="table">
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
            <tbody role="rowgroup">
              {items.map((it) => (
                <ResultRow key={it.cve_id} item={it} now={now} onSelect={(id) => select({ kind: "cve", id })} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      <nav className="spager" aria-label="Pagination">
        <button type="button" disabled={page <= 1} onClick={() => setPage(page - 1)}>
          Previous
        </button>
        <span className="num">Page {page}</span>
        <button type="button" disabled={page * PAGE_SIZE >= total} onClick={() => setPage(page + 1)}>
          Next
        </button>
      </nav>
    </section>
  );
}
