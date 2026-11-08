import { useEffect, useMemo, useState } from "react";
import type { KeyboardEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ApiError, RateLimited } from "../lib/api";
import { useCveSearch } from "../lib/queries";
import { relTime } from "../lib/relTime";
import { Text } from "../lib/text";
import type { CveItem } from "../lib/types";
import { severityOf, type Sev } from "../components/LaneRow";
import {
  FILTER_KEYS,
  parseThreatFilters,
  SEVERITIES,
  SORTS,
  STATUSES,
  toCveQuery,
  type ThreatFilters,
} from "./threatFilters";
import {
  AddedSelect,
  DEBOUNCE_MS,
  MAX_Q,
  OutOfRange,
  PAGE_SIZE,
  Pager,
  SkipToPagination,
  useDebouncedQ,
  usePager,
  useUpdateParams,
  type Patch,
} from "./threatsShared";
import ThreatsNews, { STORY_FILTER_KEYS, ThreatsRansomware } from "./ThreatsNews";

export { DEBOUNCE_MS, MAX_Q, PAGE_SIZE, parseThreatFilters, toCveQuery };
export type { ThreatFilters };

/** Every param either tab owns; switching tabs clears them (the cve / story / country selection survives). */
const TAB_PARAMS = [...new Set<string>([...FILTER_KEYS, ...STORY_FILTER_KEYS, "tab"])];

type Tab = "cves" | "news" | "ransomware";
const TABS: { key: Tab; label: string }[] = [
  { key: "cves", label: "CVEs" },
  { key: "news", label: "News" },
  { key: "ransomware", label: "Ransomware" },
];

const SEV_NAME: Record<Sev, string> = { crit: "Critical", high: "High", med: "Medium", low: "Low" };

function ResultRow({ item, filters, now }: { item: CveItem; filters: ThreatFilters; now: Date }) {
  const navigate = useNavigate();
  const scored = item.cvss !== null;
  const sev = severityOf(item.cvss);
  const addedAt = filters.status === "exploited" && item.kev_added ? item.kev_added : item.published;
  const to = `/threats/${item.cve_id}`;
  return (
    <tr
      className="srow"
      data-testid="search-row"
      onClick={(e) => {
        if (!(e.target as HTMLElement).closest("a")) navigate(to);
      }}
    >
      <td>
        <span className="sevpill" data-sev={scored ? sev : "none"}>
          <i aria-hidden="true" />
          <span className="score">{item.cvss === null ? "–" : item.cvss.toFixed(1)}</span>
          <span className="sevname">{scored ? SEV_NAME[sev] : "Unscored"}</span>
        </span>
      </td>
      <td>
        <Link className="sid" to={to}>
          {item.cve_id}
        </Link>
      </td>
      <td className="c-issue">
        {item.product && <Text className="prod" value={item.product} />}
        <Text className="sum" value={item.summary} />
      </td>
      <td>
        {item.kev && <span className="tag kev">KEV</span>}
        {item.poc_badge && <span className="tag poc">PoC</span>}
        {item.patch_available === false && <span className="tag">no patch</span>}
        {item.recent_story_count > 0 && <span className="tag">news ×{item.recent_story_count}</span>}
      </td>
      <td className="num">{item.epss_percentile !== null && `p${Math.round(item.epss_percentile * 100)}`}</td>
      <td className="num c-added" title={addedAt ?? undefined}>
        {relTime(addedAt, now)}
      </td>
    </tr>
  );
}

function ThreatsCves() {
  const [sp, setSp] = useSearchParams();
  const filters = useMemo(() => parseThreatFilters(sp), [sp]);
  const { page } = filters;

  // Sticky: the 422 notice outlives the automatic page reset's refetch; any user edit clears it.
  const [invalidSeen, setInvalidSeen] = useState(false);
  const write = useUpdateParams();
  const update = (patch: Patch, push = false) => {
    setInvalidSeen(false);
    write(patch, push);
  };
  const [more, setMore] = useState(filters.poc || filters.nopatch);

  const q = useDebouncedQ(filters.q ?? "", (v) => update({ q: v }));
  const { data, error, isFetching, isPlaceholderData } = useCveSearch(toCveQuery(filters));
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
  const total = data?.total ?? 0;
  const items = data?.items ?? [];
  const outOfRange = data !== undefined && items.length === 0 && total > 0 && page > 1;
  const sortHint = SORTS.find((s) => s.key === filters.sort)?.hint;

  let errorText: string | null = null;
  if (error || invalidSeen) {
    if (invalid || invalidSeen) errorText = "Some filters aren't valid";
    else if (error instanceof RateLimited) errorText = `Rate limited. Try again in ${error.retryAfter} s.`;
    else errorText = "Couldn't load results. Try again shortly.";
  }

  const toggleSev = (key: string) => {
    const on = new Set<string>(filters.sev);
    if (on.has(key)) on.delete(key);
    else on.add(key);
    update(
      {
        sev:
          SEVERITIES.map((s) => s.key)
            .filter((k) => on.has(k))
            .join(",") || undefined,
      },
      true,
    );
  };

  const clear = () => {
    q.reset();
    setInvalidSeen(false);
    setSp((prev) => {
      const next = new URLSearchParams(prev);
      for (const k of FILTER_KEYS) next.delete(k);
      return next;
    });
  };

  const active: { label: string; remove: Patch }[] = [];
  if (filters.excludeKev) active.push({ label: "Not in KEV", remove: { exclude_kev: undefined } });
  if (filters.due) active.push({ label: "KEV due within 7 days", remove: { due: undefined } });

  const countText = data
    ? outOfRange
      ? `${total} CVEs in total`
      : `${total} ${total === 1 ? "CVE" : "CVEs"}`
    : isFetching
      ? "Loading…"
      : "";

  return (
    <>
      <form className="tfilters" role="search" onSubmit={(e) => e.preventDefault()}>
        <div className="frow">
          <label className="f-q">
            <span className="sr-only">Search CVEs</span>
            <input
              type="search"
              placeholder="Search CVE, vendor or product"
              maxLength={MAX_Q}
              value={q.qText}
              onChange={(e) => q.onChange(e.target.value)}
              autoComplete="off"
            />
          </label>
          <AddedSelect value={filters.added} onChange={(v) => update({ added: v === "any" ? undefined : v }, true)} />
          <div className="sevchips" role="group" aria-label="Severity">
            {SEVERITIES.map((s) => (
              <button
                key={s.key}
                type="button"
                className="sev-chip"
                data-sev={s.key}
                aria-pressed={filters.sev.includes(s.key)}
                onClick={() => toggleSev(s.key)}
              >
                <i aria-hidden="true" />
                {s.label}
              </button>
            ))}
          </div>
          <div className="sortbox">
            <label>
              <span className="sr-only">Sort</span>
              <select
                value={filters.sort}
                onChange={(e) => update({ sort: e.target.value === "newest" ? undefined : e.target.value }, true)}
              >
                {SORTS.map((s) => (
                  <option key={s.key} value={s.key}>
                    {s.label}
                  </option>
                ))}
              </select>
            </label>
            <span className="sort-desc">{sortHint}</span>
          </div>
        </div>
        <div className="frow">
          <div className="statuschips" role="group" aria-label="Status">
            {STATUSES.map((s) => (
              <button
                key={s.key}
                type="button"
                className="chip-btn"
                aria-pressed={filters.status === s.key}
                onClick={() => update({ status: s.key === "all" ? undefined : s.key }, true)}
              >
                {s.label}
              </button>
            ))}
          </div>
          <button
            type="button"
            className="chip-btn"
            aria-expanded={more}
            aria-controls="more-filters"
            onClick={() => setMore((m) => !m)}
          >
            All filters
          </button>
          {more && (
            <span className="morefilters" id="more-filters">
              <button
                type="button"
                className="chip-btn"
                aria-pressed={filters.poc}
                onClick={() => update({ poc: filters.poc ? undefined : "1" }, true)}
              >
                Public exploit
              </button>
              <button
                type="button"
                className="chip-btn"
                aria-pressed={filters.nopatch}
                onClick={() => update({ nopatch: filters.nopatch ? undefined : "1" }, true)}
              >
                No patch
              </button>
            </span>
          )}
          <button type="button" className="sclear" onClick={clear}>
            Clear filters
          </button>
          <SkipToPagination />
        </div>
        {active.length > 0 && (
          <ul className="active-filters" aria-label="Active filters">
            {active.map((a) => (
              <li key={a.label}>
                <button
                  type="button"
                  className="achip"
                  aria-label={`Remove filter: ${a.label}`}
                  onClick={() => update(a.remove, true)}
                >
                  {a.label} <span aria-hidden="true">×</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </form>
      {data?.exact_match_filtered_out && (
        <p className="shint" role="note">
          Showing the exact match for {filters.q}. It is outside your current filters.
        </p>
      )}
      {errorText && (
        <p className="serror" role="alert">
          {errorText}
        </p>
      )}
      {data &&
        items.length === 0 &&
        !errorText &&
        (outOfRange ? <OutOfRange /> : <p className="sempty">No CVEs match these filters</p>)}
      {items.length > 0 && (
        <div className="tbl-wrap" aria-busy={isPlaceholderData}>
          <table className="ttable">
            <thead>
              <tr>
                <th scope="col">Severity</th>
                <th scope="col">CVE</th>
                <th scope="col">Product and issue</th>
                <th scope="col">Signals</th>
                <th scope="col">EPSS</th>
                <th scope="col">{filters.poc || filters.status === "news" ? "Published" : "Added"}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((it) => (
                <ResultRow key={it.cve_id} item={it} filters={filters} now={now} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="scount" aria-live="polite" tabIndex={-1} ref={countRef}>
        {countText}
      </p>
      <Pager page={page} total={total} setPage={setPage} />
    </>
  );
}

export default function Threats() {
  const [sp, setSp] = useSearchParams();
  const tabParam = sp.get("tab");
  const tab: Tab = tabParam === "news" || tabParam === "ransomware" ? tabParam : "cves";

  const choose = (next: Tab) => {
    if (next === tab) return;
    setSp((prev) => {
      const out = new URLSearchParams(prev);
      for (const k of TAB_PARAMS) out.delete(k);
      if (next !== "cves") out.set("tab", next);
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
      <h1>Threats</h1>
      <p className="tsub">
        Every CVE, news story and ransomware report CVEnom has recorded. Filter by when it was added, severity and
        status.
      </p>
      <div className="htabs" role="tablist" aria-label="Threats">
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
        {tab === "news" ? <ThreatsNews /> : tab === "ransomware" ? <ThreatsRansomware /> : <ThreatsCves />}
      </div>
    </section>
  );
}
