import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { ApiError, RateLimited } from "../lib/api";
import { useStorySearch } from "../lib/queries";
import { relTime } from "../lib/relTime";
import { useSelection } from "../lib/selection";
import { Text } from "../lib/text";
import type { StoryItem, StoryQuery } from "../lib/types";
import {
  cleanQ,
  MAX_Q,
  OutOfRange,
  PAGE_SIZE,
  Pager,
  parsePage,
  useDebouncedQ,
  usePager,
  useUpdateParams,
  validDate,
} from "./threatsShared";

export const STORY_FILTER_KEYS = ["q", "source", "from", "to", "page"] as const;
const MAX_SOURCE = 64;

/** Pure: reads the Stories filters from URL params, silently dropping every invalid value. */
export function parseStoryFilters(sp: URLSearchParams): StoryQuery & { page: number } {
  const out: StoryQuery & { page: number } = { page: parsePage(sp.get("page")) };
  const q = cleanQ(sp.get("q"));
  if (q) out.q = q;
  const source = sp.get("source")?.trim().slice(0, MAX_SOURCE).trim();
  if (source) out.source = source;
  const from = validDate(sp.get("from"));
  if (from) out.from = from;
  const to = validDate(sp.get("to"));
  if (to) out.to = to;
  return out;
}

function Row({
  story,
  now,
  onOpen,
  onCve,
}: {
  story: StoryItem;
  now: Date;
  onOpen: (url: string) => void;
  onCve: (id: string) => void;
}) {
  const ids = story.cve_ids ?? [];
  return (
    <li className="hrow" data-testid="history-story">
      <button type="button" className="hrow-open" onClick={() => onOpen(story.url)}>
        <Text className="hrow-title" value={story.title} />
        <span className="hrow-src">
          <Text className="hrow-from" value={story.source} /> · {relTime(story.published, now)}
        </span>
      </button>
      {ids.length > 0 && (
        <span className="chips">
          {ids.map((id) => (
            <button key={id} type="button" className="chip linked" onClick={() => onCve(id)}>
              {id}
            </button>
          ))}
        </span>
      )}
    </li>
  );
}

export default function HistoryStories() {
  const [sp, setSp] = useSearchParams();
  const { select } = useSelection();
  const filters = useMemo(() => parseStoryFilters(sp), [sp]);
  const { page } = filters;
  const update = useUpdateParams();
  const q = useDebouncedQ(filters.q ?? "", (v) => update({ q: v }));
  const { countRef, setPage } = usePager(update);

  const { data, error, isFetching, isPlaceholderData } = useStorySearch({ ...filters, page_size: PAGE_SIZE });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const now = useMemo(() => new Date(), [data]);

  const total = data?.total ?? 0;
  const items = data?.items ?? [];
  const first = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const last = Math.min(page * PAGE_SIZE, total);
  const dateOrder = filters.from && filters.to && filters.from > filters.to;
  const outOfRange = data !== undefined && items.length === 0 && total > 0 && page > 1;

  let errorText: string | null = null;
  if (error) {
    if (error instanceof ApiError && error.status === 422) errorText = "Some filters aren't valid";
    else if (error instanceof RateLimited) errorText = `Rate limited. Try again in ${error.retryAfter} s.`;
    else errorText = "Couldn't load results. Try again shortly.";
  }

  // An unchanged value must not write: update() resets the page.
  const commitSource = (v: string) => {
    const t = v.trim();
    if (t !== (filters.source ?? "")) update({ source: t });
  };

  const clear = () => {
    q.reset();
    setSp((prev) => {
      const next = new URLSearchParams(prev);
      for (const k of STORY_FILTER_KEYS) next.delete(k);
      return next;
    });
  };

  return (
    <>
      <form className="sfilters" role="search" onSubmit={(e) => e.preventDefault()}>
        <label className="f f-q">
          <span>Search stories</span>
          <input
            type="search"
            maxLength={MAX_Q}
            value={q.qText}
            onChange={(e) => q.onChange(e.target.value)}
            autoComplete="off"
          />
        </label>
        <label className="f">
          <span>Story source</span>
          <input
            type="text"
            maxLength={MAX_SOURCE}
            defaultValue={filters.source ?? ""}
            key={filters.source ?? ""}
            onBlur={(e) => commitSource(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") commitSource(e.currentTarget.value);
            }}
            autoComplete="off"
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
        {data
          ? total === 0
            ? "0 results"
            : outOfRange
              ? `${total} results in total`
              : `Showing ${first}–${last} of ${total}`
          : isFetching
            ? "Loading…"
            : ""}
      </p>
      {data &&
        items.length === 0 &&
        !errorText &&
        (outOfRange ? <OutOfRange /> : <p className="sempty">No stories match these filters</p>)}
      {items.length > 0 && (
        <ul className="hlist" aria-busy={isPlaceholderData}>
          {items.map((s, i) => (
            <Row
              key={`${s.url}#${i}`}
              story={s}
              now={now}
              onOpen={(url) => select({ kind: "story", url })}
              onCve={(id) => select({ kind: "cve", id })}
            />
          ))}
        </ul>
      )}
      <Pager page={page} total={total} setPage={setPage} />
    </>
  );
}
