import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { ApiError, RateLimited } from "../lib/api";
import { useStorySearch } from "../lib/queries";
import { relTime } from "../lib/relTime";
import { useSelection } from "../lib/selection";
import { Text } from "../lib/text";
import { useAuth } from "../lib/useAuth";
import { isRansomwareSource, RansomwareCredit } from "../components/RansomwareCredit";
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
  AddedSelect,
  parseAdded,
  SkipToPagination,
} from "./threatsShared";

export const STORY_FILTER_KEYS = ["q", "source", "added", "page"] as const;
const MAX_SOURCE = 64;

/** Pure: reads the Stories filters from URL params, silently dropping every invalid value. */
export function parseStoryFilters(sp: URLSearchParams): StoryQuery & { page: number } {
  const out: StoryQuery & { page: number } = { page: parsePage(sp.get("page")) };
  const q = cleanQ(sp.get("q"));
  if (q) out.q = q;
  const source = sp.get("source")?.trim().slice(0, MAX_SOURCE).trim();
  if (source) out.source = source;
  const added = parseAdded(sp.get("added"));
  if (added !== "any") out.added = added;
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
    <li className="hrow" data-testid="news-story">
      <button type="button" className="hrow-open" onClick={() => onOpen(story.url)}>
        <Text className="hrow-title" value={story.title} />
        <span className="hrow-src">
          <Text className="hrow-from" value={story.source} /> · {relTime(story.published, now)}
        </span>
      </button>
      {isRansomwareSource(story.source) && <RansomwareCredit className="hrow-credit" />}
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

export type StoryKind = "news" | "ransomware";

/** The Ransomware tab: ransomware.live is members-only, so guests get a one-line notice instead of an empty list. */
export function ThreatsRansomware() {
  const { user, ready } = useAuth();
  if (!ready) return null;
  if (!user)
    return (
      <p className="sempty" data-testid="ransomware-signin">
        Sign in to see ransomware activity. <RansomwareCredit />
      </p>
    );
  return <ThreatsNews kind="ransomware" />;
}

export default function ThreatsNews({ kind = "news" }: { kind?: StoryKind } = {}) {
  const ransom = kind === "ransomware";
  const [sp, setSp] = useSearchParams();
  const { select } = useSelection();
  const filters = useMemo(() => parseStoryFilters(sp), [sp]);
  const { page } = filters;
  const update = useUpdateParams();
  const q = useDebouncedQ(filters.q ?? "", (v) => update({ q: v }));
  const { countRef, setPage } = usePager(update);

  const { data, error, isFetching, isPlaceholderData } = useStorySearch({
    ...filters,
    ...(ransom ? { source: undefined } : {}),
    kind,
    page_size: PAGE_SIZE,
  });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const now = useMemo(() => new Date(), [data]);

  const total = data?.total ?? 0;
  const items = data?.items ?? [];
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
      <form className="tfilters" role="search" onSubmit={(e) => e.preventDefault()}>
        <div className="frow">
          <label className="f-q">
            <span className="sr-only">{ransom ? "Search ransomware activity" : "Search stories"}</span>
            <input
              type="search"
              placeholder={ransom ? "Search victims and groups" : "Search stories"}
              maxLength={MAX_Q}
              value={q.qText}
              onChange={(e) => q.onChange(e.target.value)}
              autoComplete="off"
            />
          </label>
          <AddedSelect
            value={filters.added ?? "any"}
            onChange={(v) => update({ added: v === "any" ? undefined : v }, true)}
          />
          {!ransom && (
            <label className="f-src">
              <span className="sr-only">Story source</span>
              <input
                type="text"
                placeholder="Source"
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
          )}
          <button type="button" className="sclear" onClick={clear}>
            Clear filters
          </button>
          <SkipToPagination />
        </div>
      </form>
      {errorText && (
        <p className="serror" role="alert">
          {errorText}
        </p>
      )}
      {data &&
        items.length === 0 &&
        !errorText &&
        (outOfRange ? (
          <OutOfRange />
        ) : (
          <p className="sempty">
            {ransom ? "No ransomware activity matches these filters" : "No stories match these filters"}
          </p>
        ))}
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
      {ransom && (
        <p className="shint">
          <RansomwareCredit />
        </p>
      )}
      <p className="scount" aria-live="polite" tabIndex={-1} ref={countRef}>
        {data
          ? outOfRange
            ? `${total} stories in total`
            : `${total} ${total === 1 ? "story" : "stories"}`
          : isFetching
            ? "Loading…"
            : ""}
      </p>
      <Pager page={page} total={total} setPage={setPage} />
    </>
  );
}
