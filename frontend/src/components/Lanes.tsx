import { Link } from "react-router-dom";
import { RateLimited } from "../lib/api";
import { DEFAULT_RANGE, RANGE_LABEL, type RangeKey } from "../lib/range";
import { errorRefetchMs, nextRetryAt, pollsAfterError, useLanes, useLoudStories } from "../lib/queries";
import { useSelection, type Selection } from "../lib/selection";
import type { CveItem, Lane, LanesOut, LoudStory } from "../lib/types";
import { useNow } from "../lib/useNow";
import { LaneRow, StoryRow } from "./LaneRow";

/** Alert bar still scans a deeper slice than the lanes show. */
export const LANE_CAP = 100;
/** Rows shown per lane on the dashboard. */
export const LANE_ROWS = 5;

interface LaneDef {
  key: Lane;
  k: "exploited" | "likely" | "loud" | "fresh";
  title: string;
  sub: string;
}
export const DEFS: LaneDef[] = [
  { key: "EXPLOITED", k: "exploited", title: "Exploited now", sub: "Added to CISA KEV or VulnCheck KEV" },
  { key: "LIKELY", k: "likely", title: "Likely next", sub: "Not yet exploited, EPSS ≥ p95" },
  { key: "LOUD", k: "loud", title: "Loud now", sub: "CVEs the news is covering" },
  { key: "FRESH", k: "fresh", title: "Fresh criticals", sub: "New, CVSS ≥ 9, not yet exploited" },
];

const ADDED: Record<RangeKey, string> = { "24h": "day", "7d": "week", "14d": "14d", "30d": "month" };
const STATUS: Record<LaneDef["k"], string> = {
  exploited: "status=exploited",
  likely: "status=likely",
  loud: "status=news",
  fresh: "status=critical&exclude_kev=1",
};
/** Dashboard deep link into Threats: lane -> status, range -> added. */
export function threatsHref(k: LaneDef["k"], range: RangeKey): string {
  // Likely is "published within likely_window_days (30)" whatever the range, so it always
  // links to added=month; the other lanes follow the range.
  const added = k === "likely" ? "month" : ADDED[range];
  return `/threats?${STATUS[k]}&added=${added}`;
}

/** Stories newest first, minus those whose CVEs are all already shown as LOUD CVE rows. */
export function loudStoriesFor(loud: CveItem[], stories: LoudStory[]): LoudStory[] {
  const shown = new Set(loud.map((c) => c.cve_id));
  return stories
    .filter((s) => !(s.cve_ids?.length > 0 && s.cve_ids.every((id) => shown.has(id))))
    .sort((a, b) => (Date.parse(b.published) || 0) - (Date.parse(a.published) || 0));
}

interface ViewProps {
  lanes?: Partial<LanesOut>;
  stories?: LoudStory[];
  loading?: boolean;
  error?: unknown;
  /** When the errored lanes query will next be refetched (epoch ms); defaults to a full interval. */
  retryAt?: number;
  now?: Date;
  range?: RangeKey;
  onSelect: (s: Selection) => void;
}

function Skeleton() {
  return (
    <div className="lane-skeleton" aria-hidden="true">
      {[0, 1, 2].map((i) => (
        <div key={i} className="lane-skeleton-row" />
      ))}
    </div>
  );
}

export function LanesView({
  lanes,
  stories = [],
  loading,
  error,
  retryAt,
  now,
  range = DEFAULT_RANGE,
  onSelect,
}: ViewProps) {
  const clock = now ?? new Date();
  const rate = error instanceof RateLimited ? error : null;
  // The same schedule the query polls on (errorRefetchInterval), so the countdown is the truth.
  const secs = Math.max(
    0,
    Math.ceil((retryAt === undefined ? errorRefetchMs(error) : retryAt - clock.getTime()) / 1000),
  );
  const when = secs > 0 ? `retrying in ${secs}s` : "retrying now";
  const polls = pollsAfterError(error);
  const selectCve = (id: string) => onSelect({ kind: "cve", id });
  return (
    <div className="lanes-wrap">
      {error ? (
        <div className="lanes-error" role="alert">
          {!polls ? "Sign in to see the lanes" : rate ? `Rate limited — ${when}` : `Couldn't load the lanes — ${when}`}
        </div>
      ) : null}
      <div className="lanes">
        {DEFS.map((d) => {
          const total = lanes?.[d.key]?.total ?? 0;
          const cves = (lanes?.[d.key]?.items ?? []).slice(0, LANE_ROWS);
          const storyShown = d.key === "LOUD" ? loudStoriesFor(cves, stories).slice(0, LANE_ROWS - cves.length) : [];
          const count = cves.length + storyShown.length;
          const showSkeleton = loading && !lanes;
          const headId = `lane-${d.k}`;
          return (
            <section key={d.key} className="lane" data-k={d.k} aria-labelledby={headId}>
              <header className="lane-head">
                <span className="tick" aria-hidden="true" />
                <h2 id={headId}>{d.title}</h2>
                <span className="n">
                  {showSkeleton ? "" : total}
                  {!showSkeleton && <span className="sr-only"> in range</span>}
                </span>
              </header>
              <div className="lane-sub">{d.sub}</div>
              <div className="lane-items">
                {showSkeleton ? (
                  <Skeleton />
                ) : count === 0 ? (
                  <p className="lane-empty">Nothing in the last {RANGE_LABEL[range]}.</p>
                ) : (
                  <>
                    {cves.map((c) => (
                      <LaneRow key={c.cve_id} item={c} lane={d.key} now={clock} onSelect={selectCve} />
                    ))}
                    {storyShown.map((s, i) => (
                      <StoryRow
                        key={`${s.url}#${i}`}
                        story={s}
                        now={clock}
                        onOpen={(url) => onSelect({ kind: "story", url })}
                      />
                    ))}
                  </>
                )}
              </div>
              {!showSkeleton && (
                <div className="lane-foot">
                  <Link to={threatsHref(d.k, range)}>
                    {total > LANE_ROWS ? `View all ${total} in Threats →` : "Open in Threats →"}
                  </Link>
                </div>
              )}
            </section>
          );
        })}
      </div>
    </div>
  );
}

export function Lanes({ range = DEFAULT_RANGE }: { range?: RangeKey }) {
  const lanes = useLanes(range, LANE_ROWS);
  const stories = useLoudStories(range, LANE_ROWS);
  // Tick every second while the error countdown is on screen.
  const now = useNow(lanes.isError ? 1000 : 60_000);
  const { select } = useSelection();
  return (
    <LanesView
      lanes={lanes.data}
      stories={stories.data}
      loading={lanes.isPending && !lanes.isError}
      error={lanes.isError ? lanes.error : undefined}
      retryAt={lanes.isError ? nextRetryAt(lanes) : undefined}
      now={now}
      range={range}
      onSelect={select}
    />
  );
}
