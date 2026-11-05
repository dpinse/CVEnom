import { RateLimited } from "../lib/api";
import { errorRefetchMs, nextRetryAt, pollsAfterError, useLanes, useLoudStories } from "../lib/queries";
import { useSelection, type Selection } from "../lib/selection";
import type { CveItem, Lane, LoudStory } from "../lib/types";
import { useNow } from "../lib/useNow";
import { LaneRow, StoryRow } from "./LaneRow";

export const LANE_CAP = 100;

interface LaneDef {
  key: Lane;
  k: string;
  title: string;
  sub: string;
  empty: string;
}
const DEFS: LaneDef[] = [
  {
    key: "EXPLOITED",
    k: "exploited",
    title: "Exploited now",
    sub: "known exploited",
    empty: "Nothing exploited right now",
  },
  { key: "LIKELY", k: "likely", title: "Likely next", sub: "high exploit odds", empty: "No likely-next CVEs" },
  { key: "LOUD", k: "loud", title: "Loud now", sub: "in the news", empty: "Quiet — no buzz" },
  { key: "FRESH", k: "fresh", title: "Fresh criticals", sub: "new and severe", empty: "No fresh criticals" },
];

/** Stories newest first, minus those whose CVEs are all already shown as LOUD CVE rows. */
export function loudStoriesFor(loud: CveItem[], stories: LoudStory[]): LoudStory[] {
  const shown = new Set(loud.map((c) => c.cve_id));
  return stories
    .filter((s) => !(s.cve_ids?.length > 0 && s.cve_ids.every((id) => shown.has(id))))
    .sort((a, b) => (Date.parse(b.published) || 0) - (Date.parse(a.published) || 0));
}

interface ViewProps {
  lanes?: Partial<Record<Lane, CveItem[]>>;
  stories?: LoudStory[];
  loading?: boolean;
  error?: unknown;
  /** When the errored lanes query will next be refetched (epoch ms); defaults to a full interval. */
  retryAt?: number;
  now?: Date;
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

export function LanesView({ lanes, stories = [], loading, error, retryAt, now, onSelect }: ViewProps) {
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
          const cves = (lanes?.[d.key] ?? []).slice(0, LANE_CAP);
          const storyRows = d.key === "LOUD" ? loudStoriesFor(cves, stories) : [];
          const storyShown = storyRows.slice(0, Math.max(0, LANE_CAP - cves.length));
          const count = cves.length + storyShown.length;
          const showSkeleton = loading && !lanes;
          const headId = `lane-${d.k}`;
          return (
            <section key={d.key} className="lane" data-k={d.k} aria-labelledby={headId}>
              <header className="lane-head">
                <span className="tick" aria-hidden="true" />
                <h2 id={headId}>{d.title}</h2>
                <span className="sub">{d.sub}</span>
                <span className="n">
                  {showSkeleton ? "" : count}
                  {!showSkeleton && <span className="sr-only"> items</span>}
                </span>
              </header>
              <div className="lane-items">
                {showSkeleton ? (
                  <Skeleton />
                ) : count === 0 ? (
                  <p className="lane-empty">{d.empty}</p>
                ) : (
                  <>
                    {cves.map((c) => (
                      <LaneRow key={c.cve_id} item={c} onSelect={selectCve} />
                    ))}
                    {storyShown.map((s, i) => (
                      <StoryRow
                        key={`${s.url}#${i}`}
                        story={s}
                        now={clock}
                        onOpen={(url) => onSelect({ kind: "story", url })}
                        onSelectCve={selectCve}
                      />
                    ))}
                  </>
                )}
              </div>
            </section>
          );
        })}
      </div>
    </div>
  );
}

export function Lanes() {
  const lanes = useLanes();
  const stories = useLoudStories();
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
      onSelect={select}
    />
  );
}
