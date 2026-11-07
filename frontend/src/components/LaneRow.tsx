import { shortAgo } from "../lib/relTime";
import { decodeEntities, Text } from "../lib/text";
import { isRansomwareSource, RansomwareCredit } from "./RansomwareCredit";
import type { CveItem, Lane, LoudStory } from "../lib/types";

export type Sev = "crit" | "high" | "med" | "low";

export function severityOf(cvss: number | null): Sev {
  if (cvss === null || !Number.isFinite(cvss)) return "low";
  if (cvss >= 9) return "crit";
  if (cvss >= 7) return "high";
  if (cvss >= 4) return "med";
  return "low";
}

const SEV_NAME: Record<Sev, string> = { crit: "Critical", high: "High", med: "Medium", low: "Low" };

/** "Product: summary" when the CVE has a product, else just the summary (entity-escaped, decoded once at render). */
export function productIssue(item: CveItem): string {
  return item.product ? `${item.product}: ${item.summary}` : item.summary;
}

/** Up to three one-line facts for a row: the lane signal first, then PoC, then "no patch". */
export function laneMeta(item: CveItem, lane: Lane, now: Date): string[] {
  const out: string[] = [];
  if (lane === "EXPLOITED") {
    if (item.kev_added) out.push(`KEV ${shortAgo(`${item.kev_added}T00:00:00Z`, now)}`);
  } else if (lane === "LIKELY") {
    if (item.epss_percentile !== null) out.push(`EPSS p${Math.round(item.epss_percentile * 100)}`);
  } else if (lane === "LOUD") {
    const n = item.recent_story_count;
    out.push(`${n} ${n === 1 ? "story" : "stories"}`);
  } else if (item.published) {
    out.push(`published ${shortAgo(item.published, now)}`);
  }
  if (item.poc_badge) out.push("PoC");
  if (item.patch_available === false) out.push("no patch");
  return out.slice(0, 3);
}

export function LaneRow({
  item,
  lane,
  now,
  onSelect,
}: {
  item: CveItem;
  lane: Lane;
  now: Date;
  onSelect: (id: string) => void;
}) {
  const sev = severityOf(item.cvss);
  const text = productIssue(item);
  return (
    <button type="button" className="row" data-sev={sev} data-testid="lane-row" onClick={() => onSelect(item.cve_id)}>
      <span className="sev" aria-label={item.cvss === null ? "Unscored" : SEV_NAME[sev]} role="img" />
      <span className="id">{item.cve_id}</span>
      <span className="score">{item.cvss === null ? "–" : item.cvss.toFixed(1)}</span>
      <span className="t" title={decodeEntities(text)}>
        <Text value={text} />
      </span>
      <span className="meta">
        {laneMeta(item, lane, now).map((m, i) => (
          <span key={m} className={i === 0 && lane === "EXPLOITED" ? "k" : undefined}>
            {m}
          </span>
        ))}
      </span>
    </button>
  );
}

export function StoryRow({ story, now, onOpen }: { story: LoudStory; now: Date; onOpen: (url: string) => void }) {
  return (
    <div className="row story-row" data-sev="story" data-testid="story-row">
      <button type="button" className="story-open" onClick={() => onOpen(story.url)}>
        <span className="t" title={decodeEntities(story.title)}>
          <Text value={story.title} />
        </span>
        <span className="meta">
          <span>
            <Text value={story.source} /> · {shortAgo(story.published, now)}
          </span>
        </span>
      </button>
      {isRansomwareSource(story.source) && <RansomwareCredit className="meta" />}
    </div>
  );
}
