import { relTime } from "../lib/relTime";
import { Text } from "../lib/text";
import type { CveItem, LoudStory } from "../lib/types";

export type Sev = "crit" | "high" | "med" | "low";

export function severityOf(cvss: number | null): Sev {
  if (cvss === null || !Number.isFinite(cvss)) return "low";
  if (cvss >= 9) return "crit";
  if (cvss >= 7) return "high";
  if (cvss >= 4) return "med";
  return "low";
}

export function LaneRow({ item, onSelect }: { item: CveItem; onSelect: (id: string) => void }) {
  const sev = severityOf(item.cvss);
  return (
    <button
      type="button"
      className={`row${item.kev ? " live" : ""}`}
      data-sev={sev}
      data-edge={item.kev ? "live" : sev}
      data-testid="lane-row"
      onClick={() => onSelect(item.cve_id)}
    >
      <span className="edge" aria-hidden="true" />
      <span className="row-body">
        <span className="row-id">
          <span className="row-id-text">{item.cve_id}</span>
          {item.kev && (
            <span className="wild">
              <i className="strobe" aria-hidden="true" />
              in the wild
            </span>
          )}
        </span>
        <Text className="row-title" value={item.summary} />
        <span className="chips">
          {item.cvss !== null && <span className={`chip num ${sev}`}>{item.cvss.toFixed(1)}</span>}
          {item.epss_percentile !== null && (
            <span className="chip num">EPSS p{Math.round(item.epss_percentile * 100)}</span>
          )}
          {item.kev && (
            <span className="chip kev" title={item.kev_source ?? undefined}>
              KEV{item.kev_added ? ` · ${item.kev_added}` : ""}
            </span>
          )}
          {item.poc_badge && <span className="chip poc">PoC</span>}
          {item.patch_available === false && <span className="chip">no patch</span>}
          {item.recent_story_count > 0 && <span className="chip linked">news ×{item.recent_story_count}</span>}
        </span>
      </span>
    </button>
  );
}

export function StoryRow({
  story,
  now,
  onOpen,
  onSelectCve,
}: {
  story: LoudStory;
  now: Date;
  onOpen: (url: string) => void;
  onSelectCve: (id: string) => void;
}) {
  const ids = story.cve_ids ?? [];
  return (
    <div className="row story-row" data-sev="story" data-testid="story-row">
      <span className="edge" aria-hidden="true" />
      <span className="row-body">
        <button type="button" className="story-open" onClick={() => onOpen(story.url)}>
          <Text className="row-title" value={story.title} />
          <span className="row-src">
            <Text value={story.source} /> · {relTime(story.published, now)}
          </span>
        </button>
        <span className="chips">
          {ids.length === 0 ? (
            <span className="chip quiet">no CVE</span>
          ) : (
            ids.map((id) => (
              <button key={id} type="button" className="chip linked" onClick={() => onSelectCve(id)}>
                {id}
              </button>
            ))
          )}
        </span>
      </span>
    </div>
  );
}
