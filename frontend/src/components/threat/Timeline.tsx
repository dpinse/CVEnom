import { timelineRows } from "../../lib/threatModel";
import { Text } from "../../lib/text";
import type { CveDetail } from "../../lib/types";
import { dayOf } from "./format";

/**
 * A vertical rail: when (offset from publication, then the date) on the left, a node on the rail,
 * what happened and who said so on the right. The three events that change the risk (published,
 * public exploit, exploited in the wild) get a coloured node and a heavier label; the rest are quiet.
 */
export function Timeline({ d }: { d: CveDetail }) {
  const rows = timelineRows(d.events ?? [], d.published);
  return (
    <section className="blk" aria-labelledby="t-timeline">
      <h2 id="t-timeline">Timeline</h2>
      {rows.length === 0 ? (
        <p className="muted">No dated events yet.</p>
      ) : (
        <>
          {d.published ? <p className="tl-note">Times are measured from publication (t = 0).</p> : null}
          <ol className="tl">
            {rows.map((r, i) => (
              <li key={`${r.at}#${r.label}#${r.source}#${i}`} className={r.key ? "key" : undefined} data-kind={r.kind}>
                <span className="when">
                  <span className="off">{r.offset ?? ""}</span>
                  <time className="d" dateTime={r.at}>
                    {dayOf(r.at)}
                  </time>
                </span>
                <span className="node" aria-hidden="true" />
                <span className="what">
                  <span className="e">{r.label}</span>
                  <span className="src">
                    <Text value={r.source} />
                  </span>
                </span>
              </li>
            ))}
          </ol>
        </>
      )}
    </section>
  );
}
