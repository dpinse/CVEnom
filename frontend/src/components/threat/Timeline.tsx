import { timelineRows } from "../../lib/threatModel";
import { Text } from "../../lib/text";
import type { CveDetail } from "../../lib/types";
import { dayOf } from "./format";

export function Timeline({ d }: { d: CveDetail }) {
  const rows = timelineRows(d.events ?? [], d.published);
  return (
    <section className="blk" aria-labelledby="t-timeline">
      <h2 id="t-timeline">Timeline</h2>
      {rows.length === 0 ? (
        <p className="muted">No dated events yet.</p>
      ) : (
        <ol className="tl">
          {rows.map((r, i) => (
            <li key={`${r.at}#${r.label}#${r.source}#${i}`} className={r.key ? "key" : undefined}>
              <time className="d" dateTime={r.at}>
                {dayOf(r.at)}
              </time>
              <span className="off">{r.offset ?? ""}</span>
              <span>
                <span className="e">{r.label}</span>{" "}
                <span className="src">
                  · <Text value={r.source} />
                </span>
              </span>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
