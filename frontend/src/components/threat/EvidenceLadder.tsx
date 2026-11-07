import { ladderStages } from "../../lib/threatModel";
import type { CveDetail } from "../../lib/types";

/** Detectable and Public exploit are weaker signals than KEV and ransomware, so they use the softer colour. */
const SOFT = new Set(["Detectable", "Public exploit"]);

export function EvidenceLadder({ d }: { d: CveDetail }) {
  return (
    <section className="blk" aria-labelledby="t-ladder">
      <h2 id="t-ladder">Exploitation evidence</h2>
      <ol className="ladder">
        {ladderStages(d).map((s) => (
          <li key={s.name} className={`${s.reached ? "done" : ""}${SOFT.has(s.name) ? " soft" : ""}`.trim()}>
            <span className="st">
              {s.name}
              <span className="sr-only">{s.reached ? ": reached" : ": not reached"}</span>
            </span>
            <span className="ev">{s.evidence}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}
