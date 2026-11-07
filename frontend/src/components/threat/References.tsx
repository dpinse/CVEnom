import { decodeEntities, ExternalLink, LinkRemoved, safeHref, Text } from "../../lib/text";
import type { CveReference } from "../../lib/types";

/** Host plus path; the query string is dropped from the label, not from the link. */
function shown(safe: string): string {
  const u = new URL(safe);
  return `${u.hostname}${u.pathname === "/" ? "" : u.pathname}`;
}

export function References({ refs }: { refs: CveReference[] }) {
  return (
    <section className="blk" aria-labelledby="t-refs">
      <h2 id="t-refs">References</h2>
      <ul className="reflist">
        {refs.map((r, i) => {
          // Stored URLs are entity-escaped: decode exactly once, then validate. An unsafe URL is never shown.
          const safe = safeHref(decodeEntities(r.url));
          const tag = r.tags?.[0];
          return (
            <li key={`${r.url}#${i}`}>
              <span className="k">{tag ? <Text value={tag} /> : "Link"}</span>
              {safe ? <ExternalLink href={safe}>{shown(safe)}</ExternalLink> : <LinkRemoved />}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
