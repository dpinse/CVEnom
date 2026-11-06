import { ApiError } from "../lib/api";
import { useStory } from "../lib/queries";
import { relTime } from "../lib/relTime";
import { CVE_ID_RE, useSelection } from "../lib/selection";
import { decodeEntities, ExternalLink, safeHref, Text } from "../lib/text";
import type { StoryDetailOut } from "../lib/types";
import { useNow } from "../lib/useNow";
import { countryName, isIso2 } from "./geoSummary";
import { isRansomwareSource, RansomwareCredit } from "./RansomwareCredit";

const str = (v: unknown): string => (typeof v === "string" ? v : "");

/** The ransomware.live details block. Every value is entity-escaped text: shown through <Text>, never as HTML. */
function RansomDetails({ details }: { details: Record<string, unknown> }) {
  const country = str(details.country);
  const rows: [string, string][] = [
    ["Victim", str(details.victim)],
    ["Group", str(details.group)],
    ["Sector", str(details.activity)],
    ["Country", country && isIso2(country) ? countryName(country) : country],
    ["Attack date", str(details.attackdate)],
    ["Discovered", str(details.discovered)],
  ];
  const shown = rows.filter(([, v]) => v !== "");
  const website = str(details.website); // plain text, never an anchor; null when the backend dropped it
  const description = str(details.description);
  const press = Array.isArray(details.press) ? details.press.filter((p): p is string => typeof p === "string") : [];
  return (
    <>
      {(shown.length > 0 || website) && (
        <div>
          <div className="seclabel">Details</div>
          <dl className="kv" data-testid="ransom-details">
            {shown.map(([k, v]) => (
              <div key={k} className="kv-row">
                <dt>{k}</dt>
                <dd>
                  <Text value={v} />
                </dd>
              </div>
            ))}
            {website && (
              <div className="kv-row">
                <dt>Website</dt>
                <dd>
                  <Text value={website} />
                </dd>
              </div>
            )}
          </dl>
        </div>
      )}
      {description && (
        <div>
          <div className="seclabel">Description</div>
          <p className="sum isolate">
            <Text value={description} />
          </p>
        </div>
      )}
      {press.length > 0 && (
        <div>
          <div className="seclabel">Press</div>
          <ul className="refs">
            {press.map((p, i) => (
              <li key={`${p}#${i}`} className="ref">
                <ExternalLink href={decodeEntities(p)} className="dlink">
                  <Text value={safeHostOrText(p)} />
                </ExternalLink>
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

/** Link text for a press URL: its hostname when it is a safe URL, else the decoded text itself. */
function safeHostOrText(p: string): string {
  const safe = safeHref(decodeEntities(p));
  return safe ? new URL(safe).hostname : p;
}

function StoryBody({ story }: { story: StoryDetailOut }) {
  const { select } = useSelection();
  const now = useNow();
  const ids = story.cve_ids ?? [];
  const ransom = isRansomwareSource(story.source);
  return (
    <>
      <h3 className="dstory-title">
        <Text value={story.title} />
      </h3>
      <div className="dmeta">
        <span>
          <Text value={story.source} /> · {relTime(story.published, now)}
        </span>
        {ransom && <RansomwareCredit />}
      </div>
      {ransom && story.details && typeof story.details === "object" && <RansomDetails details={story.details} />}
      {story.summary ? (
        <div>
          <div className="seclabel">What happened</div>
          <p className="sum isolate">
            <Text value={story.summary} />
          </p>
        </div>
      ) : null}
      <p className="sum">
        <ExternalLink href={story.url} className="dlink">
          {ransom ? "View on ransomware.live" : "Open article"}
        </ExternalLink>
      </p>
      <div>
        <div className="seclabel">Linked CVEs</div>
        <div className="chips">
          {ids.length === 0 ? (
            <span className="chip quiet">no CVE attributed</span>
          ) : (
            ids.map((id, i) =>
              typeof id === "string" && CVE_ID_RE.test(id) ? (
                <button
                  key={`${id}#${i}`}
                  type="button"
                  className="chip linked"
                  onClick={() => select({ kind: "cve", id })}
                >
                  {id}
                </button>
              ) : (
                <span key={`${String(id)}#${i}`} className="chip quiet">
                  <Text value={String(id)} />
                </span>
              ),
            )
          )}
        </div>
      </div>
    </>
  );
}

/** A story drawer body, read through GET /api/story?url= (any stored story, not just the loud feed). */
export function StoryDetail({ url }: { url: string }) {
  const q = useStory(url);
  if (q.isError) {
    if (q.error instanceof ApiError && q.error.status === 404) {
      // The URL came from the address bar: never echo it, and never as a link. For anonymous callers a restricted
      // story is indistinguishable from a missing one, so the copy says only "not found".
      return (
        <div className="dnote">
          <p className="sum">Story not found (it may have been removed)</p>
        </div>
      );
    }
    return (
      <div className="dnote" role="alert">
        <p className="sum">{"Couldn't load this story"}</p>
        <button type="button" className="chip linked" onClick={() => void q.refetch()}>
          Retry
        </button>
      </div>
    );
  }
  if (!q.data) return <div className="dskeleton" role="status" aria-busy="true" aria-label="Loading story" />;
  return <StoryBody story={q.data} />;
}
