import { useLoudStories } from "../lib/queries";
import { relTime } from "../lib/relTime";
import { CVE_ID_RE, useSelection } from "../lib/selection";
import { ExternalLink, safeHref, Text } from "../lib/text";
import { useNow } from "../lib/useNow";
import { isRansomwareSource, RansomwareCredit } from "./RansomwareCredit";

/** A story drawer body. There is no single-story endpoint, so it reads the cached loud feed. */
export function StoryDetail({ url }: { url: string }) {
  const stories = useLoudStories();
  const { select } = useSelection();
  const now = useNow();
  if (stories.isPending && !stories.isError) {
    return <div className="dskeleton" role="status" aria-busy="true" aria-label="Loading story" />;
  }
  const story = stories.data?.find((s) => s.url === url || safeHref(s.url) === url);
  if (!story && stories.isError) {
    return (
      <div className="dnote" role="alert">
        <p className="sum">{"Couldn't load stories — try again"}</p>
      </div>
    );
  }
  if (!story) {
    return (
      <div className="dnote">
        <p className="sum">This story is no longer in the live feed.</p>
        <p className="sum">
          <ExternalLink href={url} className="dlink">
            <Text value={url} />
          </ExternalLink>
        </p>
      </div>
    );
  }
  const ids = story.cve_ids ?? [];
  return (
    <>
      <h3 className="dstory-title">
        <Text value={story.title} />
      </h3>
      <div className="dmeta">
        <span>
          <Text value={story.source} /> · {relTime(story.published, now)}
        </span>
        {isRansomwareSource(story.source) && <RansomwareCredit />}
      </div>
      <div>
        <div className="seclabel">What happened</div>
        <p className="sum isolate">
          <Text value={story.summary} />
        </p>
      </div>
      <p className="sum">
        <ExternalLink href={story.url} className="dlink">
          Open article
        </ExternalLink>
      </p>
      <div>
        <div className="seclabel">Linked CVEs</div>
        <div className="chips">
          {ids.length === 0 ? (
            <span className="chip quiet">no CVE attributed</span>
          ) : (
            ids.map((id) =>
              typeof id === "string" && CVE_ID_RE.test(id) ? (
                <button key={id} type="button" className="chip linked" onClick={() => select({ kind: "cve", id })}>
                  {id}
                </button>
              ) : (
                <span key={String(id)} className="chip quiet">
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
