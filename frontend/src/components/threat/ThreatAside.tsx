import { Link } from "react-router-dom";
import { RANGE_LABEL } from "../../lib/range";
import { relTime } from "../../lib/relTime";
import { ExternalLink, Text } from "../../lib/text";
import type { CveDetail } from "../../lib/types";
import { useNow } from "../../lib/useNow";
import { countryName, isIso2 } from "../geoSummary";
import { GeoAttribution } from "../GlobeChrome";
import { isRansomwareSource, RansomwareCredit } from "../RansomwareCredit";

/** "Where it's seen" always covers the last 7 days (spec Amendment A: no range control on this page). */
export const SEEN_RANGE = "7d";
const MAX_RELATED = 4;

export function ThreatAside({ d }: { d: CveDetail }) {
  const now = useNow();
  const stories = [...(d.stories ?? [])].sort(
    (a, b) => (Date.parse(b.published) || 0) - (Date.parse(a.published) || 0),
  );
  const related = (d.related ?? []).slice(0, MAX_RELATED);
  const seen = (d.geo_top ?? []).filter((g) => isIso2(g.country_code));
  return (
    <aside className="t-aside" aria-label="Context">
      <div className="panel aside-box">
        <h3>In the news</h3>
        {stories.length === 0 ? (
          <p className="muted small">No coverage yet.</p>
        ) : (
          stories.map((s, i) => (
            <div className="story" key={`${s.url}#${i}`}>
              <ExternalLink href={s.url}>
                <Text value={s.title} />
              </ExternalLink>
              <span>
                <Text value={s.source} /> · {relTime(s.published, now)}
              </span>
              {isRansomwareSource(s.source) && <RansomwareCredit />}
            </div>
          ))
        )}
      </div>
      <div className="panel aside-box">
        <h3>Related threats</h3>
        {related.length === 0 ? (
          <p className="muted small">None found.</p>
        ) : (
          related.map((r) => (
            <div className="story" key={r.cve_id}>
              <Link className="mono" to={`/threats/${encodeURIComponent(r.cve_id)}`}>
                {r.cve_id}
              </Link>
              <span>
                {r.product ? (
                  <>
                    <Text value={r.product} /> ·{" "}
                  </>
                ) : null}
                {r.kev
                  ? "exploited"
                  : r.epss_percentile !== null
                    ? `EPSS p${Math.round(r.epss_percentile * 100)}`
                    : "no EPSS"}
              </span>
            </div>
          ))
        )}
      </div>
      {seen.length > 0 && (
        <div className="panel aside-box">
          <h3>Where it&apos;s seen</h3>
          <dl className="kv">
            {seen.map((g) => (
              <div className="kv-row" key={g.country_code}>
                <dt>{countryName(g.country_code)}</dt>
                <dd className="num">{g.events}</dd>
              </div>
            ))}
          </dl>
          <span className="muted small">
            Scanning and exploit attempts that name this CVE, last {RANGE_LABEL[SEEN_RANGE]}.
          </span>
          <GeoAttribution />
        </div>
      )}
    </aside>
  );
}
