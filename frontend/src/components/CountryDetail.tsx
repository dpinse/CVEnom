import { useEffect } from "react";
import { ApiError } from "../lib/api";
import { DEFAULT_RANGE } from "../lib/range";
import { useCountry } from "../lib/queries";
import { relTime } from "../lib/relTime";
import { decodeEntities, ExternalLink, safeHref, Text } from "../lib/text";
import type { CountryActivity, CountryEvent } from "../lib/types";
import { useNow } from "../lib/useNow";
import { isGeoKind, KIND_LABEL } from "./geoSummary";
import { useGlobe } from "./GlobeContext";
import { KindSwatch } from "./GlobeChrome";
import { isRansomwareSource, RansomwareCredit } from "./RansomwareCredit";

/** The trend is shown only when there is something to draw: enough events, spread over at least two buckets. */
export const TREND_MIN_EVENTS = 3;
export const TREND_MIN_BUCKETS = 2;

const W = 240;
const H = 48;

/**
 * Display-only hourly bars. The trend is not guaranteed to sum to the counts, so it is only ever drawn, never
 * reconciled with them. Holds numbers only: no text from the API.
 */
function CountryTrend({ trend }: { trend: CountryActivity["trend"] }) {
  const val = (n: number) => (Number.isFinite(n) && n > 0 ? n : 0);
  const max = Math.max(1, ...trend.map((b) => val(b.events)));
  const slot = W / trend.length;
  return (
    <svg
      className="trend"
      data-testid="country-trend"
      viewBox={`0 0 ${W} ${H}`}
      role="img"
      aria-label="Events per hour"
      preserveAspectRatio="none"
    >
      {trend.map((b, i) => {
        const h = val(b.events) > 0 ? Math.max(2, (val(b.events) / max) * H) : 0;
        return h > 0 ? (
          <rect key={i} className="trend-bar" x={i * slot + 0.5} y={H - h} width={Math.max(1, slot - 1)} height={h} />
        ) : null;
      })}
    </svg>
  );
}

function EventRow({ e, now }: { e: CountryEvent; now: Date }) {
  // A rejected (unsafe or .onion) story_url renders nothing at all.
  const safe = e.story_url ? safeHref(decodeEntities(e.story_url)) : null;
  return (
    <li className="ref cev">
      {isGeoKind(e.kind) ? (
        <span className="cev-kind">
          <KindSwatch kind={e.kind} /> {KIND_LABEL[e.kind]}
        </span>
      ) : (
        <span className="cev-kind">
          <Text value={e.kind} />
        </span>
      )}
      {e.label ? (
        <span>
          <Text value={e.label} />
        </span>
      ) : null}
      <span className="dmuted">
        <Text value={e.source} /> · {relTime(e.observed_at, now)}
      </span>
      {safe ? (
        <ExternalLink href={safe} className="dlink">
          {new URL(safe).hostname}
        </ExternalLink>
      ) : null}
    </li>
  );
}

function CountryBody({ a }: { a: CountryActivity }) {
  const now = useNow();
  const total = a.counts.reduce((n, c) => n + (Number.isFinite(c.events) ? c.events : 0), 0);
  const nonZero = a.trend.filter((b) => Number.isFinite(b.events) && b.events > 0).length;
  const showTrend = total >= TREND_MIN_EVENTS && nonZero >= TREND_MIN_BUCKETS;
  const events = a.events;
  const credit = events?.some((e) => isRansomwareSource(e.source)) ?? false;
  if (a.counts.length === 0) {
    return (
      <div className="dnote">
        <p className="sum">No activity recorded for this country in the last {a.window_hours || 24} hours</p>
      </div>
    );
  }
  return (
    <>
      <div>
        <div className="seclabel">Activity, last {a.window_hours} hours</div>
        <ul className="refs" data-testid="country-counts">
          {a.counts.map((c) => (
            <li key={c.kind} className="ref">
              {isGeoKind(c.kind) ? (
                <>
                  <KindSwatch kind={c.kind} />
                  <span>{KIND_LABEL[c.kind]}</span>
                </>
              ) : (
                <Text value={c.kind} />
              )}
              <span className="dmuted mono">{c.events} events</span>
            </li>
          ))}
        </ul>
      </div>
      {showTrend && (
        <div>
          <div className="seclabel">Trend</div>
          <CountryTrend trend={a.trend} />
        </div>
      )}
      {a.top_sources.length > 0 && (
        <div>
          <div className="seclabel">Top sources</div>
          <ul className="refs">
            {a.top_sources.map((s) => (
              <li key={s.source} className="ref">
                <Text value={s.source} />
                <span className="dmuted mono">{s.events} events</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      <div>
        <div className="seclabel">Events</div>
        {events === null ? (
          <p className="sum">Sign in to see individual events</p>
        ) : events.length === 0 ? (
          <p className="sum">No individual events in this window</p>
        ) : (
          <ul className="refs" data-testid="country-events">
            {events.map((e, i) => (
              <EventRow key={`${e.observed_at}#${i}`} e={e} now={now} />
            ))}
          </ul>
        )}
        {credit && <RansomwareCredit />}
      </div>
    </>
  );
}

/** A country drawer body: GET /api/geo/{cc} for the last 24 h. Also turns the globe to the country. */
export function CountryDetail({ cc }: { cc: string }) {
  const q = useCountry(cc, DEFAULT_RANGE);
  const globe = useGlobe();
  useEffect(() => {
    globe.flyTo(cc);
  }, [cc, globe]);
  if (q.isError) {
    return (
      <div className="dnote" role="alert">
        <p className="sum">
          {q.error instanceof ApiError && q.error.status === 404
            ? "No data for this country"
            : "Couldn't load this country's activity."}
        </p>
        <button type="button" className="chip linked" onClick={() => void q.refetch()}>
          Retry
        </button>
      </div>
    );
  }
  if (!q.data) return <div className="dskeleton" role="status" aria-busy="true" aria-label="Loading country" />;
  return <CountryBody a={q.data} />;
}
