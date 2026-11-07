/**
 * The map's side panel. With no `?country=`: "Top countries" (8 rows, every one a real button, so the list is the
 * keyboard route to each country, including those the 110m atlas cannot draw). With `?country=CC`: that country's
 * breakdown by kind, the CVEs linked to it and (signed in only) its latest events.
 */
import { useEffect, useMemo } from "react";
import { ApiError } from "../lib/api";
import { useGeo, useCountry } from "../lib/queries";
import { RANGE_LABEL, type RangeKey } from "../lib/range";
import { relTime } from "../lib/relTime";
import { useSelection } from "../lib/selection";
import { Text } from "../lib/text";
import type { CountryActivity } from "../lib/types";
import { useNow } from "../lib/useNow";
import { GeoAttribution, KindSwatch } from "./GlobeChrome";
import { useGlobe } from "./GlobeContext";
import { countryName, countryTotals, isGeoKind, KIND_LABEL, rankCountries } from "./geoSummary";
import { severityOf } from "./LaneRow";
import { isRansomwareSource, RansomwareCredit } from "./RansomwareCredit";

export const TOP_COUNTRIES = 8;
const EVENTS_SHOWN = 5;

function TopCountries({ range }: { range: RangeKey }) {
  const geo = useGeo(range);
  const { select } = useSelection();
  const totals = useMemo(() => countryTotals(Array.isArray(geo.data) ? geo.data : []), [geo.data]);
  const top = rankCountries(totals, TOP_COUNTRIES);
  const max = top[0]?.events ?? 0;
  return (
    <>
      <div className="side-head">
        <h2>Top countries</h2>
        <span className="muted">{RANGE_LABEL[range]}</span>
      </div>
      {geo.isPending ? (
        <p className="muted" role="status">
          Loading countries…
        </p>
      ) : geo.isError && !geo.data ? (
        <p className="muted" role="alert">
          Geolocated activity is unavailable right now.
        </p>
      ) : top.length === 0 ? (
        <p className="muted">No geolocated activity in the last {RANGE_LABEL[range]}.</p>
      ) : (
        <ul className="clist" aria-label="Top countries">
          {top.map((c) => (
            <li key={c.iso2}>
              <button type="button" onClick={() => select({ kind: "country", cc: c.iso2 })}>
                <span className="cc">{c.iso2}</span>
                <span className="nm">
                  {c.name}
                  <span className="bar-mini">
                    <i style={{ width: `${Math.max(2, (c.events / max) * 100)}%` }} />
                  </span>
                </span>
                <span className="num">{c.events}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
      <p className="muted hint">Select a country on the map or in this list to see what makes up its count.</p>
    </>
  );
}

function Events({ a }: { a: CountryActivity }) {
  const now = useNow();
  const events = a.events;
  if (events === null) {
    return (
      <p className="muted hint" data-testid="country-events-hint">
        Sign in to see individual events.
      </p>
    );
  }
  if (events.length === 0) return null;
  return (
    <>
      <h3>Latest events</h3>
      <ul className="evlist" data-testid="country-events">
        {events.slice(0, EVENTS_SHOWN).map((e, i) => (
          <li key={`${e.observed_at}#${i}`}>
            <span>
              {isGeoKind(e.kind) ? KIND_LABEL[e.kind] : <Text value={e.kind} />}
              {e.label ? (
                <>
                  {" "}
                  · <Text value={e.label} />
                </>
              ) : null}
            </span>
            <span className="muted">
              <Text value={e.source} /> · {relTime(e.observed_at, now)}
            </span>
          </li>
        ))}
      </ul>
      {events.some((e) => isRansomwareSource(e.source)) && <RansomwareCredit />}
    </>
  );
}

function CountryBody({
  a,
  onOpenCve,
  range,
}: {
  a: CountryActivity;
  onOpenCve: (id: string) => void;
  range: RangeKey;
}) {
  if (a.counts.length === 0) {
    return <p className="muted">No activity recorded for this country in the last {RANGE_LABEL[range]}.</p>;
  }
  return (
    <>
      <dl className="kv" data-testid="country-counts">
        {a.counts.map((c) => (
          <div key={c.kind} className="kv-line">
            <dt>
              {isGeoKind(c.kind) ? (
                <>
                  <KindSwatch kind={c.kind} /> {KIND_LABEL[c.kind]}
                </>
              ) : (
                <Text value={c.kind} />
              )}
            </dt>
            <dd>{c.events}</dd>
          </div>
        ))}
      </dl>
      {a.top_cves.length > 0 && (
        <>
          <h3>CVEs linked here</h3>
          <ul className="clist" aria-label="CVEs linked here">
            {a.top_cves.map((c) => (
              <li key={c.cve_id}>
                <button type="button" className="cve" onClick={() => onOpenCve(c.cve_id)}>
                  <i className="sevdot" data-sev={c.cvss === null ? "none" : severityOf(c.cvss)} aria-hidden="true" />
                  <span className="mono">{c.cve_id}</span>
                  <span className="num">{c.cvss === null ? "–" : c.cvss.toFixed(1)}</span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
      <Events a={a} />
    </>
  );
}

function CountryView({ cc, range }: { cc: string; range: RangeKey }) {
  const q = useCountry(cc, range);
  const { select, clearCountry } = useSelection();
  const globe = useGlobe();
  useEffect(() => {
    globe.flyTo(cc);
  }, [cc, globe]);
  return (
    <>
      <div className="side-head">
        <h2>{countryName(cc)}</h2>
        <button type="button" className="back" onClick={clearCountry}>
          All countries
        </button>
      </div>
      {q.isError ? (
        <div role="alert">
          <p className="muted">
            {q.error instanceof ApiError && q.error.status === 404
              ? "No data for this country"
              : "Couldn't load this country's activity."}
          </p>
          <button type="button" className="chip linked" onClick={() => void q.refetch()}>
            Retry
          </button>
        </div>
      ) : !q.data ? (
        <div className="dskeleton" role="status" aria-busy="true" aria-label="Loading country" />
      ) : (
        <CountryBody a={q.data} range={range} onOpenCve={(id) => select({ kind: "cve", id })} />
      )}
    </>
  );
}

export function CountryPanel({ range }: { range: RangeKey }) {
  const { country } = useSelection();
  return (
    <aside className="side" aria-label="Country detail">
      {country ? <CountryView cc={country} range={range} /> : <TopCountries range={range} />}
      <GeoAttribution />
    </aside>
  );
}
