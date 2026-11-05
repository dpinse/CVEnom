import { useEffect, useRef } from "react";
import { ApiError } from "../lib/api";
import { useCve } from "../lib/queries";
import { relTime } from "../lib/relTime";
import { ExternalLink, Text } from "../lib/text";
import type { CveDetail, GeoEventOut } from "../lib/types";
import { useNow } from "../lib/useNow";
import { countryName, isGeoKind, isIso2, KIND_LABEL } from "./geoSummary";
import { useGlobe } from "./GlobeContext";
import { severityOf } from "./LaneRow";

export const AFFECTED_CAP = 50;
export const DETAILS_CAP = 12;

const clamp = (n: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, n));
const isNum = (n: unknown): n is number => typeof n === "number" && Number.isFinite(n);

/** Strings pass through (and are decoded by <Text>); everything else becomes compact JSON text. */
export function asText(v: unknown): string {
  if (typeof v === "string") return v;
  try {
    return JSON.stringify(v) ?? String(v);
  } catch {
    return String(v);
  }
}

function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  return Number.isFinite(t) ? new Date(t).toISOString().slice(0, 10) : "";
}

function Meter({
  name,
  value,
  max,
  text,
  tone,
}: {
  name: string;
  value: number | null;
  max: number;
  text: string;
  tone: string;
}) {
  const has = isNum(value);
  const pct = has ? clamp((value / max) * 100, 0, 100) : 0;
  return (
    <div className="meter">
      <div className="mtop">
        <span className="mname">{name}</span>
        <span className="mval">{has ? text : "n/a"}</span>
      </div>
      <div
        className="track"
        role="meter"
        aria-label={name}
        aria-valuemin={0}
        aria-valuemax={max}
        aria-valuenow={has ? clamp(value, 0, max) : undefined}
        aria-valuetext={has ? text : "not available"}
      >
        <i data-tone={tone} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function GeoEvent({ ev, now }: { ev: GeoEventOut; now: Date }) {
  const kind = isGeoKind(ev.kind) ? KIND_LABEL[ev.kind] : String(ev.kind);
  const cc = isIso2(ev.country_code) ? ev.country_code : null;
  const entries = Object.entries(ev.details && typeof ev.details === "object" ? ev.details : {});
  const shown = entries.slice(0, DETAILS_CAP);
  return (
    <li className="gev">
      <div className="gev-top">
        <span className="chip">
          <Text value={kind} />
        </span>
        {cc && <span className="gev-cc">{countryName(cc)}</span>}
        <span className="gev-mag mono">{isNum(ev.magnitude) ? ev.magnitude : "n/a"}</span>
        <span className="gev-time">{relTime(ev.observed_at, now)}</span>
      </div>
      {ev.label ? (
        <div className="gev-label">
          <Text value={ev.label} />
        </div>
      ) : null}
      {shown.length > 0 && (
        <dl className="kv">
          {shown.map(([k, v]) => (
            <div key={k} className="kv-row">
              <dt>
                <Text value={k} />
              </dt>
              <dd>
                <Text value={asText(v)} />
              </dd>
            </div>
          ))}
          {entries.length > shown.length && <div className="kv-more">+{entries.length - shown.length} more</div>}
        </dl>
      )}
    </li>
  );
}

function topCountry(events: GeoEventOut[]): string | null {
  let best: GeoEventOut | null = null;
  for (const ev of events) {
    if (!isIso2(ev.country_code)) continue;
    const m = isNum(ev.magnitude) ? ev.magnitude : -Infinity;
    if (best === null || m > (isNum(best.magnitude) ? best.magnitude : -Infinity)) best = ev;
  }
  return best?.country_code ?? null;
}

export function CveDetailBody({ d }: { d: CveDetail }) {
  const now = useNow();
  const globe = useGlobe();
  const flown = useRef<string | null>(null);

  useEffect(() => {
    if (flown.current === d.cve_id) return;
    const cc = topCountry(d.geo_events ?? []);
    if (cc) {
      flown.current = d.cve_id;
      globe.flyTo(cc);
    }
  }, [d, globe]);

  const sev = severityOf(d.cvss);
  const epss = isNum(d.epss_percentile) ? d.epss_percentile : null;
  const epssTone = epss === null ? "low" : epss >= 0.5 ? "live" : epss >= 0.15 ? "high" : "low";
  const published = fmtDate(d.published);
  const kevDate = fmtDate(d.kev_added);
  const affected = d.affected ?? [];
  const stories = [...(d.stories ?? [])].sort(
    (a, b) => (Date.parse(b.published) || 0) - (Date.parse(a.published) || 0),
  );
  const geo = d.geo_events ?? [];
  return (
    <>
      <div className="dmeta">
        {d.kev && (
          <span className="wild">
            <i className="strobe" aria-hidden="true" />
            in the wild
          </span>
        )}
        {published && <span>Published {published}</span>}
      </div>
      <div className="meters">
        <Meter
          name="CVSS"
          value={isNum(d.cvss) ? d.cvss : null}
          max={10}
          text={isNum(d.cvss) ? d.cvss.toFixed(1) : ""}
          tone={sev}
        />
        <Meter
          name="EPSS percentile"
          value={epss}
          max={1}
          text={epss === null ? "" : `p${Math.round(clamp(epss, 0, 1) * 100)}`}
          tone={epssTone}
        />
      </div>
      <div className="chips">
        {d.kev ? (
          <span className="chip kev">
            KEV
            {d.kev_source ? (
              <>
                {" · "}
                <Text value={d.kev_source} />
              </>
            ) : null}
            {kevDate ? ` · ${kevDate}` : ""}
          </span>
        ) : (
          <span className="chip quiet">not in KEV</span>
        )}
        {d.poc_badge ? <span className="chip poc">public PoC</span> : <span className="chip quiet">no PoC</span>}
        {d.patch_available === true ? (
          <span className="chip">patch available</span>
        ) : d.patch_available === false ? (
          <span className="chip">no patch</span>
        ) : (
          <span className="chip quiet">patch unknown</span>
        )}
      </div>
      <div>
        <div className="seclabel">Summary</div>
        <p className="sum isolate">
          <Text value={d.summary} />
        </p>
      </div>
      {affected.length > 0 && (
        <div>
          <div className="seclabel">Affected</div>
          <ul className="prods">
            {affected.slice(0, AFFECTED_CAP).map((a, i) => (
              <li key={i} className="chip">
                <Text value={asText(a)} />
              </li>
            ))}
            {affected.length > AFFECTED_CAP && <li className="chip quiet">+{affected.length - AFFECTED_CAP} more</li>}
          </ul>
        </div>
      )}
      {stories.length > 0 && (
        <div>
          <div className="seclabel">Linked stories</div>
          <ul className="slinks">
            {stories.map((s, i) => (
              <li key={`${s.url}-${i}`} className="slink">
                <span className="s">
                  <Text value={s.source} /> · {relTime(s.published, now)}
                </span>
                <ExternalLink href={s.url} className="dlink">
                  <Text value={s.title} />
                </ExternalLink>
              </li>
            ))}
          </ul>
        </div>
      )}
      {geo.length > 0 && (
        <div>
          <div className="seclabel">Geo events</div>
          <ul className="gevs">
            {geo.map((ev, i) => (
              <GeoEvent key={i} ev={ev} now={now} />
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

/** Fetches the CVE and renders loading, 404, error-with-retry, or the detail. */
export function CveDetailView({ id }: { id: string }) {
  const q = useCve(id);
  if (q.isError) {
    if (q.error instanceof ApiError && q.error.status === 404) {
      return (
        <div className="dnote" role="alert">
          <p className="sum">CVE not found</p>
        </div>
      );
    }
    return (
      <div className="dnote" role="alert">
        <p className="sum">Couldn&apos;t load this CVE.</p>
        <button type="button" className="chip linked" onClick={() => void q.refetch()}>
          Retry
        </button>
      </div>
    );
  }
  if (!q.data) return <div className="dskeleton" role="status" aria-busy="true" aria-label="Loading CVE" />;
  return <CveDetailBody d={q.data} />;
}
