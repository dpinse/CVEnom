import { useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../lib/api";
import { DEFAULT_RANGE } from "../lib/range";
import { useCve } from "../lib/queries";
import { isIso3166Alpha2 } from "../lib/iso3166";
import { relTime } from "../lib/relTime";
import { cveOrgUrl, cweUrl, kevUrl, nvdUrl } from "../lib/refLinks";
import { useSelection } from "../lib/selection";
import { decodeEntities, ExternalLink, LinkRemoved, safeHref, Text } from "../lib/text";
import type { CveDetail, GeoEventOut } from "../lib/types";
import { useAuth } from "../lib/useAuth";
import { useNow } from "../lib/useNow";
import { countryName, isGeoKind, isIso2, KIND_LABEL } from "./geoSummary";
import { useGlobe } from "./GlobeContext";
import { severityOf, type Sev } from "./LaneRow";
import { isRansomwareSource, RansomwareCredit } from "./RansomwareCredit";

export const AFFECTED_CAP = 50;
export const DETAILS_CAP = 12;
/** The backend returns at most this many linked stories per CVE (`.limit(50)` in backend api/routes_read.py). */
export const BACKEND_STORIES_CAP = 50;

const SEV_LABEL: Record<Sev, string> = { crit: "Critical", high: "High", med: "Medium", low: "Low" };
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
  const { select } = useSelection();
  const entries = Object.entries(ev.details && typeof ev.details === "object" ? ev.details : {});
  const shown = entries.slice(0, DETAILS_CAP);
  return (
    <li className="gev">
      <div className="gev-top">
        <span className="chip">
          <Text value={kind} />
        </span>
        {cc &&
          (isIso3166Alpha2(cc) ? (
            <button type="button" className="chip linked gev-cc" onClick={() => select({ kind: "country", cc })}>
              {countryName(cc)}
            </button>
          ) : (
            <span className="gev-cc">{countryName(cc)}</span>
          ))}
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
  const { user, ready } = useAuth();
  const flown = useRef<string | null>(null);

  useEffect(() => {
    if (flown.current === d.cve_id) return;
    const cc = topCountry(d.geo_events ?? []);
    if (cc) {
      flown.current = d.cve_id;
      globe.flyTo(cc);
    }
  }, [d, globe]);

  const sev = severityOf(isNum(d.cvss) ? d.cvss : null);
  const sevLabel = d.cvss_severity ?? (isNum(d.cvss) ? SEV_LABEL[sev] : null);
  const epss = isNum(d.epss_percentile) ? d.epss_percentile : null;
  const epssTone = epss === null ? "low" : epss >= 0.5 ? "live" : epss >= 0.15 ? "high" : "low";
  const hasScores = isNum(d.cvss) || isNum(d.epss) || isNum(d.epss_percentile) || !!d.cvss_vector;
  const kevDate = fmtDate(d.kev_added);
  const dates = (
    [
      ["Published", fmtDate(d.published)],
      ["Last modified", fmtDate(d.last_modified)],
      ["KEV added", kevDate],
      ["CISA due", d.kev_due ? fmtDate(d.kev_due) || d.kev_due : ""],
    ] as [string, string][]
  ).filter(([, v]) => v !== "");
  const affected = d.affected ?? [];
  const cwes = (d.cwes ?? []).filter((c) => typeof c === "string");
  const refs = d.references ?? [];
  const stories = [...(d.stories ?? [])].sort(
    (a, b) => (Date.parse(b.published) || 0) - (Date.parse(a.published) || 0),
  );
  const geo = d.geo_events ?? [];
  const nvd = nvdUrl(d.cve_id);
  const kevLink = d.kev ? kevUrl(d.cve_id) : null;
  const cveOrg = cveOrgUrl(d.cve_id);
  // Anonymous callers get aggregate story counts that include sources only signed-in users can read.
  // Only once auth has settled (not a guest-looking flash), and not when the list is merely capped.
  const hiddenStories =
    ready &&
    user === null &&
    isNum(d.recent_story_count) &&
    d.recent_story_count > stories.length &&
    stories.length < BACKEND_STORIES_CAP;
  return (
    <>
      <div>
        <Link className="btn" to={`/threats/${encodeURIComponent(d.cve_id)}?range=${DEFAULT_RANGE}`}>
          Open threat page →
        </Link>
      </div>
      <div className="dhdr">
        {d.kev_name ? (
          <p className="dname">
            <Text value={d.kev_name} />
          </p>
        ) : null}
        <div className="chips">
          {sevLabel ? (
            <span className="chip" data-tone={sev}>
              <Text value={sevLabel} />
            </span>
          ) : null}
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
          {d.kev_ransomware === true && <span className="chip kev">ransomware use</span>}
          {d.poc_badge ? <span className="chip poc">public PoC</span> : <span className="chip quiet">no PoC</span>}
          {d.patch_available === true ? (
            <span className="chip">patch available</span>
          ) : d.patch_available === false ? (
            <span className="chip">no patch</span>
          ) : (
            <span className="chip quiet">patch unknown</span>
          )}
        </div>
        {d.kev && (
          <div className="dmeta">
            <span className="wild">
              <i className="strobe" aria-hidden="true" />
              in the wild
            </span>
          </div>
        )}
      </div>
      {d.summary ? (
        <div>
          <div className="seclabel">Summary</div>
          <p className="sum isolate">
            <Text value={d.summary} />
          </p>
        </div>
      ) : null}
      {hasScores && (
        <div>
          <div className="seclabel">Scores</div>
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
          {d.cvss_vector ? (
            <p className="dmuted mono" data-testid="cvss-vector">
              <Text value={d.cvss_vector} />
            </p>
          ) : null}
          {isNum(d.epss) ? <p className="dmuted mono">EPSS score {d.epss.toFixed(3)}</p> : null}
        </div>
      )}
      {dates.length > 0 && (
        <div>
          <div className="seclabel">Key dates</div>
          <dl className="kv">
            {dates.map(([k, v]) => (
              <div key={k} className="kv-row">
                <dt>{k}</dt>
                <dd>{v}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
      {d.kev_action ? (
        <div>
          <div className="seclabel">Required action</div>
          <p className="sum">
            <Text value={d.kev_action} />
          </p>
          {d.kev_notes ? (
            <p className="dmuted">
              <Text value={d.kev_notes} />
            </p>
          ) : null}
        </div>
      ) : null}
      {affected.length > 0 && (
        <div>
          <div className="seclabel">Affected products</div>
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
      {cwes.length > 0 && (
        <div>
          <div className="seclabel">Weaknesses</div>
          <ul className="prods">
            {cwes.map((c, i) => (
              <li key={`${c}#${i}`} className="chip">
                <ExternalLink href={cweUrl(c) ?? ""} className="dlink">
                  <Text value={c} />
                </ExternalLink>
              </li>
            ))}
          </ul>
        </div>
      )}
      {refs.length > 0 && (
        <div>
          <div className="seclabel">References</div>
          <ul className="refs">
            {refs.map((r, i) => {
              // Stored URLs are entity-escaped: decode exactly once, then validate. An unsafe URL is never shown.
              const safe = safeHref(decodeEntities(r.url));
              return (
                <li key={`${r.url}#${i}`} className="ref">
                  {safe ? (
                    <ExternalLink href={safe} className="dlink">
                      {new URL(safe).hostname}
                    </ExternalLink>
                  ) : (
                    <LinkRemoved />
                  )}
                  {(r.tags ?? []).map((t, j) => (
                    <span key={`${t}#${j}`} className="chip quiet">
                      <Text value={t} />
                    </span>
                  ))}
                </li>
              );
            })}
          </ul>
        </div>
      )}
      {(stories.length > 0 || hiddenStories) && (
        <div>
          <div className="seclabel">Related stories</div>
          <ul className="slinks">
            {stories.map((s, i) => (
              <li key={`${s.url}-${i}`} className="slink">
                <span className="s">
                  <Text value={s.source} /> · {relTime(s.published, now)}
                </span>
                <div>
                  <ExternalLink href={s.url} className="dlink">
                    <Text value={s.title} />
                  </ExternalLink>
                  {isRansomwareSource(s.source) && <RansomwareCredit className="block" />}
                </div>
              </li>
            ))}
          </ul>
          {hiddenStories && (
            <p className="dmuted" data-testid="anon-story-note">
              Some sources are visible to signed-in users only.
            </p>
          )}
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
      <div>
        <div className="seclabel">Links</div>
        <ul className="stdlinks">
          {nvd && (
            <li>
              <ExternalLink href={nvd} className="dlink">
                NVD
              </ExternalLink>
            </li>
          )}
          {kevLink && (
            <li>
              <ExternalLink href={kevLink} className="dlink">
                CISA KEV
              </ExternalLink>
            </li>
          )}
          {cveOrg && (
            <li>
              <ExternalLink href={cveOrg} className="dlink">
                cve.org
              </ExternalLink>
            </li>
          )}
        </ul>
      </div>
    </>
  );
}

/** Fetches the CVE and renders loading, 404, error-with-retry, or the detail. */
export function CveDetailView({ id }: { id: string }) {
  const q = useCve(id, DEFAULT_RANGE);
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
