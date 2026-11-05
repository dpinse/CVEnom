/**
 * Globe chrome rendered as DOM (the map style has no glyphs, so no text is drawn in WebGL):
 * overlay title, legend, DB-IP attribution, the screen-reader hotspot list, and the static
 * fallback panel. Lives in the main bundle (no atlas, no MapLibre) so the fallback still works
 * if the lazy globe chunk itself fails to load.
 */
import type { GeoSummaryItem } from "../lib/types";
import { ExternalLink } from "../lib/text";
import { GEO_KINDS, KIND_LABEL, countryName, rankCountries, topHotspots } from "./geoSummary";

const fmt = (n: number) => (Number.isFinite(n) ? String(Math.round(n * 10) / 10) : "0");

export function GlobeTitle({ id }: { id?: string }) {
  return (
    <h2 id={id} className="globe-ov globe-title">
      Threat geography — <b>exploit scanning &amp; outages</b>
    </h2>
  );
}

/** Required by DB-IP Lite's CC-BY 4.0 licence (Plan 2): shown wherever geo data renders. */
export function GeoAttribution() {
  return (
    <ExternalLink href="https://db-ip.com" className="geo-attrib">
      IP geolocation by DB-IP.com
    </ExternalLink>
  );
}

export function GlobeLegend({ hint = true }: { hint?: boolean }) {
  return (
    <div className="globe-legend">
      {GEO_KINDS.map((k) => (
        <span key={k} className="lg-item">
          <i className={`swatch k-${k}`} aria-hidden="true" />
          {KIND_LABEL[k]}
        </span>
      ))}
      <span className="lg-item">
        <i className="swatch shade-ramp" aria-hidden="true" />
        outage severity
      </span>
      {hint && <span className="lg-hint">drag to rotate · ctrl + scroll to zoom</span>}
      <GeoAttribution />
    </div>
  );
}

/** Visually hidden list of the strongest (country, kind) hotspots. */
export function HotspotList({ items }: { items: readonly GeoSummaryItem[] }) {
  const top = topHotspots(items, 10);
  return (
    <ul className="sr-only" aria-label="Top threat hotspots">
      {top.map((it) => (
        <li key={`${it.country_code}:${it.kind}`}>
          {countryName(it.country_code)}: {KIND_LABEL[it.kind as keyof typeof KIND_LABEL]}, magnitude {fmt(Number(it.magnitude))},{" "}
          {fmt(Number(it.events))} events
        </li>
      ))}
    </ul>
  );
}

/** Static panel used when WebGL (or the globe chunk) is unavailable: legend + ranked countries. */
export function GlobeFallback({ items, state }: { items: readonly GeoSummaryItem[]; state: "ready" | "loading" | "error" }) {
  const ranked = rankCountries(items, 12);
  return (
    <div className="globe-fallback">
      <GlobeTitle />
      <p className="gf-note">
        Globe unavailable: this browser could not start WebGL 2, so the most active countries are listed instead.
      </p>
      {state === "loading" && <p className="gf-note">Loading geolocated activity…</p>}
      {state === "error" && <p className="gf-note">Geolocated activity is unavailable right now.</p>}
      {state === "ready" && ranked.length === 0 && (
        <p className="gf-note">No geolocated threat activity in the last 24 hours.</p>
      )}
      {ranked.length > 0 && (
        <ol className="gf-list" aria-label="Most active countries">
          {ranked.map((r) => (
            <li key={r.iso2}>
              <span className="gf-name">{r.name}</span>
              <span className="gf-kinds">
                {r.kinds.map((k) => (
                  <i key={k} className={`swatch k-${k}`} title={KIND_LABEL[k]} aria-hidden="true" />
                ))}
                <span className="sr-only">{r.kinds.map((k) => KIND_LABEL[k]).join(", ")}</span>
              </span>
              <span className="gf-mag mono">{fmt(r.magnitude)}</span>
            </li>
          ))}
        </ol>
      )}
      <GlobeLegend hint={false} />
    </div>
  );
}
