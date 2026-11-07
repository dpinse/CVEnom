/**
 * Map chrome rendered as DOM (the map style has no glyphs, so no text is drawn in WebGL):
 * choropleth legend, DB-IP attribution and the static fallback panel. Lives in the main bundle (no atlas, no MapLibre) so the fallback still works
 * if the lazy globe chunk itself fails to load.
 */
import type { CSSProperties } from "react";
import { ExternalLink } from "../lib/text";
import { CHORO_STEPS, type GeoKind, KIND_TOKEN, rankCountries } from "./geoSummary";

/**
 * Colour swatch for a hotspot kind. The colour comes from KIND_TOKEN, the same mapping the map
 * paint uses, set as a CSS custom property through the CSSOM (CSP-safe, no style attribute).
 */
export function KindSwatch({ kind, title }: { kind: GeoKind; title?: string }) {
  const style = { "--swatch": `var(${KIND_TOKEN[kind]})` } as CSSProperties;
  return <i className="swatch" data-kind={kind} style={style} title={title} aria-hidden="true" />;
}

/** Why the static panel is showing. */
export type FallbackReason = "webgl" | "module" | "render";

const FALLBACK_NOTE: Record<FallbackReason, string> = {
  webgl: "Map unavailable: couldn't start WebGL 2 in this browser, so the most active countries are listed instead.",
  module: "Map unavailable: couldn't load the map module, so the most active countries are listed instead.",
  render: "Map unavailable: the map couldn't render its data, so the most active countries are listed instead.",
};

/** Required by DB-IP Lite's CC-BY 4.0 licence (Plan 2): shown wherever geo data renders. */
export function GeoAttribution() {
  return (
    <ExternalLink href="https://db-ip.com" className="geo-attrib">
      IP geolocation by DB-IP.com
    </ExternalLink>
  );
}

/** `fewer [5 swatches] more alerts · N countries · <range>` plus the DB-IP attribution (the mockup's legend). */
export function MapLegend({ countries, rangeLabel }: { countries: number; rangeLabel: string }) {
  return (
    <div className="map-legend">
      <span>fewer</span>
      <span className="steps" aria-hidden="true">
        {CHORO_STEPS.map((p) => (
          <i key={p} style={{ "--p": `${Math.round(p * 100)}%` } as CSSProperties} />
        ))}
      </span>
      <span>
        more alerts · {countries} {countries === 1 ? "country" : "countries"} · {rangeLabel}
      </span>
      <GeoAttribution />
    </div>
  );
}

/** Static list used when WebGL (or the map chunk) is unavailable: the most active countries, ranked by events. */
export function GlobeFallback({
  totals,
  state,
  reason,
  rangeLabel,
}: {
  totals: ReadonlyMap<string, number>;
  state: "ready" | "loading" | "error";
  reason: FallbackReason;
  rangeLabel: string;
}) {
  const ranked = rankCountries(totals, 12);
  return (
    <div className="globe-fallback">
      <p className="gf-note">{FALLBACK_NOTE[reason]}</p>
      {state === "loading" && <p className="gf-note">Loading geolocated activity…</p>}
      {state === "error" && <p className="gf-note">Geolocated activity is unavailable right now.</p>}
      {state === "ready" && ranked.length === 0 && (
        <p className="gf-note">No geolocated threat activity in the last {rangeLabel}.</p>
      )}
      {ranked.length > 0 && (
        <ol className="gf-list" aria-label="Most active countries">
          {ranked.map((r) => (
            <li key={r.iso2}>
              <span className="gf-name">{r.name}</span>
              <span className="gf-mag mono">{r.events}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
