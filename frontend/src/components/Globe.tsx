/**
 * The MapLibre map: a choropleth of events per country from /api/geo, flat (mercator) by default
 * with a globe projection toggle. Lazy-loaded through LazyGlobe so MapLibre, the atlas and this
 * module stay out of the initial bundle. Renders into MapPanel's `.map-stage`.
 */
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { isIso3166Alpha2 } from "../lib/iso3166";
import { DEFAULT_RANGE, RANGE_LABEL, type RangeKey } from "../lib/range";
import { useGeo } from "../lib/queries";
import { useSelection } from "../lib/selection";
import type { GeoSummaryItem } from "../lib/types";
import { GlobeFallback } from "./GlobeChrome";
import { useGlobeRegistration } from "./GlobeContext";
import { centroids, countryName, countryTotals, describeGeo, withBuckets } from "./globeData";
import { type GlobeController, type GlobeFailure, type MapMode, mountGlobe } from "./globeMap";

const EMPTY: GeoSummaryItem[] = [];

interface Tip {
  iso2: string;
  x: number;
  y: number;
}

export default function Globe({ range = DEFAULT_RANGE, mode = "flat" }: { range?: RangeKey; mode?: MapMode }) {
  const geo = useGeo(range);
  const items = Array.isArray(geo.data) ? geo.data : EMPTY;
  const totals = useMemo(() => countryTotals(items), [items]);
  const state: "loading" | "error" | "ready" = geo.isPending ? "loading" : geo.isError && !geo.data ? "error" : "ready";
  const register = useGlobeRegistration();
  const summaryId = useId();
  const containerRef = useRef<HTMLDivElement>(null);
  const ctlRef = useRef<GlobeController | null>(null);
  const [failed, setFailed] = useState<GlobeFailure | null>(null);
  const [tip, setTip] = useState<Tip | null>(null);
  // The map is created once; it reads the latest `select` and `mode` through refs instead of remounting.
  const { select, country } = useSelection();
  const selectRef = useRef(select);
  const modeRef = useRef(mode);
  useEffect(() => {
    selectRef.current = select;
    modeRef.current = mode;
  });

  const data = useMemo(() => ({ countries: withBuckets(totals) }), [totals]);

  // Create the map once; tear everything down on unmount.
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    let unregister = () => {};
    const ctl = mountGlobe(el, {
      mode: modeRef.current,
      onLoad: () => {
        unregister = register((iso2) => {
          const c = centroids.get(iso2);
          if (c) ctl?.flyTo(c);
        });
      },
      // No WebGL 2, or the data never rendered (worker/source failure): static fallback,
      // never a crashed or blank page. The controller has already torn itself down.
      onError: (_err, reason) => setFailed(reason),
      onCountryClick: (cc) => {
        if (isIso3166Alpha2(cc)) selectRef.current({ kind: "country", cc });
      },
      onHover: (iso2, p) => setTip(iso2 && p ? { iso2, x: p.x, y: p.y } : null),
      describedBy: summaryId,
    });
    if (!ctl) return;
    ctlRef.current = ctl;
    return () => {
      unregister();
      ctlRef.current = null;
      ctl.destroy();
    };
  }, [register, summaryId]);

  // Data changes update the GeoJSON source in place (buffered until `load`).
  useEffect(() => {
    ctlRef.current?.setData(data);
  }, [data]);
  useEffect(() => {
    ctlRef.current?.setMode(mode);
  }, [mode]);
  useEffect(() => {
    ctlRef.current?.setSelected(country);
  }, [country]);

  const rangeLabel = RANGE_LABEL[range];
  if (failed) return <GlobeFallback totals={totals} state={state} reason={failed} rangeLabel={rangeLabel} />;

  const label =
    state === "loading"
      ? "Threat map: loading data"
      : state === "error"
        ? "Threat map: data unavailable"
        : describeGeo(totals, rangeLabel);
  const events = tip ? (totals.get(tip.iso2) ?? 0) : 0;

  return (
    <>
      {/* MapLibre's canvas (focusable, role=region) lives in here; it points at the summary below via
          aria-describedby, so no interactive element sits in a role=img. */}
      <div ref={containerRef} className="globe-map" />
      <p id={summaryId} className="sr-only">
        {label}
      </p>
      {tip && (
        <div className="tip" style={{ left: tip.x + 12, top: tip.y + 12 }}>
          {countryName(tip.iso2)} · {events} {events === 1 ? "event" : "events"}
        </div>
      )}
    </>
  );
}
