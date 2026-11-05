/**
 * The MapLibre globe centerpiece: outage shading per country and threat hotspots per
 * (country, kind) from /api/geo (last 24 h). Lazy-loaded through LazyGlobe so MapLibre, the
 * atlas and this module stay out of the initial bundle.
 */
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useGeo } from "../lib/queries";
import type { GeoSummaryItem } from "../lib/types";
import { GlobeFallback, GlobeLegend, GlobeTitle, HotspotList } from "./GlobeChrome";
import { useGlobeRegistration } from "./GlobeContext";
import { centroids, describeGeo, toCountryShading, toHotspots, withShading } from "./globeData";
import { type GlobeController, mountGlobe } from "./globeMap";

const EMPTY: GeoSummaryItem[] = [];

export default function Globe() {
  const geo = useGeo(24);
  const items = Array.isArray(geo.data) ? geo.data : EMPTY;
  const state: "loading" | "error" | "ready" = geo.isPending ? "loading" : geo.isError && !geo.data ? "error" : "ready";
  const register = useGlobeRegistration();
  const titleId = useId();
  const containerRef = useRef<HTMLDivElement>(null);
  const ctlRef = useRef<GlobeController | null>(null);
  const [failed, setFailed] = useState(false);

  const data = useMemo(() => ({ countries: withShading(toCountryShading(items)), hotspots: toHotspots(items) }), [items]);

  // Create the map once; tear everything down on unmount.
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    let unregister = () => {};
    const ctl = mountGlobe(el, {
      onLoad: () => {
        unregister = register((iso2) => {
          const c = centroids.get(iso2);
          if (c) ctl?.flyTo(c);
        });
      },
      // No WebGL 2 (or any other init failure): static fallback, never a crashed page.
      onError: () => setFailed(true),
    });
    if (!ctl) return;
    ctlRef.current = ctl;
    return () => {
      unregister();
      ctlRef.current = null;
      ctl.destroy();
    };
  }, [register]);

  // Data changes update the GeoJSON sources in place (buffered until `load`).
  useEffect(() => {
    ctlRef.current?.setData(data);
  }, [data]);

  if (failed) {
    return (
      <section className="globe-stage" aria-label="Threat geography">
        <GlobeFallback items={items} state={state} />
      </section>
    );
  }

  const label =
    state === "loading"
      ? "Global threat map: loading data"
      : state === "error"
        ? "Global threat map: data unavailable"
        : describeGeo(items);

  return (
    <section className="globe-stage" aria-labelledby={titleId}>
      <div className="globe-well">
        <div ref={containerRef} className="globe-map" role="img" aria-label={label} />
        <GlobeTitle id={titleId} />
        <div className="globe-ov globe-ov-bottom">
          <GlobeLegend />
        </div>
        <HotspotList items={items} />
      </div>
    </section>
  );
}
