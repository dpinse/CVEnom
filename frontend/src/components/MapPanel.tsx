import { useCallback, useMemo, useState } from "react";
import { useGeo } from "../lib/queries";
import { RANGE_LABEL, type RangeKey } from "../lib/range";
import { CountryPanel } from "./CountryPanel";
import { MapLegend } from "./GlobeChrome";
import { countryTotals } from "./geoSummary";
import type { MapMode } from "./globeMap";
import { LazyGlobe } from "./LazyGlobe";

const STORAGE_KEY = "cvenom.mapMode";
const MODES: readonly MapMode[] = ["flat", "globe"];

/** Flat (mercator) unless the viewer chose the globe; blocked or throwing storage means flat. */
export function useMapMode(): [MapMode, (m: MapMode) => void] {
  const [mode, setMode] = useState<MapMode>(() => {
    try {
      const v = localStorage.getItem(STORAGE_KEY);
      return MODES.includes(v as MapMode) ? (v as MapMode) : "flat";
    } catch {
      return "flat";
    }
  });
  const set = useCallback((m: MapMode) => {
    setMode(m);
    try {
      localStorage.setItem(STORAGE_KEY, m);
    } catch {
      /* storage unavailable: the choice holds for this visit */
    }
  }, []);
  return [mode, set];
}

/** Map (flat or globe, choropleth) on the left, the country side panel on the right; stacks under 820px. */
export function MapPanel({ range }: { range: RangeKey }) {
  const [mode, setMode] = useMapMode();
  const geo = useGeo(range);
  const active = useMemo(() => {
    let n = 0;
    for (const v of countryTotals(Array.isArray(geo.data) ? geo.data : []).values()) if (v > 0) n++;
    return n;
  }, [geo.data]);
  return (
    <section className="panel mapgrid" aria-label="Threat geography">
      <div className={`map-stage${mode === "globe" ? " globe" : ""}`}>
        <div className="map-tools">
          <div className="seg" role="group" aria-label="Map projection">
            {MODES.map((m) => (
              <button key={m} type="button" aria-pressed={m === mode} onClick={() => setMode(m)}>
                {m === "flat" ? "Flat" : "Globe"}
              </button>
            ))}
          </div>
        </div>
        <LazyGlobe range={range} mode={mode} />
        <MapLegend countries={active} rangeLabel={RANGE_LABEL[range]} />
      </div>
      <CountryPanel range={range} />
    </section>
  );
}
