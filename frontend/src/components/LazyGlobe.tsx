/**
 * Entry point for the map. `React.lazy` keeps MapLibre, the atlas and the map code in a
 * separate chunk fetched (from self) only when the map mounts. An error boundary turns a
 * failed chunk load or render error into the static fallback list instead of a blank page.
 */
import { Component, Suspense, lazy, useMemo, type ReactNode } from "react";
import { DEFAULT_RANGE, RANGE_LABEL, type RangeKey } from "../lib/range";
import { useGeo } from "../lib/queries";
import { type FallbackReason, GlobeFallback } from "./GlobeChrome";
import { countryTotals } from "./geoSummary";
import type { MapMode } from "./globeMap";

const Globe = lazy(() => import("./Globe"));

function FallbackWithData({ reason, range }: { reason: FallbackReason; range: RangeKey }) {
  const geo = useGeo(range);
  const totals = useMemo(() => countryTotals(Array.isArray(geo.data) ? geo.data : []), [geo.data]);
  const state = geo.isPending ? "loading" : geo.isError && !geo.data ? "error" : "ready";
  return <GlobeFallback totals={totals} state={state} reason={reason} rangeLabel={RANGE_LABEL[range]} />;
}

/**
 * Catches a failed lazy import of the map chunk (or a render error inside it) and shows the
 * static list with the "couldn't load the map module" note. Exported for tests.
 */
export class GlobeBoundary extends Component<{ children: ReactNode; range?: RangeKey }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? (
      <FallbackWithData reason="module" range={this.props.range ?? DEFAULT_RANGE} />
    ) : (
      this.props.children
    );
  }
}

/** Same footprint as the map while its chunk loads, so the layout does not jump. */
function GlobePlaceholder() {
  return (
    <>
      <div className="globe-map" />
      <p className="sr-only">Threat map: loading</p>
    </>
  );
}

export function LazyGlobe({ range = DEFAULT_RANGE, mode = "flat" }: { range?: RangeKey; mode?: MapMode }) {
  return (
    <GlobeBoundary range={range}>
      <Suspense fallback={<GlobePlaceholder />}>
        <Globe range={range} mode={mode} />
      </Suspense>
    </GlobeBoundary>
  );
}
