/**
 * Entry point for the globe. `React.lazy` keeps MapLibre, the atlas and the globe code in a
 * separate chunk fetched (from self) only when the globe mounts. An error boundary turns a
 * failed chunk load or render error into the static fallback panel instead of a blank page.
 */
import { Component, Suspense, lazy, type ReactNode } from "react";
import { useGeo } from "../lib/queries";
import { type FallbackReason, GlobeFallback, GlobeLegend, GlobeTitle } from "./GlobeChrome";

const Globe = lazy(() => import("./Globe"));

function FallbackWithData({ reason }: { reason: FallbackReason }) {
  const geo = useGeo(24);
  const items = Array.isArray(geo.data) ? geo.data : [];
  const state = geo.isPending ? "loading" : geo.isError && !geo.data ? "error" : "ready";
  return (
    <section className="globe-stage" aria-label="Threat geography">
      <GlobeFallback items={items} state={state} reason={reason} />
    </section>
  );
}

/**
 * Catches a failed lazy import of the globe chunk (or a render error inside it) and shows the
 * static panel with the "couldn't load the map module" note. Exported for tests.
 */
export class GlobeBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? <FallbackWithData reason="module" /> : this.props.children;
  }
}

/** Same footprint as the globe while its chunk loads, so the layout does not jump. */
function GlobePlaceholder() {
  return (
    <section className="globe-stage" aria-label="Threat geography">
      <div className="globe-well">
        <div className="globe-map" />
        <p className="sr-only">Global threat map: loading</p>
        <GlobeTitle />
        <div className="globe-ov globe-ov-bottom">
          <GlobeLegend />
        </div>
      </div>
    </section>
  );
}

export function LazyGlobe() {
  return (
    <GlobeBoundary>
      <Suspense fallback={<GlobePlaceholder />}>
        <Globe />
      </Suspense>
    </GlobeBoundary>
  );
}
