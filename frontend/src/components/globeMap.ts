/**
 * Imperative MapLibre controller behind <Globe>. Lazy chunk only.
 *
 * CSP: MapLibre v6 ships ESM only (dist/maplibre-gl.mjs + dist/maplibre-gl-worker.mjs); the
 * separate v4/v5 "-csp" bundles are gone because v6 never evals or builds a blob worker for a
 * same-origin worker URL. We point setWorkerUrl at the worker file emitted by Vite (`?url`)
 * under /assets, so MapLibre does `new Worker(<same-origin url>, {type: "module"})`: works
 * under `script-src 'self'; worker-src 'self'` with no 'unsafe-eval' and no blob:.
 *
 * Style: built in code from the CSS design tokens. version 8, no glyphs, no sprite, no remote
 * sources; the only sources are in-memory GeoJSON added after the map's `load` event. There
 * are no symbol/text layers (legend and title are DOM overlays).
 */
import {
  Map as MlMap,
  setWorkerUrl,
  type ExpressionSpecification,
  type GeoJSONSource,
  type LayerSpecification,
  type StyleSpecification,
} from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import workerUrl from "maplibre-gl/dist/maplibre-gl-worker.mjs?url";
import type { FeatureCollection, Geometry } from "geojson";
import { SHADE_ALPHA, mixColor } from "./geoSummary";

// ---- tokens -----------------------------------------------------------------------

export interface GlobeTokens {
  ocean: string;
  land: string;
  border: string;
  sevHigh: string;
  sevCrit: string;
  sevMed: string;
  live: string;
  scope: string;
}

const TOKEN_NAMES: Record<keyof GlobeTokens, string> = {
  ocean: "--ocean",
  land: "--land",
  border: "--border-geo",
  sevHigh: "--sev-high",
  sevCrit: "--sev-crit",
  sevMed: "--sev-med",
  live: "--live",
  scope: "--scope",
};

/** Dark-theme values from tokens.css; used only if a custom property cannot be read. */
const FALLBACK: GlobeTokens = {
  ocean: "#0a1521",
  land: "#2b3f54",
  border: "#4d7093",
  sevHigh: "#ff9a44",
  sevCrit: "#ff5663",
  sevMed: "#ecc14a",
  live: "#ff2f45",
  scope: "#6fb0d4",
};

/** Read the geo/signal tokens from <html>'s computed style (theme-aware). */
export function readGlobeTokens(): GlobeTokens {
  let cs: CSSStyleDeclaration | null = null;
  try {
    cs = window.getComputedStyle(document.documentElement);
  } catch {
    cs = null;
  }
  const out = { ...FALLBACK };
  for (const key of Object.keys(TOKEN_NAMES) as (keyof GlobeTokens)[]) {
    const v = cs?.getPropertyValue(TOKEN_NAMES[key]).trim();
    if (v) out[key] = v;
  }
  return out;
}

// ---- style ------------------------------------------------------------------------

/** Country fill: --land, tinted by outage level with increasing alpha of --sev-high. */
export function fillColor(t: GlobeTokens): ExpressionSpecification {
  return [
    "match",
    ["get", "level"],
    1,
    mixColor(t.land, t.sevHigh, SHADE_ALPHA[1]),
    2,
    mixColor(t.land, t.sevHigh, SHADE_ALPHA[2]),
    3,
    mixColor(t.land, t.sevHigh, SHADE_ALPHA[3]),
    t.land,
  ];
}

/** Hotspot colour by kind. */
export function circleColor(t: GlobeTokens): ExpressionSpecification {
  return ["match", ["get", "kind"], "scan", t.live, "outage", t.sevHigh, "victim", t.sevCrit, "c2", t.sevMed, "bgp", t.scope, t.scope];
}

/** The initial style: background (ocean) only. Data sources/layers are added on `load`. */
export function baseStyle(t: GlobeTokens): StyleSpecification {
  return {
    version: 8,
    projection: { type: "globe" },
    sources: {},
    layers: [{ id: "background", type: "background", paint: { "background-color": t.ocean } }],
  };
}

export function dataLayers(t: GlobeTokens): LayerSpecification[] {
  return [
    { id: "countries", type: "fill", source: "countries", paint: { "fill-color": fillColor(t) } },
    {
      id: "borders",
      type: "line",
      source: "countries",
      paint: { "line-color": t.border, "line-width": 0.5, "line-opacity": 0.9 },
    },
    {
      id: "hotspots",
      type: "circle",
      source: "hotspots",
      layout: { "circle-sort-key": ["-", 0, ["get", "r"]] },
      paint: {
        "circle-radius": ["get", "r"],
        "circle-color": circleColor(t),
        "circle-opacity": 0.45,
        "circle-stroke-color": circleColor(t),
        "circle-stroke-width": 1.25,
        "circle-stroke-opacity": 0.95,
        "circle-pitch-alignment": "map",
      },
    },
  ];
}

// ---- controller ---------------------------------------------------------------------

/** Auto-rotate speed (degrees of longitude per second at full speed). */
export const ROTATE_DEG_PER_S = 3;
/** Resume auto-rotate after this long without user interaction. */
export const IDLE_RESUME_MS = 4000;
/** Ease the rotation speed in over this long after resuming. */
const RAMP_MS = 1200;
const START_CENTER: [number, number] = [-30, 22];

/**
 * Zoom at which the globe fills ~85% of the container's shorter side. (MapLibre's globe renders
 * smaller than the Mercator world size at the same zoom; 0.5 was tuned against Firefox output.)
 */
export function fitZoom(el: HTMLElement): number {
  const side = Math.min(el.clientWidth, el.clientHeight);
  if (!side) return 1.5;
  const radiusPx = 0.5 * side;
  return Math.max(0, Math.min(3, Math.log2((radiusPx * 2 * Math.PI) / 512)));
}

export interface GlobeData {
  countries: FeatureCollection<Geometry>;
  hotspots: FeatureCollection<Geometry>;
}

export interface GlobeController {
  setData(d: GlobeData): void;
  /** Ease to [lon, lat] and hold rotation until the user next interacts. */
  flyTo(center: [number, number]): void;
  destroy(): void;
}

export interface MountOptions {
  /** Called once, after `load`, when sources and layers exist. */
  onLoad?: () => void;
  /** Called if MapLibre cannot initialise (e.g. no WebGL 2); the caller shows the static fallback. */
  onError?: (err: unknown) => void;
}

const smooth = (x: number) => x * x * (3 - 2 * x);

/**
 * Create the map in `container`. Never throws: an init failure (no WebGL 2, worker or style
 * error thrown by the constructor) is reported through `onError` and returns null.
 */
export function mountGlobe(container: HTMLElement, opts: MountOptions = {}): GlobeController | null {
  try {
    return createGlobe(container, opts);
  } catch (err) {
    opts.onError?.(err);
    return null;
  }
}

function createGlobe(container: HTMLElement, opts: MountOptions): GlobeController {
  setWorkerUrl(workerUrl);
  let tokens = readGlobeTokens();

  const map = new MlMap({
    container,
    style: baseStyle(tokens),
    center: START_CENTER,
    zoom: fitZoom(container),
    minZoom: 0,
    maxZoom: 6,
    attributionControl: false,
    maplibreLogo: false,
    // Scroll zoom is off by default so the page scrolls past the globe; the wheel listener
    // below turns it on per-event for Ctrl/Cmd+wheel or while the globe has focus.
    scrollZoom: false,
    // North stays up: no bearing/pitch rotation, only drag-to-pan (which spins the globe).
    dragRotate: false,
    pitchWithRotate: false,
    touchPitch: false,
    boxZoom: false,
    fadeDuration: 0,
    canvasContextAttributes: { antialias: true },
  });
  map.touchZoomRotate?.disableRotation?.();

  let loaded = false;
  let destroyed = false;
  let pending: GlobeData | null = null;
  let userZoomed = false;
  let scrollZoomOn = false;

  // ---- rotation state ----
  let raf = 0;
  let lastT: number | null = null;
  let resumeAt: number | null = null;
  let lastInteraction = Number.NEGATIVE_INFINITY;
  let pointerDown = false;
  let held = false; // set by flyTo; cleared by the next user interaction
  let visible = typeof document === "undefined" || document.visibilityState !== "hidden";
  let inView = true;
  const motionMq = safeMatchMedia("(prefers-reduced-motion: reduce)");
  let reduced = !!motionMq?.matches;

  const canRun = () => loaded && !destroyed && !reduced && visible && inView;

  function stop() {
    if (raf) cancelAnimationFrame(raf);
    raf = 0;
    lastT = null;
    resumeAt = null;
  }
  function schedule() {
    if (!raf && canRun()) raf = requestAnimationFrame(tick);
  }
  function tick(t: number) {
    raf = 0;
    if (!canRun()) {
      lastT = null;
      return;
    }
    const dt = lastT === null ? 0 : Math.min(0.1, Math.max(0, (t - lastT) / 1000));
    lastT = t;
    const idle = !pointerDown && !held && t - lastInteraction >= IDLE_RESUME_MS;
    if (idle) {
      resumeAt ??= t;
      const speed = ROTATE_DEG_PER_S * smooth(Math.min(1, (t - resumeAt) / RAMP_MS));
      if (dt > 0 && speed > 0) {
        const c = map.getCenter();
        map.jumpTo({ center: [c.lng + speed * dt, c.lat] });
      }
    } else {
      resumeAt = null;
    }
    schedule();
  }

  function touch() {
    lastInteraction = performance.now();
    held = false;
  }
  const onDown = () => {
    pointerDown = true;
    touch();
  };
  const onUp = () => {
    if (!pointerDown) return;
    pointerDown = false;
    touch();
  };
  const onUserMove = (e: { originalEvent?: unknown }) => {
    if (e?.originalEvent) touch();
  };
  const onUserZoom = (e: { originalEvent?: unknown }) => {
    if (e?.originalEvent) {
      userZoomed = true;
      touch();
    }
  };
  map.on("mousedown", onDown);
  map.on("touchstart", onDown);
  map.on("mouseup", onUp);
  map.on("touchend", onUp);
  map.on("touchcancel", onUp);
  map.on("dragend", onUp);
  map.on("move", onUserMove);
  map.on("zoomstart", onUserZoom);
  window.addEventListener("pointerup", onUp, true);
  container.addEventListener("keydown", touch);

  const onWheel = (e: WheelEvent) => {
    const focused = container.contains(document.activeElement);
    const want = e.ctrlKey || e.metaKey || focused;
    if (want) touch(); // a plain page scroll over the globe is not an interaction with it
    if (want && !scrollZoomOn) map.scrollZoom.enable();
    else if (!want && scrollZoomOn) map.scrollZoom.disable();
    scrollZoomOn = want;
  };
  // Capture phase on the container runs before MapLibre's own wheel handler on its canvas.
  container.addEventListener("wheel", onWheel, { capture: true, passive: true });

  const onVisibility = () => {
    visible = document.visibilityState !== "hidden";
    if (visible) schedule();
    else stop();
  };
  document.addEventListener("visibilitychange", onVisibility);

  const onMotion = () => {
    reduced = !!motionMq?.matches;
    if (reduced) stop();
    else schedule();
  };
  motionMq?.addEventListener?.("change", onMotion);

  let io: IntersectionObserver | null = null;
  if (typeof IntersectionObserver !== "undefined") {
    io = new IntersectionObserver((entries) => {
      inView = entries.some((e) => e.isIntersecting);
      if (inView) schedule();
      else stop();
    });
    io.observe(container);
  }

  let ro: ResizeObserver | null = null;
  if (typeof ResizeObserver !== "undefined") {
    ro = new ResizeObserver(() => {
      if (destroyed) return;
      map.resize();
      if (!userZoomed) map.setZoom(fitZoom(container));
    });
    ro.observe(container);
  }

  // ---- theme ----
  function applyTheme() {
    if (!loaded || destroyed) return;
    tokens = readGlobeTokens();
    map.setPaintProperty("background", "background-color", tokens.ocean);
    map.setPaintProperty("countries", "fill-color", fillColor(tokens));
    map.setPaintProperty("borders", "line-color", tokens.border);
    map.setPaintProperty("hotspots", "circle-color", circleColor(tokens));
    map.setPaintProperty("hotspots", "circle-stroke-color", circleColor(tokens));
  }
  const mo = new MutationObserver(applyTheme);
  mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  const schemeMq = safeMatchMedia("(prefers-color-scheme: light)");
  schemeMq?.addEventListener?.("change", applyTheme);

  // ---- data ----
  function pushData(d: GlobeData) {
    (map.getSource("countries") as GeoJSONSource | undefined)?.setData(d.countries);
    (map.getSource("hotspots") as GeoJSONSource | undefined)?.setData(d.hotspots);
  }

  map.on("load", () => {
    if (destroyed) return;
    loaded = true;
    tokens = readGlobeTokens();
    const d = pending ?? { countries: { type: "FeatureCollection", features: [] }, hotspots: { type: "FeatureCollection", features: [] } };
    map.addSource("countries", { type: "geojson", data: d.countries });
    map.addSource("hotspots", { type: "geojson", data: d.hotspots });
    for (const layer of dataLayers(tokens)) map.addLayer(layer);
    // Tokens may have changed between construction and load (theme toggled early).
    map.setPaintProperty("background", "background-color", tokens.ocean);
    opts.onLoad?.();
    schedule();
  });

  return {
    setData(d) {
      pending = d;
      if (loaded && !destroyed) pushData(d);
    },
    flyTo(center) {
      if (!loaded || destroyed) return;
      held = true;
      map.easeTo({ center, duration: reduced ? 0 : 1600, essential: true });
    },
    destroy() {
      if (destroyed) return;
      destroyed = true;
      stop();
      mo.disconnect();
      ro?.disconnect();
      io?.disconnect();
      schemeMq?.removeEventListener?.("change", applyTheme);
      motionMq?.removeEventListener?.("change", onMotion);
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("pointerup", onUp, true);
      container.removeEventListener("keydown", touch);
      container.removeEventListener("wheel", onWheel, { capture: true });
      map.remove();
    },
  };
}

function safeMatchMedia(q: string): MediaQueryList | null {
  try {
    return typeof window.matchMedia === "function" ? window.matchMedia(q) : null;
  } catch {
    return null;
  }
}
