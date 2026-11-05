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
import { GEO_KINDS, type GeoKind, KIND_TOKEN, SHADE_ALPHA, mixColor } from "./geoSummary";

// ---- tokens -----------------------------------------------------------------------

export interface GlobeTokens {
  ocean: string;
  land: string;
  border: string;
  /** Resolved colour per hotspot kind, via the shared KIND_TOKEN mapping. */
  kind: Record<GeoKind, string>;
}

/** Dark-theme values from tokens.css; used only if a custom property cannot be read. */
const FALLBACK: Readonly<Record<string, string>> = {
  "--ocean": "#0a1521",
  "--land": "#2b3f54",
  "--border-geo": "#4d7093",
  "--sev-high": "#ff9a44",
  "--sev-med": "#ecc14a",
  "--sev-low": "#3dd79a",
  "--live": "#ff2f45",
  "--scope": "#6fb0d4",
};

/** Read the geo/signal tokens from <html>'s computed style (theme-aware). */
export function readGlobeTokens(): GlobeTokens {
  let cs: CSSStyleDeclaration | null = null;
  try {
    cs = window.getComputedStyle(document.documentElement);
  } catch {
    cs = null;
  }
  const read = (name: string) => cs?.getPropertyValue(name).trim() || FALLBACK[name] || "#888888";
  const kind = {} as Record<GeoKind, string>;
  for (const k of GEO_KINDS) kind[k] = read(KIND_TOKEN[k]);
  return { ocean: read("--ocean"), land: read("--land"), border: read("--border-geo"), kind };
}

// ---- style ------------------------------------------------------------------------

/** Country fill: --land, tinted by outage level with increasing alpha of the outage colour. */
export function fillColor(t: GlobeTokens): ExpressionSpecification {
  const over = t.kind.outage;
  return [
    "match",
    ["get", "level"],
    1,
    mixColor(t.land, over, SHADE_ALPHA[1]),
    2,
    mixColor(t.land, over, SHADE_ALPHA[2]),
    3,
    mixColor(t.land, over, SHADE_ALPHA[3]),
    t.land,
  ];
}

/** Hotspot colour by kind, generated from KIND_TOKEN (the same mapping the legend uses). */
export function circleColor(t: GlobeTokens): ExpressionSpecification {
  const [first, ...rest] = GEO_KINDS;
  return ["match", ["get", "kind"], first, t.kind[first], ...rest.flatMap((k) => [k, t.kind[k]]), t.kind.scan];
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
/** Active rotation is capped at ~30 fps: frames closer together than this are skipped. */
export const ROTATE_FRAME_MS = 1000 / 30;
/** If the countries source has not rendered this long after `load`, show the fallback. */
export const DATA_DEADLINE_MS = 6000;
/** After a map `error` event, allow this long for the countries source to render anyway. */
export const ERROR_GRACE_MS = 1500;
/** Ease the rotation speed in over this long after resuming. */
const RAMP_MS = 1200;
const START_CENTER: [number, number] = [-30, 22];

/** Accessible name of MapLibre's (focusable) canvas; the data summary is linked via aria-describedby. */
export const CANVAS_LABEL =
  "Interactive threat globe. Drag or use the arrow keys to rotate; Ctrl or Cmd with scroll, or the plus and minus keys, to zoom.";

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

/** Why the globe gave up: WebGL/init failed, or the map started but its data never rendered. */
export type GlobeFailure = "webgl" | "render";

export interface MountOptions {
  /** Called once, after `load`, when sources and layers exist. */
  onLoad?: () => void;
  /**
   * Called (once) when the globe cannot be shown; the caller renders the static fallback.
   * For "render" failures the controller has already torn the map down.
   */
  onError?: (err: unknown, reason: GlobeFailure) => void;
  /** id of the element holding the data summary, linked from the canvas via aria-describedby. */
  describedBy?: string;
}

const smooth = (x: number) => x * x * (3 - 2 * x);

/**
 * Create the map in `container`. Never throws: an init failure (no WebGL 2, or anything else
 * the constructor throws) is reported through `onError(err, "webgl")` and returns null.
 */
export function mountGlobe(container: HTMLElement, opts: MountOptions = {}): GlobeController | null {
  try {
    return createGlobe(container, opts);
  } catch (err) {
    opts.onError?.(err, "webgl");
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
    // Scroll zoom is off so a plain wheel always scrolls the page; the wheel listener below
    // enables it per event only for Ctrl/Cmd+wheel (the on-screen hint). Keyboard +/- zoom
    // stays available while the canvas has focus.
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

  // The canvas is MapLibre's focusable keyboard target (role=region). Give it a meaningful name
  // and point it at the live data summary instead of nesting it inside a role=img.
  const canvas = map.getCanvas?.();
  canvas?.setAttribute("aria-label", CANVAS_LABEL);
  if (opts.describedBy) canvas?.setAttribute("aria-describedby", opts.describedBy);

  let loaded = false;
  let destroyed = false;
  let failed = false;
  let pending: GlobeData | null = null;
  let userZoomed = false;
  let scrollZoomOn = false;

  // ---- rotation state ----
  // Rotating: a RAF loop (capped ~30 fps). Waiting to resume: a single setTimeout, no RAF.
  // Held (pointer down, or after flyTo): nothing scheduled at all.
  let raf = 0;
  let resumeTimer: ReturnType<typeof setTimeout> | undefined;
  let lastFrame: number | null = null;
  let resumeAt: number | null = null;
  let lastInteraction = Number.NEGATIVE_INFINITY; // Date.now() of the last user interaction
  let pointerDown = false;
  let held = false; // set by flyTo; cleared by the next user interaction
  let visible = typeof document === "undefined" || document.visibilityState !== "hidden";
  let inView = true;
  const motionMq = safeMatchMedia("(prefers-reduced-motion: reduce)");
  let reduced = !!motionMq?.matches;

  const canRun = () => loaded && !destroyed && !reduced && visible && inView;

  function cancelRaf() {
    if (raf) cancelAnimationFrame(raf);
    raf = 0;
    lastFrame = null;
    resumeAt = null;
  }
  function clearResume() {
    if (resumeTimer !== undefined) clearTimeout(resumeTimer);
    resumeTimer = undefined;
  }
  /** Bring the loop into the state the current conditions call for. */
  function schedule() {
    if (!canRun() || pointerDown || held) {
      cancelRaf();
      clearResume();
      return;
    }
    const wait = lastInteraction + IDLE_RESUME_MS - Date.now();
    if (wait > 0) {
      cancelRaf();
      clearResume();
      resumeTimer = setTimeout(() => {
        resumeTimer = undefined;
        schedule();
      }, wait);
      return;
    }
    clearResume();
    if (!raf) raf = requestAnimationFrame(tick);
  }
  function tick(t: number) {
    raf = 0;
    if (!canRun() || pointerDown || held || Date.now() - lastInteraction < IDLE_RESUME_MS) {
      schedule();
      return;
    }
    if (lastFrame !== null && t - lastFrame < ROTATE_FRAME_MS - 1) {
      raf = requestAnimationFrame(tick); // skip this display frame (30 fps cap)
      return;
    }
    const dt = lastFrame === null ? 0 : Math.min(0.1, Math.max(0, (t - lastFrame) / 1000));
    lastFrame = t;
    resumeAt ??= t;
    const speed = ROTATE_DEG_PER_S * smooth(Math.min(1, (t - resumeAt) / RAMP_MS));
    if (dt > 0 && speed > 0) {
      const c = map.getCenter();
      map.jumpTo({ center: [c.lng + speed * dt, c.lat] });
    }
    raf = requestAnimationFrame(tick);
  }

  function touch() {
    lastInteraction = Date.now();
    held = false;
    schedule();
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

  // Only Ctrl/Cmd+wheel zooms; a plain wheel is never handled, so the page scrolls even when
  // the canvas has focus (e.g. after a drag). Capture phase runs before MapLibre's own handler.
  const onWheel = (e: WheelEvent) => {
    const want = e.ctrlKey || e.metaKey;
    if (want) touch();
    if (want && !scrollZoomOn) map.scrollZoom.enable();
    else if (!want && scrollZoomOn) map.scrollZoom.disable();
    scrollZoomOn = want;
  };
  container.addEventListener("wheel", onWheel, { capture: true, passive: true });

  const onVisibility = () => {
    visible = document.visibilityState !== "hidden";
    schedule();
  };
  document.addEventListener("visibilitychange", onVisibility);

  const onMotion = () => {
    reduced = !!motionMq?.matches;
    schedule();
  };
  motionMq?.addEventListener?.("change", onMotion);

  let io: IntersectionObserver | null = null;
  if (typeof IntersectionObserver !== "undefined") {
    io = new IntersectionObserver((entries) => {
      inView = entries.some((e) => e.isIntersecting);
      schedule();
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

  // ---- data-render watchdog ----
  // A worker or source failure (e.g. the worker blocked or failing to parse) leaves an empty
  // globe. If the countries source has not reported loaded within the deadline, give up and
  // let the caller show the static fallback.
  let dataOk = false;
  let dataTimer: ReturnType<typeof setTimeout> | undefined;
  let dataDue = Number.POSITIVE_INFINITY;
  function armDataCheck(ms: number) {
    if (dataOk || destroyed) return;
    const due = Date.now() + ms;
    if (dataTimer !== undefined && dataDue <= due) return;
    if (dataTimer !== undefined) clearTimeout(dataTimer);
    dataDue = due;
    dataTimer = setTimeout(() => {
      dataTimer = undefined;
      if (!dataOk && !destroyed) fail(new Error("globe data did not render"), "render");
    }, ms);
  }
  function countriesLoaded(e: { sourceId?: string; isSourceLoaded?: boolean }): boolean {
    if (e?.sourceId !== "countries") return false;
    if (e.isSourceLoaded) return true;
    try {
      return map.isSourceLoaded("countries");
    } catch {
      return false;
    }
  }
  map.on("sourcedata", (e: { sourceId?: string; isSourceLoaded?: boolean }) => {
    if (dataOk || !countriesLoaded(e)) return;
    dataOk = true;
    if (dataTimer !== undefined) clearTimeout(dataTimer);
    dataTimer = undefined;
  });
  map.on("error", () => {
    // Before `load` an error may mean load never comes; after it, a short grace is enough.
    armDataCheck(loaded ? ERROR_GRACE_MS : DATA_DEADLINE_MS);
  });

  function fail(err: unknown, reason: GlobeFailure) {
    if (failed) return;
    failed = true;
    controller.destroy();
    opts.onError?.(err, reason);
  }

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
    armDataCheck(DATA_DEADLINE_MS);
    opts.onLoad?.();
    schedule();
  });

  const controller: GlobeController = {
    setData(d) {
      pending = d;
      if (loaded && !destroyed) pushData(d);
    },
    flyTo(center) {
      if (!loaded || destroyed) return;
      held = true;
      schedule();
      map.easeTo({ center, duration: reduced ? 0 : 1600, essential: true });
    },
    destroy() {
      if (destroyed) return;
      destroyed = true;
      cancelRaf();
      clearResume();
      if (dataTimer !== undefined) clearTimeout(dataTimer);
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
  return controller;
}

function safeMatchMedia(q: string): MediaQueryList | null {
  try {
    return typeof window.matchMedia === "function" ? window.matchMedia(q) : null;
  } catch {
    return null;
  }
}
