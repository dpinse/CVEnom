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
 * sources; the only source is in-memory GeoJSON (country polygons carrying a choropleth bucket)
 * added after the map's `load` event. There are no symbol/text/circle layers (legend and
 * tooltip are DOM overlays). Flat (mercator) is the default projection; globe is a toggle.
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
import { CHORO_STEPS, mixColor } from "./geoSummary";

// ---- tokens -----------------------------------------------------------------------

export interface GlobeTokens {
  ocean: string;
  land: string;
  border: string;
  /** The alert colour (--live) the choropleth mixes into the land colour. */
  alert: string;
  /** Outline colour for the hovered / selected country. */
  text: string;
}

export type MapMode = "flat" | "globe";

/** Dark-theme values from tokens.css; used only if a custom property cannot be read. */
const FALLBACK: Readonly<Record<string, string>> = {
  "--ocean": "#0a1521",
  "--land": "#2b3f54",
  "--border-geo": "#4d7093",
  "--live": "#ff2f45",
  "--text": "#e6edf5",
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
  return {
    ocean: read("--ocean"),
    land: read("--land"),
    border: read("--border-geo"),
    alert: read("--live"),
    text: read("--text"),
  };
}

// ---- style ------------------------------------------------------------------------

/** Country fill: --land, with the alert colour mixed in at CHORO_STEPS[bucket] for buckets 0..4. */
export function fillColor(t: GlobeTokens): ExpressionSpecification {
  return [
    "match",
    ["get", "bucket"],
    0,
    mixColor(t.land, t.alert, CHORO_STEPS[0]),
    1,
    mixColor(t.land, t.alert, CHORO_STEPS[1]),
    2,
    mixColor(t.land, t.alert, CHORO_STEPS[2]),
    3,
    mixColor(t.land, t.alert, CHORO_STEPS[3]),
    4,
    mixColor(t.land, t.alert, CHORO_STEPS[4]),
    t.land,
  ];
}

/** Outline width: thick when selected, medium when hovered (feature-state, keyed by iso2 via promoteId), else none. */
export function outlineWidth(): ExpressionSpecification {
  return [
    "case",
    ["boolean", ["feature-state", "selected"], false],
    2.2,
    ["boolean", ["feature-state", "hover"], false],
    1.4,
    0,
  ];
}

/** The initial style: background (ocean) only. Data sources/layers are added on `load`. */
export function baseStyle(t: GlobeTokens, mode: MapMode = "flat"): StyleSpecification {
  return {
    version: 8,
    projection: { type: mode === "flat" ? "mercator" : "globe" },
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
      id: "hover-outline",
      type: "line",
      source: "countries",
      paint: { "line-color": t.text, "line-width": outlineWidth() },
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
/**
 * Watchdog, silent case: with no error at all, the countries source must have rendered within
 * this long after `load` (visible time only; generous for low-end hardware / throttled tabs).
 */
export const DATA_DEADLINE_MS = 15000;
/** Watchdog, after a post-`load` map error: fall back only if countries still not loaded this long after it. */
export const ERROR_GRACE_MS = 5000;
/** Ease the rotation speed in over this long after resuming. */
const RAMP_MS = 1200;
const START_CENTER: Readonly<Record<MapMode, [number, number]>> = { globe: [-30, 22], flat: [10, 28] };

/** Accessible name of MapLibre's (focusable) canvas; the data summary is linked via aria-describedby. */
export const CANVAS_LABEL =
  "Interactive threat map. Drag or use the arrow keys to pan; Ctrl or Cmd with scroll, or the plus and minus keys, to zoom. The top countries list beside it is the keyboard route to each country.";

/**
 * Zoom at which the globe fills ~85% of the container's shorter side. (MapLibre's globe renders
 * smaller than the Mercator world size at the same zoom; 0.5 was tuned against Firefox output.)
 */
export function fitZoom(el: HTMLElement, mode: MapMode = "globe"): number {
  if (mode === "flat") {
    // Mercator: the 512 px world fits the container's width (the crop top and bottom is mostly ocean and ice).
    return el.clientWidth ? Math.max(0, Math.min(3, Math.log2(el.clientWidth / 512))) : 0.5;
  }
  const side = Math.min(el.clientWidth, el.clientHeight);
  if (!side) return 1.5;
  const radiusPx = 0.5 * side;
  return Math.max(0, Math.min(3, Math.log2((radiusPx * 2 * Math.PI) / 512)));
}

export interface GlobeData {
  countries: FeatureCollection<Geometry>;
}

export interface GlobeController {
  setData(d: GlobeData): void;
  /** Switch between mercator and globe projections (auto-rotate runs in globe mode only). */
  setMode(mode: MapMode): void;
  /** Outline the selected country (null clears). */
  setSelected(iso2: string | null): void;
  /** Globe only: ease to [lon, lat] and hold rotation until the user next interacts. */
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
  /** Initial projection (default flat). */
  mode?: MapMode;
  /** A country with activity was clicked (a drag never fires MapLibre's click): its ISO-2 code. */
  onCountryClick?: (iso2: string) => void;
  /** Pointer over a country with activity (iso2 + container-relative px), or leaving it (null, null). */
  onHover?: (iso2: string | null, point: { x: number; y: number } | null) => void;
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
  let mode: MapMode = opts.mode ?? "flat";

  const map = new MlMap({
    container,
    style: baseStyle(tokens, mode),
    center: START_CENTER[mode],
    zoom: fitZoom(container, mode),
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

  const canRun = () => loaded && !destroyed && mode === "globe" && !reduced && visible && inView;

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
    if (visible) resumeWatchdog();
    else pauseWatchdog();
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
      if (!userZoomed) map.setZoom(fitZoom(container, mode));
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
    map.setPaintProperty("hover-outline", "line-color", tokens.text);
  }
  const mo = new MutationObserver(applyTheme);
  mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  const schemeMq = safeMatchMedia("(prefers-color-scheme: light)");
  schemeMq?.addEventListener?.("change", applyTheme);

  // ---- data-render watchdog ----
  // A worker or source failure (e.g. the worker blocked or failing to parse) leaves an empty
  // globe. Rules (controller ruling):
  //  - an `error` before `load`            -> fall back immediately;
  //  - an `error` after `load`             -> fall back only if the countries source is still
  //                                           not loaded ERROR_GRACE_MS after that error;
  //  - no error                            -> silent deadline DATA_DEADLINE_MS after `load`.
  // The countdown only runs while the tab is visible: hidden pauses it, visible re-arms the
  // remaining time. The earliest pending deadline wins.
  let dataOk = false;
  let wdTimer: ReturnType<typeof setTimeout> | undefined;
  let wdDue = Number.POSITIVE_INFINITY; // Date.now() deadline of the running timer
  let wdPausedLeft: number | null = null; // remaining ms while the tab is hidden
  function clearWatchdog() {
    if (wdTimer !== undefined) clearTimeout(wdTimer);
    wdTimer = undefined;
    wdDue = Number.POSITIVE_INFINITY;
  }
  function armWatchdog(ms: number) {
    if (dataOk || destroyed || failed) return;
    if (!visible) {
      wdPausedLeft = Math.min(wdPausedLeft ?? Number.POSITIVE_INFINITY, ms);
      return;
    }
    const due = Date.now() + ms;
    if (wdTimer !== undefined && wdDue <= due) return;
    clearWatchdog();
    wdDue = due;
    wdTimer = setTimeout(() => {
      wdTimer = undefined;
      wdDue = Number.POSITIVE_INFINITY;
      if (!dataOk && !destroyed) fail(new Error("globe data did not render"), "render");
    }, ms);
  }
  function pauseWatchdog() {
    if (wdTimer === undefined) return;
    const left = Math.max(0, wdDue - Date.now());
    wdPausedLeft = Math.min(wdPausedLeft ?? Number.POSITIVE_INFINITY, left);
    clearWatchdog();
  }
  function resumeWatchdog() {
    if (wdPausedLeft === null) return;
    const left = wdPausedLeft;
    wdPausedLeft = null;
    armWatchdog(left);
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
    clearWatchdog();
    wdPausedLeft = null;
  });
  map.on("error", (e: { error?: unknown }) => {
    if (destroyed || dataOk) return;
    if (!loaded) fail(e?.error ?? new Error("map error before load"), "render");
    else armWatchdog(ERROR_GRACE_MS);
  });

  function fail(err: unknown, reason: GlobeFailure) {
    if (failed) return;
    failed = true;
    controller.destroy();
    opts.onError?.(err, reason);
  }

  // ---- hover / selected outline (feature-state on the countries source) ----
  let hovered: string | null = null;
  let selected: string | null = null;
  function setOutline(id: string, key: "hover" | "selected", on: boolean) {
    try {
      map.setFeatureState({ source: "countries", id }, { [key]: on });
    } catch {
      /* source not ready: the next event sets it again */
    }
  }
  function setHover(id: string | null) {
    if (id === hovered) return;
    if (hovered) setOutline(hovered, "hover", false);
    hovered = id;
    if (id) setOutline(id, "hover", true);
  }

  // ---- data ----
  function pushData(d: GlobeData) {
    (map.getSource("countries") as GeoJSONSource | undefined)?.setData(d.countries);
  }

  map.on("load", () => {
    if (destroyed) return;
    loaded = true;
    tokens = readGlobeTokens();
    const d = pending ?? {
      countries: { type: "FeatureCollection", features: [] },
    };
    // promoteId makes iso2 the feature id, so hover/selected feature-state survives setData.
    map.addSource("countries", { type: "geojson", data: d.countries, promoteId: "iso2" });
    for (const layer of dataLayers(tokens)) map.addLayer(layer);
    // Tokens may have changed between construction and load (theme toggled early).
    map.setPaintProperty("background", "background-color", tokens.ocean);
    armWatchdog(DATA_DEADLINE_MS);
    // The mode may have been switched before the style was ready.
    if (mode !== (opts.mode ?? "flat")) map.setProjection({ type: mode === "flat" ? "mercator" : "globe" });
    if (selected) setOutline(selected, "selected", true);
    // Only countries with activity (bucket >= 0) react: the rest are land, not a target.
    const active = (e: { features?: { properties?: Record<string, unknown> | null }[] }): string | null => {
      const p = e.features?.[0]?.properties;
      return p && typeof p.iso2 === "string" && Number(p.bucket) >= 0 ? p.iso2 : null;
    };
    map.on("click", "countries", (e: { features?: { properties?: Record<string, unknown> | null }[] }) => {
      const iso2 = active(e);
      if (iso2) opts.onCountryClick?.(iso2);
    });
    map.on(
      "mousemove",
      "countries",
      (e: { features?: { properties?: Record<string, unknown> | null }[]; point?: { x: number; y: number } }) => {
        const iso2 = active(e);
        setHover(iso2);
        map.getCanvas().style.cursor = iso2 ? "pointer" : "";
        if (iso2 && e.point) opts.onHover?.(iso2, { x: e.point.x, y: e.point.y });
        else opts.onHover?.(null, null);
      },
    );
    map.on("mouseleave", "countries", () => {
      setHover(null);
      map.getCanvas().style.cursor = "";
      opts.onHover?.(null, null);
    });
    opts.onLoad?.();
    schedule();
  });

  const controller: GlobeController = {
    setData(d) {
      pending = d;
      if (loaded && !destroyed) pushData(d);
    },
    setMode(next) {
      if (next === mode || destroyed) return;
      mode = next;
      if (loaded) {
        map.setProjection({ type: next === "flat" ? "mercator" : "globe" });
        userZoomed = false;
        map.jumpTo({ center: START_CENTER[next], zoom: fitZoom(container, next) });
      }
      held = false;
      schedule();
    },
    setSelected(iso2) {
      if (iso2 === selected) return;
      if (loaded && !destroyed && selected) setOutline(selected, "selected", false);
      selected = iso2;
      if (loaded && !destroyed && iso2) setOutline(iso2, "selected", true);
    },
    flyTo(center) {
      if (!loaded || destroyed || mode !== "globe") return;
      held = true;
      schedule();
      map.easeTo({ center, duration: reduced ? 0 : 1600, essential: true });
    },
    destroy() {
      if (destroyed) return;
      destroyed = true;
      cancelRaf();
      clearResume();
      clearWatchdog();
      wdPausedLeft = null;
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
