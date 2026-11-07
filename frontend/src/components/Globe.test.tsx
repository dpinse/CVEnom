import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, useLocation } from "react-router-dom";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { qk } from "../lib/queries";
import type { GeoSummaryItem } from "../lib/types";
import { useSelection } from "../lib/selection";
import { server, setupMsw } from "../test/shell";
import Globe from "./Globe";
import { GlobeProvider, useGlobe } from "./GlobeContext";
import { GlobeBoundary } from "./LazyGlobe";
import { CHORO_STEPS, mixColor } from "./geoSummary";
import { CANVAS_LABEL, DATA_DEADLINE_MS, ERROR_GRACE_MS, IDLE_RESUME_MS, dataLayers, type MapMode } from "./globeMap";

type Handler = (e?: unknown) => void;

const h = vi.hoisted(() => {
  const state = {
    maps: [] as unknown[],
    throwOnInit: false,
    setWorkerUrl: (() => {}) as (u: string) => void,
  };
  return state;
});

vi.mock("maplibre-gl", () => {
  class FakeMap {
    options: Record<string, unknown>;
    handlers = new Map<string, Set<Handler>>();
    cursor = "";
    sources: Record<string, { spec: unknown; data: unknown; setData: (d: unknown) => void }> = {};
    layers: Record<string, unknown>[] = [];
    paint: Record<string, Record<string, unknown>> = {};
    paintCalls: [string, string, unknown][] = [];
    removed = false;
    center = { lng: 0, lat: 20 };
    zoom = 1.5;
    resize = vi.fn();
    easeTo = vi.fn();
    jumpTo = vi.fn((o: { center?: [number, number] }) => {
      if (o.center) this.center = { lng: o.center[0], lat: o.center[1] };
    });
    scrollZoom = { enable: vi.fn(), disable: vi.fn() };
    touchZoomRotate = { disableRotation: vi.fn() };
    canvas: HTMLCanvasElement;
    constructor(options: Record<string, unknown>) {
      if (h.throwOnInit) throw new Error("WebGL2 is required to display this map.");
      this.options = options;
      // Like MapLibre: a focusable canvas with role=region inside the container.
      this.canvas = document.createElement("canvas");
      this.canvas.setAttribute("tabindex", "0");
      this.canvas.setAttribute("role", "region");
      this.canvas.setAttribute("aria-label", "Map");
      (options.container as HTMLElement).appendChild(this.canvas);
      h.maps.push(this);
    }
    isSourceLoaded() {
      return false;
    }
    // Like MapLibre: on(type, fn) or on(type, layerId, fn); layer handlers are keyed "type@layer".
    on(type: string, a: string | Handler, b?: Handler) {
      const key = typeof a === "string" ? `${type}@${a}` : type;
      if (!this.handlers.has(key)) this.handlers.set(key, new Set());
      this.handlers.get(key)!.add(typeof a === "string" ? b! : a);
      return this;
    }
    off(type: string, a: string | Handler, b?: Handler) {
      this.handlers.get(typeof a === "string" ? `${type}@${a}` : type)?.delete(typeof a === "string" ? b! : a);
      return this;
    }
    fire(type: string, e: unknown = {}, layer?: string) {
      for (const fn of this.handlers.get(layer ? `${type}@${layer}` : type) ?? []) fn(e);
    }
    addSource(id: string, spec: { data: unknown }) {
      const src = {
        spec,
        data: spec.data,
        setData: vi.fn((d: unknown) => {
          src.data = d;
        }),
      };
      this.sources[id] = src;
    }
    getSource(id: string) {
      return this.sources[id];
    }
    addLayer(l: Record<string, unknown>) {
      this.layers.push(l);
    }
    getLayer(id: string) {
      return this.layers.find((l) => l.id === id) ?? (id === "background" ? { id } : undefined);
    }
    setPaintProperty(layer: string, prop: string, value: unknown) {
      this.paintCalls.push([layer, prop, value]);
      (this.paint[layer] ??= {})[prop] = value;
    }
    setSky = vi.fn();
    setProjection = vi.fn();
    featureStates: { source: string; id: string; state: Record<string, boolean> }[] = [];
    setFeatureState = vi.fn((f: { source: string; id: string }, state: Record<string, boolean>) => {
      this.featureStates.push({ ...f, state });
    });
    getCenter() {
      return this.center;
    }
    getZoom() {
      return this.zoom;
    }
    setZoom(z: number) {
      this.zoom = z;
    }
    getCanvas() {
      return this.canvas;
    }
    remove() {
      this.removed = true;
    }
  }
  return {
    Map: FakeMap,
    setWorkerUrl: (u: string) => h.setWorkerUrl(u),
  };
});

interface FakeMapT {
  options: { style: Record<string, unknown>; [k: string]: unknown };
  sources: Record<
    string,
    { spec: unknown; data: { features: { properties: Record<string, unknown> }[] }; setData: ReturnType<typeof vi.fn> }
  >;
  layers: { id: string; type: string; paint?: Record<string, unknown> }[];
  paint: Record<string, Record<string, unknown>>;
  paintCalls: [string, string, unknown][];
  removed: boolean;
  easeTo: ReturnType<typeof vi.fn>;
  setProjection: ReturnType<typeof vi.fn>;
  featureStates: { source: string; id: string; state: Record<string, boolean> }[];
  jumpTo: ReturnType<typeof vi.fn>;
  resize: ReturnType<typeof vi.fn>;
  scrollZoom: { enable: ReturnType<typeof vi.fn>; disable: ReturnType<typeof vi.fn> };
  fire: (type: string, e?: unknown, layer?: string) => void;
  getCanvas: () => HTMLCanvasElement;
}
const maps = () => h.maps as FakeMapT[];
const lastMap = () => maps()[maps().length - 1];

const fixture: GeoSummaryItem[] = [
  { country_code: "US", kind: "scan", magnitude: 7, events: 320, last_seen: "2026-11-05T10:00:00Z" },
  { country_code: "US", kind: "outage", magnitude: 6, events: 3, last_seen: "2026-11-05T10:00:00Z" },
  { country_code: "NL", kind: "c2", magnitude: 2, events: 9, last_seen: "2026-11-05T10:00:00Z" },
  { country_code: "JP", kind: "outage", magnitude: 1, events: 1, last_seen: "2026-11-05T10:00:00Z" },
  {
    country_code: null as unknown as string,
    kind: "scan",
    magnitude: 99,
    events: 1,
    last_seen: "2026-11-05T10:00:00Z",
  },
];

function seeded(data: GeoSummaryItem[] | undefined) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  if (data) qc.setQueryData(qk.geo("7d"), data);
  return qc;
}

function Search() {
  return <output data-testid="search">{useLocation().search}</output>;
}

function renderGlobe(
  data: GeoSummaryItem[] | undefined = fixture,
  extra?: ReactNode,
  qc = seeded(data),
  mode: MapMode = "flat",
) {
  const tree = (m: MapMode) => (
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <GlobeProvider>
          <Globe mode={m} />
          {extra}
        </GlobeProvider>
        <Search />
      </MemoryRouter>
    </QueryClientProvider>
  );
  const r = render(tree(mode));
  return { ...r, setMode: (m: MapMode) => r.rerender(tree(m)) };
}
const renderGlobeMode = (extra?: ReactNode, data: GeoSummaryItem[] | undefined = fixture) =>
  renderGlobe(data, extra, seeded(data), "globe");

// ---- environment controls ---------------------------------------------------
let reducedMotion = false;
let rafQueue: FrameRequestCallback[] = [];
let tokens: Record<string, string> = {};
const DARK = {
  "--ocean": "#0a1521",
  "--land": "#2b3f54",
  "--border-geo": "#4d7093",
  "--sev-high": "#ff9a44",
  "--sev-crit": "#ff5663",
  "--sev-low": "#3dd79a",
  "--sev-med": "#ecc14a",
  "--live": "#ff2f45",
  "--scope": "#6fb0d4",
  "--text": "#e9eef4",
};

function runFrames(n: number, stepMs = 16) {
  for (let i = 0; i < n; i++) {
    const q = rafQueue;
    rafQueue = [];
    const t = performance.now() + (i + 1) * stepMs;
    for (const cb of q) cb(t);
  }
}

setupMsw({ ready: true });

beforeEach(() => {
  h.maps.length = 0;
  h.throwOnInit = false;
  h.setWorkerUrl = vi.fn();
  reducedMotion = false;
  rafQueue = [];
  tokens = { ...DARK };
  document.documentElement.removeAttribute("data-theme");
  vi.stubGlobal("matchMedia", (q: string) => ({
    matches: q.includes("prefers-reduced-motion") ? reducedMotion : false,
    media: q,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
  vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => {
    rafQueue.push(cb);
    return rafQueue.length;
  });
  vi.stubGlobal("cancelAnimationFrame", () => {
    rafQueue = [];
  });
  const real = window.getComputedStyle.bind(window);
  vi.spyOn(window, "getComputedStyle").mockImplementation((el: Element, pseudo?: string | null) => {
    const cs = real(el, pseudo);
    if (el !== document.documentElement) return cs;
    return new Proxy(cs, {
      get(target, prop) {
        if (prop === "getPropertyValue") return (name: string) => tokens[name] ?? "";
        const v = Reflect.get(target, prop);
        return typeof v === "function" ? v.bind(target) : v;
      },
    });
  });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const loadMap = () => act(() => lastMap().fire("load"));
/** Text of the element the canvas names in aria-describedby. */
function summary(): string | null {
  const id = document.querySelector("canvas")?.getAttribute("aria-describedby");
  return id ? (document.getElementById(id)?.textContent ?? null) : null;
}
const mapContainer = () => document.querySelector(".globe-map") as HTMLElement;

describe("<Globe> map wiring", () => {
  it("serves the worker from self via setWorkerUrl before creating the map", () => {
    renderGlobe();
    expect(h.setWorkerUrl).toHaveBeenCalledTimes(1);
    const url = vi.mocked(h.setWorkerUrl).mock.calls[0][0];
    expect(url).toMatch(/maplibre-gl-worker/);
    expect(url).not.toMatch(/^(https?:|blob:|data:)/);
  });

  it("creates a flat (mercator) map by default, with attribution and logo controls off", () => {
    renderGlobe();
    expect(maps()).toHaveLength(1);
    const o = lastMap().options;
    expect((o.style as { projection: unknown }).projection).toEqual({ type: "mercator" });
    expect(o.attributionControl).toBe(false);
    expect(o.maplibreLogo).toBeFalsy();
    expect(o.scrollZoom).toBe(false);
    expect(o.dragRotate).toBe(false);
    expect(o.pitchWithRotate).toBe(false);
  });

  it("starts in the globe projection when the mode is globe", () => {
    renderGlobeMode();
    expect((lastMap().options.style as { projection: unknown }).projection).toEqual({ type: "globe" });
  });

  it("adds one source and the fill, border and hover-outline layers only after the load event", () => {
    renderGlobe();
    const m = lastMap();
    expect(Object.keys(m.sources)).toEqual([]);
    expect(m.layers).toEqual([]);
    loadMap();
    expect(Object.keys(m.sources)).toEqual(["countries"]);
    expect((m.sources.countries.spec as { promoteId: string }).promoteId).toBe("iso2");
    expect(m.layers.map((l) => [l.id, l.type])).toEqual([
      ["countries", "fill"],
      ["borders", "line"],
      ["hover-outline", "line"],
    ]);
    const style = m.options.style as { layers: { id: string; type: string }[] };
    expect(style.layers.map((l) => [l.id, l.type])).toEqual([["background", "background"]]);
  });

  it("style JSON has no remote URL, no glyphs and no sprite; sources are in-memory GeoJSON", () => {
    renderGlobe();
    loadMap();
    const m = lastMap();
    const style = m.options.style;
    expect(style).not.toHaveProperty("glyphs");
    expect(style).not.toHaveProperty("sprite");
    expect(style.version).toBe(8);
    const everything = JSON.stringify({
      style,
      sources: Object.values(m.sources).map((s) => s.spec),
      layers: m.layers,
    });
    expect(everything).not.toMatch(/https?:/i);
    expect(everything).not.toMatch(/mapbox:/i);
    for (const s of Object.values(m.sources)) {
      expect((s.spec as { type: string }).type).toBe("geojson");
      expect(typeof (s.spec as { data: unknown }).data).toBe("object");
    }
    for (const l of m.layers) expect(l.type).not.toBe("symbol");
  });

  it("countries render even with no data (Antarctica excluded), all with no bucket", () => {
    renderGlobe([]);
    loadMap();
    const m = lastMap();
    expect(m.sources.countries.data.features).toHaveLength(176);
    expect(m.sources.countries.data.features.every((f) => f.properties.bucket === -1)).toBe(true);
  });

  it("pushes each country's bucket and event count from useGeo into the source", () => {
    renderGlobe();
    loadMap();
    const m = lastMap();
    const prop = (iso: string) => m.sources.countries.data.features.find((f) => f.properties.iso2 === iso)?.properties;
    // totals: US 320 + 3, NL 9, JP 1 (the null-country row is ignored); max 323
    expect(prop("US")).toMatchObject({ bucket: 4, n: 323 });
    expect(prop("NL")).toMatchObject({ bucket: 0, n: 9 });
    expect(prop("JP")).toMatchObject({ bucket: 0, n: 1 });
    expect(prop("DE")).toMatchObject({ bucket: -1, n: 0 });
  });

  it("dataLayers has no circle layer and the fill matches on bucket (land colour otherwise)", () => {
    renderGlobe();
    loadMap();
    const m = lastMap();
    expect(m.layers.some((l) => l.type === "circle")).toBe(false);
    expect(
      dataLayers({ ocean: "#000", land: "#2b3f54", border: "#4d7093", alert: "#ff2f45", text: "#fff" }).map(
        (l) => l.type,
      ),
    ).toEqual(["fill", "line", "line"]);
    const fill = m.layers.find((l) => l.id === "countries")!.paint!["fill-color"] as unknown[];
    expect(fill.slice(0, 2)).toEqual(["match", ["get", "bucket"]]);
    CHORO_STEPS.forEach((p, i) => {
      expect(fill[2 + i * 2]).toBe(i);
      expect(fill[3 + i * 2]).toBe(mixColor(DARK["--land"], DARK["--live"], p));
    });
    expect(fill[fill.length - 1]).toBe(DARK["--land"]);
    const border = m.layers.find((l) => l.id === "borders")!.paint!;
    expect(border["line-color"]).toBe(DARK["--border-geo"]);
    expect(border["line-width"]).toBe(0.5);
    expect(m.layers.find((l) => l.id === "hover-outline")!.paint!["line-color"]).toBe(DARK["--text"]);
  });
});

describe("<Globe> accessibility and interaction", () => {
  it("labels the focusable canvas and links it to the data summary, with no role=img around it", () => {
    renderGlobe();
    expect(screen.queryByRole("img")).toBeNull();
    const region = screen.getByRole("region", { name: CANVAS_LABEL });
    expect(region).toHaveAttribute("tabindex", "0");
    expect(summary()).toBe(
      "Threat map: 3 countries with activity in the last 7 days; most active United States, 323 events",
    );
  });

  it("clicking a country with activity selects ?country=; one without activity or an unknown code does nothing", () => {
    renderGlobe();
    loadMap();
    const m = lastMap();
    act(() => m.fire("click", { features: [{ properties: { iso2: "DE", bucket: 2 } }] }, "countries"));
    expect(screen.getByTestId("search")).toHaveTextContent("?country=DE");
    act(() => m.fire("click", { features: [{ properties: { iso2: "FR", bucket: -1 } }] }, "countries"));
    expect(screen.getByTestId("search")).toHaveTextContent("?country=DE");
    act(() => m.fire("click", { features: [{ properties: { iso2: "QQ", bucket: 1 } }] }, "countries"));
    expect(screen.getByTestId("search")).toHaveTextContent("?country=DE");
  });

  it("a click with no iso2 does nothing", () => {
    renderGlobe();
    loadMap();
    const m = lastMap();
    act(() => m.fire("click", { features: [{ properties: {} }] }, "countries"));
    act(() => m.fire("click", { features: [] }, "countries"));
    expect(screen.getByTestId("search")).toHaveTextContent("");
  });

  it("hovering a country with activity shows 'Country · N events', outlines it and sets a pointer cursor", () => {
    renderGlobe();
    loadMap();
    const m = lastMap();
    act(() =>
      m.fire(
        "mousemove",
        { features: [{ properties: { iso2: "NL", bucket: 0 } }], point: { x: 40, y: 50 } },
        "countries",
      ),
    );
    expect(screen.getByText("Netherlands · 9 events")).toBeInTheDocument();
    expect(m.getCanvas().style.cursor).toBe("pointer");
    expect(m.featureStates.at(-1)).toEqual({ source: "countries", id: "NL", state: { hover: true } });
    // moving onto land without activity clears everything
    act(() =>
      m.fire(
        "mousemove",
        { features: [{ properties: { iso2: "FR", bucket: -1 } }], point: { x: 60, y: 50 } },
        "countries",
      ),
    );
    expect(screen.queryByText(/Netherlands ·/)).toBeNull();
    expect(m.getCanvas().style.cursor).toBe("");
    expect(m.featureStates.at(-1)).toEqual({ source: "countries", id: "NL", state: { hover: false } });
    act(() =>
      m.fire(
        "mousemove",
        { features: [{ properties: { iso2: "JP", bucket: 0 } }], point: { x: 1, y: 2 } },
        "countries",
      ),
    );
    expect(screen.getByText("Japan · 1 event")).toBeInTheDocument();
    act(() => m.fire("mouseleave", {}, "countries"));
    expect(screen.queryByText(/Japan ·/)).toBeNull();
  });

  it("outlines the selected country from ?country=", () => {
    function Pick() {
      const { select } = useSelection();
      return (
        <button type="button" onClick={() => select({ kind: "country", cc: "JP" })}>
          pick
        </button>
      );
    }
    renderGlobe(fixture, <Pick />);
    loadMap();
    const m = lastMap();
    fireEvent.click(screen.getByRole("button", { name: "pick" }));
    expect(m.featureStates.at(-1)).toEqual({ source: "countries", id: "JP", state: { selected: true } });
  });

  it("survives loading and API error states", async () => {
    server.use(http.get("http://localhost/api/geo", () => HttpResponse.json({ detail: "boom" }, { status: 500 })));
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    renderGlobe(undefined, null, qc);
    expect(summary()).toMatch(/loading/i);
    await waitFor(() => expect(summary()).toMatch(/unavailable/i));
    loadMap();
    expect(lastMap().sources.countries.data.features).toHaveLength(176);
  });
});

describe("<Globe> resilience", () => {
  it("renders the static fallback (ranked countries, SG included) when MapLibre init throws", () => {
    h.throwOnInit = true;
    renderGlobe([...fixture, { country_code: "SG", kind: "scan", magnitude: 1, events: 900, last_seen: "x" }]);
    expect(screen.getByText(/couldn't start WebGL 2/i)).toBeInTheDocument();
    const ranked = screen.getByRole("list", { name: /most active countries/i });
    const rows = [...ranked.querySelectorAll("li")].map((li) => li.textContent);
    expect(rows[0]).toContain("Singapore");
    expect(rows[1]).toContain("United States");
    expect(rows).toHaveLength(4);
  });

  it("unmount removes the map and disconnects observers and loops", () => {
    const { unmount } = renderGlobe();
    loadMap();
    const m = lastMap();
    unmount();
    expect(m.removed).toBe(true);
    const before = m.paintCalls.length;
    document.documentElement.setAttribute("data-theme", "light");
    expect(rafQueue).toEqual([]);
    return Promise.resolve().then(() => expect(m.paintCalls.length).toBe(before));
  });

  it("a theme flip re-reads tokens and updates paint without recreating the map", async () => {
    renderGlobe();
    loadMap();
    const m = lastMap();
    tokens = {
      ...DARK,
      "--ocean": "#bcd4e8",
      "--land": "#eef4fa",
      "--live": "#c00f24",
      "--border-geo": "#7ea3c0",
      "--text": "#0f1a27",
    };
    document.documentElement.setAttribute("data-theme", "light");
    await waitFor(() => expect(m.paint.background?.["background-color"]).toBe("#bcd4e8"));
    expect(m.paint.borders?.["line-color"]).toBe("#7ea3c0");
    expect(m.paint["hover-outline"]?.["line-color"]).toBe("#0f1a27");
    const fill = m.paint.countries?.["fill-color"] as unknown[];
    expect(fill[fill.length - 1]).toBe("#eef4fa");
    expect(fill[3]).toBe(mixColor("#eef4fa", "#c00f24", CHORO_STEPS[0]));
    expect(maps()).toHaveLength(1);
  });
});

describe("<Globe> motion", () => {
  it("auto-rotates eastward via requestAnimationFrame once loaded in globe mode", () => {
    renderGlobeMode();
    loadMap();
    const m = lastMap();
    runFrames(120);
    expect(m.jumpTo).toHaveBeenCalled();
    const last = m.jumpTo.mock.calls.at(-1)![0] as { center: [number, number] };
    expect(last.center[0]).toBeGreaterThan(0);
  });

  it("flat mode never rotates", () => {
    renderGlobe();
    loadMap();
    runFrames(120);
    expect(lastMap().jumpTo).not.toHaveBeenCalled();
    expect(rafQueue).toEqual([]);
  });

  it("setMode('globe') calls setProjection({type:'globe'}) and starts rotating; flat stops it again", () => {
    const { setMode } = renderGlobe();
    loadMap();
    const m = lastMap();
    act(() => setMode("globe"));
    expect(m.setProjection).toHaveBeenLastCalledWith({ type: "globe" });
    expect(rafQueue.length).toBe(1);
    act(() => setMode("flat"));
    expect(m.setProjection).toHaveBeenLastCalledWith({ type: "mercator" });
    expect(rafQueue).toEqual([]);
    m.jumpTo.mockClear();
    runFrames(60);
    expect(m.jumpTo).not.toHaveBeenCalled();
  });

  it("prefers-reduced-motion disables rotation entirely, even in globe mode", () => {
    reducedMotion = true;
    renderGlobeMode();
    loadMap();
    runFrames(120);
    expect(lastMap().jumpTo).not.toHaveBeenCalled();
    expect(rafQueue).toEqual([]);
  });

  it("pauses on user interaction", () => {
    renderGlobeMode();
    loadMap();
    const m = lastMap();
    act(() => m.fire("mousedown", { originalEvent: new MouseEvent("mousedown") }));
    expect(rafQueue).toEqual([]); // no idle RAF loop while held
    m.jumpTo.mockClear();
    runFrames(60);
    expect(m.jumpTo).not.toHaveBeenCalled();
  });

  it("stops when the tab is hidden", () => {
    renderGlobeMode();
    loadMap();
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
    try {
      act(() => {
        document.dispatchEvent(new Event("visibilitychange"));
      });
      expect(rafQueue).toEqual([]);
    } finally {
      Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" });
    }
  });
});

describe("<Globe> interaction and flyTo", () => {
  function FlyButton({ code }: { code: string }) {
    const globe = useGlobe();
    return (
      <button type="button" onClick={() => globe.flyTo(code)}>
        fly {code}
      </button>
    );
  }

  it("flyTo is a no-op before load, then eases to the country centroid", () => {
    renderGlobeMode(<FlyButton code="NL" />);
    const m = lastMap();
    fireEvent.click(screen.getByRole("button", { name: "fly NL" }));
    expect(m.easeTo).not.toHaveBeenCalled();
    loadMap();
    fireEvent.click(screen.getByRole("button", { name: "fly NL" }));
    expect(m.easeTo).toHaveBeenCalledTimes(1);
    const { center } = m.easeTo.mock.calls[0][0] as { center: [number, number] };
    expect(center[0]).toBeGreaterThan(3);
    expect(center[0]).toBeLessThan(7.5);
    expect(center[1]).toBeGreaterThan(50.5);
    expect(center[1]).toBeLessThan(54);
  });

  it("flyTo does nothing in flat mode", () => {
    renderGlobe(fixture, <FlyButton code="NL" />);
    loadMap();
    fireEvent.click(screen.getByRole("button", { name: "fly NL" }));
    expect(lastMap().easeTo).not.toHaveBeenCalled();
  });

  it("flyTo ignores unknown countries", () => {
    renderGlobeMode(<FlyButton code="ZZ" />);
    loadMap();
    fireEvent.click(screen.getByRole("button", { name: "fly ZZ" }));
    expect(lastMap().easeTo).not.toHaveBeenCalled();
  });

  it("useGlobe outside a provider is a harmless no-op", () => {
    function Lone() {
      const g = useGlobe();
      g.flyTo("US");
      return null;
    }
    expect(() => render(<Lone />)).not.toThrow();
  });

  it("zooms only on Ctrl/Cmd+wheel; a plain wheel scrolls the page even after focus/drag", () => {
    renderGlobeMode();
    loadMap();
    const m = lastMap();
    const canvas = document.querySelector("canvas")!;
    // a click or drag focuses MapLibre's canvas
    act(() => {
      m.fire("mousedown", { originalEvent: new MouseEvent("mousedown") });
      canvas.focus();
      m.fire("mouseup", { originalEvent: new MouseEvent("mouseup") });
    });
    expect(document.activeElement).toBe(canvas);
    const notPrevented = fireEvent.wheel(canvas, { deltaY: 10 });
    expect(notPrevented).toBe(true);
    expect(m.scrollZoom.enable).not.toHaveBeenCalled();
    fireEvent.wheel(canvas, { deltaY: 10, ctrlKey: true });
    expect(m.scrollZoom.enable).toHaveBeenCalledTimes(1);
    fireEvent.wheel(mapContainer(), { deltaY: 10, metaKey: true });
    expect(m.scrollZoom.enable).toHaveBeenCalledTimes(1); // still on
    expect(fireEvent.wheel(canvas, { deltaY: 10 })).toBe(true);
    expect(m.scrollZoom.disable).toHaveBeenCalledTimes(1);
    expect(m.options.keyboard).not.toBe(false); // keyboard +/- zoom stays available when focused
  });

  it("resizes the map when its container resizes", () => {
    const observed: ResizeObserverCallback[] = [];
    vi.stubGlobal(
      "ResizeObserver",
      class {
        constructor(cb: ResizeObserverCallback) {
          observed.push(cb);
        }
        observe() {}
        disconnect() {}
        unobserve() {}
      },
    );
    renderGlobeMode();
    loadMap();
    act(() => observed.forEach((cb) => cb([], {} as ResizeObserver)));
    expect(lastMap().resize).toHaveBeenCalled();
  });
});

describe("<Globe> rotation scheduling", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("waits for resume with a timer, not a no-op RAF loop, then restarts RAF after 4 s idle", () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    renderGlobeMode();
    loadMap();
    const m = lastMap();
    expect(rafQueue.length).toBe(1);
    act(() => m.fire("mousedown", { originalEvent: new MouseEvent("mousedown") }));
    act(() => m.fire("mouseup", { originalEvent: new MouseEvent("mouseup") }));
    expect(rafQueue).toEqual([]);
    act(() => vi.advanceTimersByTime(IDLE_RESUME_MS - 100));
    expect(rafQueue).toEqual([]);
    act(() => vi.advanceTimersByTime(150));
    expect(rafQueue.length).toBe(1);
  });

  it("caps active rotation at ~30 fps by skipping frames", () => {
    renderGlobeMode();
    loadMap();
    const m = lastMap();
    runFrames(61, 1000 / 60); // ~1 s of 60 Hz display frames
    const calls = m.jumpTo.mock.calls.length;
    expect(calls).toBeGreaterThanOrEqual(25);
    expect(calls).toBeLessThanOrEqual(31);
  });

  it("flyTo holds rotation with nothing scheduled", () => {
    function Fly() {
      const g = useGlobe();
      return (
        <button type="button" onClick={() => g.flyTo("JP")}>
          fly
        </button>
      );
    }
    renderGlobeMode(<Fly />);
    loadMap();
    expect(rafQueue.length).toBe(1);
    fireEvent.click(screen.getByRole("button", { name: "fly" }));
    expect(rafQueue).toEqual([]);
    expect(lastMap().easeTo).toHaveBeenCalledTimes(1);
  });
});

describe("<Globe> render watchdog", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  const fakeClock = () => vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
  const noFallback = () => expect(screen.queryByText(/couldn't render its data/i)).toBeNull();
  const fellBack = () => expect(screen.getByText(/couldn't render its data/i)).toBeInTheDocument();
  const setVisibility = (state: "hidden" | "visible") => {
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => state });
    act(() => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
  };

  it("exports the ruled watchdog constants", () => {
    expect(DATA_DEADLINE_MS).toBe(15000);
    expect(ERROR_GRACE_MS).toBe(5000);
  });

  it("an error before load falls back immediately", () => {
    fakeClock();
    renderGlobe();
    const m = lastMap();
    act(() => m.fire("error", { error: new Error("worker failed") }));
    fellBack();
    expect(m.removed).toBe(true);
  });

  it("post-load error, data arriving at 3 s: no fallback", () => {
    fakeClock();
    renderGlobe();
    loadMap();
    const m = lastMap();
    act(() => m.fire("error", { error: new Error("transient worker warning") }));
    act(() => vi.advanceTimersByTime(3000));
    act(() => m.fire("sourcedata", { sourceId: "countries", isSourceLoaded: true }));
    act(() => vi.advanceTimersByTime(DATA_DEADLINE_MS * 2));
    noFallback();
    expect(m.removed).toBe(false);
  });

  it("post-load error, no data by 5 s: fallback (and the map is removed)", () => {
    fakeClock();
    renderGlobe();
    loadMap();
    const m = lastMap();
    act(() => vi.advanceTimersByTime(2000));
    act(() => m.fire("error", { error: new Error("worker failed") }));
    act(() => vi.advanceTimersByTime(ERROR_GRACE_MS - 100));
    noFallback();
    act(() => vi.advanceTimersByTime(200));
    fellBack();
    expect(m.removed).toBe(true);
    expect(screen.getByRole("list", { name: /most active countries/i })).toBeInTheDocument();
  });

  it("no error and no data: silent fallback at 15 s, not before", () => {
    fakeClock();
    renderGlobe();
    loadMap();
    act(() => vi.advanceTimersByTime(DATA_DEADLINE_MS - 100));
    noFallback();
    act(() => vi.advanceTimersByTime(200));
    fellBack();
  });

  it("a hidden tab pauses the watchdog; visible again re-arms only the remaining time", () => {
    fakeClock();
    try {
      renderGlobe();
      loadMap();
      act(() => vi.advanceTimersByTime(10000)); // 5 s of the 15 s budget left
      setVisibility("hidden");
      act(() => vi.advanceTimersByTime(60000));
      noFallback();
      setVisibility("visible");
      act(() => vi.advanceTimersByTime(4900));
      noFallback();
      act(() => vi.advanceTimersByTime(200));
      fellBack();
    } finally {
      Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" });
    }
  });

  it("once the countries source has loaded, later errors never trigger the fallback", () => {
    fakeClock();
    renderGlobe();
    loadMap();
    const m = lastMap();
    act(() => m.fire("sourcedata", { sourceId: "countries", isSourceLoaded: true }));
    act(() => m.fire("error", { error: new Error("transient") }));
    act(() => vi.advanceTimersByTime(DATA_DEADLINE_MS * 3));
    noFallback();
    expect(m.removed).toBe(false);
  });

  it("the lazy-chunk error boundary shows the 'couldn't load the map module' note", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    function Boom(): never {
      throw new Error("Failed to fetch dynamically imported module");
    }
    render(
      <QueryClientProvider client={seeded(fixture)}>
        <GlobeBoundary>
          <Boom />
        </GlobeBoundary>
      </QueryClientProvider>,
    );
    expect(screen.getByText(/couldn't load the map module/i)).toBeInTheDocument();
    expect(screen.getByRole("list", { name: /most active countries/i })).toBeInTheDocument();
  });
});
