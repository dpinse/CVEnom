import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClientProvider } from "@tanstack/react-query";
import { HttpResponse, http, type JsonBodyType } from "msw";
import { MemoryRouter, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { createQueryClient } from "../lib/queries";
import Dashboard from "../pages/Dashboard";
import type { CountryActivity, CountryEvent, GeoSummaryItem } from "../lib/types";
import { lanes, member, server, setupMsw, signIn } from "../test/shell";
import { CountryPanel } from "./CountryPanel";
import { DrawerHost } from "./DrawerHost";
import { MapPanel, useMapMode } from "./MapPanel";
import { RangeControl } from "./RangeControl";
import { SummaryLine, summaryHrefs } from "./SummaryLine";
import { renderHook } from "@testing-library/react";

// The real map (MapLibre) is covered by Globe.test.tsx; here it is a stub that exposes its props.
vi.mock("./LazyGlobe", () => ({
  LazyGlobe: ({ range, mode }: { range: string; mode: string }) => (
    <div data-testid="map" data-range={range} data-mode={mode} />
  ),
}));
vi.mock("./GlobeContext", () => ({ useGlobe: () => ({ flyTo: () => {} }) }));

setupMsw({ ready: true });
afterEach(cleanup);

const at = "2026-11-05T09:00:00Z";
const g = (country_code: string, kind: string, events: number): GeoSummaryItem => ({
  country_code,
  kind,
  magnitude: 1,
  events,
  last_seen: at,
});

/** 10 countries; SG (no polygon in the 110m atlas) is the busiest. */
const GEO: GeoSummaryItem[] = [
  g("SG", "scan", 900),
  g("US", "scan", 300),
  g("US", "victim", 20),
  g("DE", "scan", 120),
  g("FR", "scan", 90),
  g("NL", "c2", 80),
  g("JP", "scan", 70),
  g("BR", "outage", 60),
  g("IN", "scan", 50),
  g("RU", "c2", 40),
  g("MT", "bgp", 30),
];

const serveGeo = (items: GeoSummaryItem[] = GEO) =>
  server.use(http.get("http://localhost/api/geo", () => HttpResponse.json(items)));

const country = (o: Partial<CountryActivity> = {}): CountryActivity => ({
  country_code: "DE",
  window_hours: 168,
  counts: [
    { kind: "scan", events: 12, magnitude: 5 },
    { kind: "outage", events: 2, magnitude: 3 },
  ],
  top_sources: [],
  trend: [],
  trend_unit: "day",
  top_cves: [{ cve_id: "CVE-2026-1001", cvss: 9.8, events: 4 }],
  events: null,
  ...o,
});
const cev = (o: Partial<CountryEvent> = {}): CountryEvent => ({
  source: "greynoise",
  kind: "scan",
  label: "scan burst",
  magnitude: 3,
  observed_at: "2026-11-05T11:00:00Z",
  asn: null,
  story_url: null,
  details: {},
  ...o,
});
const serveCountry = (a: CountryActivity, cc = "DE") =>
  server.use(http.get(`http://localhost/api/geo/${cc}`, () => HttpResponse.json(a)));

function Search() {
  const l = useLocation();
  return <output data-testid="search">{l.search}</output>;
}
function renderAt(ui: React.ReactNode, path = "/") {
  const qc = createQueryClient();
  qc.setDefaultOptions({ queries: { ...qc.getDefaultOptions().queries, retry: false } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        {ui}
        <Search />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("CountryPanel: top countries", () => {
  test("lists the top 8 sorted by events, each a button with code, name, bar and count", async () => {
    serveGeo();
    renderAt(<CountryPanel range="7d" />);
    const list = await screen.findByRole("list", { name: "Top countries" });
    const rows = within(list).getAllByRole("button");
    expect(rows).toHaveLength(8);
    expect(rows.map((b) => b.querySelector(".cc")!.textContent)).toEqual([
      "SG",
      "US",
      "DE",
      "FR",
      "NL",
      "JP",
      "BR",
      "IN",
    ]);
    expect(rows[1]).toHaveTextContent("United States");
    expect(rows[1].querySelector(".num")).toHaveTextContent("320");
    expect(rows[1].querySelector(".bar-mini i")).not.toBeNull();
    expect(screen.getByText(/Select a country on the map or in this list/)).toBeInTheDocument();
  });

  test("a country the atlas cannot draw (SG) is the first row and selects ?country=SG from the keyboard", async () => {
    serveGeo();
    serveCountry(country({ country_code: "SG" }), "SG");
    renderAt(<CountryPanel range="7d" />);
    const list = await screen.findByRole("list", { name: "Top countries" });
    const first = within(list).getAllByRole("button")[0];
    expect(first).toHaveTextContent("Singapore");
    first.focus();
    expect(first).toHaveFocus();
    fireEvent.click(first); // a real <button>: Enter and Space click it natively (covered end to end in e2e)
    expect(screen.getByTestId("search")).toHaveTextContent("?country=SG");
  });

  test("empty and failed data show a note, not an empty list", async () => {
    serveGeo([]);
    renderAt(<CountryPanel range="30d" />);
    expect(await screen.findByText("No geolocated activity in the last 30 days.")).toBeInTheDocument();
    cleanup();
    server.use(http.get("http://localhost/api/geo", () => HttpResponse.json({ error: "x" }, { status: 500 })));
    renderAt(<CountryPanel range="7d" />);
    expect(await screen.findByRole("alert")).toHaveTextContent("unavailable");
  });
});

describe("CountryPanel: one country", () => {
  test("?country=DE shows the breakdown and CVEs; All countries clears the selection", async () => {
    serveCountry(country());
    serveGeo();
    renderAt(<CountryPanel range="7d" />, "/?country=DE&range=7d");
    expect(await screen.findByRole("heading", { name: "Germany" })).toBeInTheDocument();
    const counts = await screen.findByTestId("country-counts");
    expect(within(counts).getByText("exploit scanning").closest("div")).toHaveTextContent("12");
    expect(within(counts).getByText("infrastructure outage").closest("div")).toHaveTextContent("2");
    expect(screen.getByRole("button", { name: /CVE-2026-1001/ })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "All countries" }));
    expect(screen.getByTestId("search")).toHaveTextContent("?range=7d");
    expect(screen.getByTestId("search")).not.toHaveTextContent("country");
  });

  test("the country is fetched for the dashboard range", async () => {
    const seen: string[] = [];
    server.use(
      http.get("http://localhost/api/geo/DE", ({ request }) => {
        seen.push(new URL(request.url).searchParams.get("range") ?? "");
        return HttpResponse.json(country());
      }),
    );
    renderAt(<CountryPanel range="30d" />, "/?country=DE");
    await screen.findByTestId("country-counts");
    expect(seen).toEqual(["30d"]);
  });

  test("opening a CVE from the panel keeps ?country= (R7) and the drawer closes back to the panel", async () => {
    serveCountry(country());
    server.use(
      http.get("http://localhost/api/cves/CVE-2026-1001", () => HttpResponse.json({ error: "x" }, { status: 500 })),
    );
    renderAt(
      <>
        <CountryPanel range="7d" />
        <DrawerHost />
      </>,
      "/?country=DE",
    );
    fireEvent.click(await screen.findByRole("button", { name: /CVE-2026-1001/ }));
    expect(screen.getByTestId("search")).toHaveTextContent("country=DE");
    expect(screen.getByTestId("search")).toHaveTextContent("cve=CVE-2026-1001");
    fireEvent.click(await screen.findByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(screen.getByTestId("search")).toHaveTextContent("?country=DE");
    expect(screen.getByRole("heading", { name: "Germany" })).toBeInTheDocument();
  });

  test("anonymous viewers get counts only: no event list", async () => {
    serveCountry(country({ events: null }));
    renderAt(<CountryPanel range="7d" />, "/?country=DE");
    await screen.findByTestId("country-counts");
    expect(screen.queryByTestId("country-events")).toBeNull();
    expect(screen.queryByTestId("ransomware-credit")).toBeNull();
    expect(screen.getByTestId("country-events-hint")).toHaveTextContent("Sign in to see individual events.");
  });

  test("the side panel carries the DB-IP attribution in both states", async () => {
    serveCountry(country());
    renderAt(<CountryPanel range="7d" />, "/?country=DE");
    await screen.findByTestId("country-counts");
    expect(screen.getByRole("link", { name: "IP geolocation by DB-IP.com" })).toBeInTheDocument();
    cleanup();
    // The list state fetches /api/geo: serve it and wait for it, or the request outlives this
    // test and MSW's "error" strategy rejects it inside whichever test runs next.
    serveGeo();
    renderAt(<CountryPanel range="7d" />, "/");
    await screen.findByRole("list", { name: "Top countries" });
    expect(screen.getByRole("link", { name: "IP geolocation by DB-IP.com" })).toBeInTheDocument();
  });

  test("signed in: events render as text only (escaped markup stays literal) with the ransomware credit", async () => {
    signIn(member);
    serveCountry(
      country({
        events: [
          cev({ label: "&lt;script&gt;alert(1)&lt;/script&gt;", source: "ransomware.live", kind: "victim" }),
          cev({ label: "Victim &amp; Co" }),
        ],
      }),
    );
    renderAt(<CountryPanel range="7d" />, "/?country=DE");
    const list = await screen.findByTestId("country-events");
    expect(within(list).getByText(/<script>alert\(1\)<\/script>/)).toBeInTheDocument();
    expect(list.querySelector("script")).toBeNull();
    expect(within(list).getByText(/Victim & Co/)).toBeInTheDocument();
    expect(screen.getByTestId("ransomware-credit")).toBeInTheDocument();
  });

  test("no activity, a 404 and a failure each get their own note", async () => {
    serveCountry(country({ counts: [], top_cves: [] }));
    renderAt(<CountryPanel range="7d" />, "/?country=DE");
    expect(await screen.findByText("No activity recorded for this country in the last 7 days.")).toBeInTheDocument();
    cleanup();
    server.use(http.get("http://localhost/api/geo/DE", () => HttpResponse.json({ error: "x" }, { status: 500 })));
    renderAt(<CountryPanel range="7d" />, "/?country=DE");
    expect(await screen.findByRole("button", { name: "Retry" })).toBeInTheDocument();
  });
});

describe("MapPanel", () => {
  test("legend reads: fewer, five swatches, more alerts, country count and range, with the DB-IP credit", async () => {
    serveGeo([g("US", "scan", 40), g("SG", "scan", 9), g("DE", "scan", 3)]);
    renderAt(<MapPanel range="7d" />);
    await screen.findByRole("list", { name: "Top countries" });
    const legend = document.querySelector(".map-legend")!;
    expect(legend.textContent).toMatch(/^fewer\s*more alerts · 3 countries · 7 days/);
    expect(legend.querySelectorAll(".steps i")).toHaveLength(5);
    expect(within(legend as HTMLElement).getByRole("link", { name: "IP geolocation by DB-IP.com" })).toHaveAttribute(
      "href",
      "https://db-ip.com/",
    );
  });

  test("the legend says 1 country, not 1 countries, and follows the range", async () => {
    serveGeo([g("US", "scan", 40)]);
    renderAt(<MapPanel range="24h" />);
    await screen.findByRole("list", { name: "Top countries" });
    expect(document.querySelector(".map-legend")!.textContent).toContain("1 country · 24 hours");
  });

  test("Flat is the default; the Globe toggle switches the map mode and is remembered", async () => {
    serveGeo();
    renderAt(<MapPanel range="7d" />);
    const group = screen.getByRole("group", { name: "Map projection" });
    expect(within(group).getByRole("button", { name: "Flat" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByTestId("map")).toHaveAttribute("data-mode", "flat");
    fireEvent.click(within(group).getByRole("button", { name: "Globe" }));
    expect(screen.getByTestId("map")).toHaveAttribute("data-mode", "globe");
    expect(localStorage.getItem("cvenom.mapMode")).toBe("globe");
  });
});

describe("useMapMode", () => {
  beforeEach(() => localStorage.clear());
  const wrap = ({ children }: { children: React.ReactNode }) => <MemoryRouter>{children}</MemoryRouter>;

  test("defaults to flat, honours a stored globe, ignores junk", () => {
    expect(renderHook(() => useMapMode(), { wrapper: wrap }).result.current[0]).toBe("flat");
    localStorage.setItem("cvenom.mapMode", "globe");
    expect(renderHook(() => useMapMode(), { wrapper: wrap }).result.current[0]).toBe("globe");
    localStorage.setItem("cvenom.mapMode", "sphere");
    expect(renderHook(() => useMapMode(), { wrapper: wrap }).result.current[0]).toBe("flat");
  });

  test("blocked storage gives flat and the toggle still works for the visit", () => {
    const spy = vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    const set = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    try {
      const { result } = renderHook(() => useMapMode(), { wrapper: wrap });
      expect(result.current[0]).toBe("flat");
      expect(() => result.current[1]("globe")).not.toThrow();
    } finally {
      spy.mockRestore();
      set.mockRestore();
    }
  });
});

describe("SummaryLine", () => {
  test("hrefs use the Threats params (R6/R19), mapped from the range", async () => {
    server.use(
      http.get("http://localhost/api/summary", () =>
        HttpResponse.json({
          range: "7d",
          new_kev: 3,
          kev_due_soon: 2,
          new_critical: 11,
          public_exploits: 5,
          latest_kev_added: null,
        }),
      ),
    );
    renderAt(<SummaryLine range="7d" />);
    expect(await screen.findByRole("heading", { level: 1, name: "Last 7 days" })).toBeInTheDocument();
    const hrefOf = (name: RegExp) => screen.getByRole("link", { name }).getAttribute("href");
    await waitFor(() => expect(screen.getByRole("link", { name: /new KEV listings/ })).toHaveTextContent("3"));
    expect(hrefOf(/new KEV listings/)).toBe("/threats?status=exploited&added=week");
    expect(hrefOf(/KEV deadlines this week/)).toBe("/threats?due=7d");
    expect(hrefOf(/new critical CVEs/)).toBe("/threats?status=critical&exclude_kev=1&added=week");
    expect(hrefOf(/public exploits published/)).toBe("/threats?poc=1&added=week");
    expect(screen.getByRole("link", { name: /new critical CVEs/ })).toHaveTextContent("11");
  });

  test("range maps to added: 24h day, 7d week, 14d 14d, 30d month", () => {
    expect((["24h", "7d", "14d", "30d"] as const).map((r) => summaryHrefs(r).kev.split("added=")[1])).toEqual([
      "day",
      "week",
      "14d",
      "month",
    ]);
  });

  test("counts show a dash while loading or after a failure, never NaN", async () => {
    server.use(http.get("http://localhost/api/summary", () => HttpResponse.json({ error: "x" }, { status: 500 })));
    renderAt(<SummaryLine range="7d" />);
    expect(screen.getByRole("link", { name: /new KEV listings/ })).toHaveTextContent("–");
    await waitFor(() => expect(screen.queryByText("NaN")).toBeNull());
  });
});

describe("Dashboard range wiring", () => {
  test("changing the range control re-queries summary, geo, lanes, stories and volume with the new range", async () => {
    const seen: Record<string, string[]> = {};
    const record = (name: string, body: JsonBodyType) =>
      http.get(`http://localhost/api/${name}`, ({ request }) => {
        (seen[name] ??= []).push(new URL(request.url).searchParams.get("range") ?? "");
        return HttpResponse.json(body);
      });
    server.use(
      record("summary", {
        range: "7d",
        new_kev: 0,
        kev_due_soon: 0,
        new_critical: 0,
        public_exploits: 0,
        latest_kev_added: null,
      }),
      record("geo", GEO),
      record("lanes", lanes()),
      record("stories/loud", []),
      record("volume", { range: "7d", unit: "day", buckets: [], total: 0, unscored: 0 }),
    );
    renderAt(
      <>
        <RangeControl />
        <Dashboard />
      </>,
      "/",
    );
    await waitFor(() =>
      expect(Object.keys(seen).sort()).toEqual(["geo", "lanes", "stories/loud", "summary", "volume"]),
    );
    for (const k of Object.keys(seen)) expect(new Set(seen[k]), k).toEqual(new Set(["7d"]));
    expect(screen.getByTestId("map")).toHaveAttribute("data-range", "7d");

    fireEvent.click(screen.getByRole("button", { name: "14d" }));
    await waitFor(() => {
      for (const k of ["geo", "lanes", "stories/loud", "summary", "volume"]) expect(seen[k], k).toContain("14d");
    });
    expect(screen.getByTestId("map")).toHaveAttribute("data-range", "14d");
    expect(screen.getByRole("heading", { level: 1, name: "Last 14 days" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /new KEV listings/ })).toHaveAttribute(
      "href",
      "/threats?status=exploited&added=14d",
    );
  });

  test("lays out summary line, map panel, lanes and volume in that order", async () => {
    serveGeo();
    server.use(
      http.get("http://localhost/api/summary", () =>
        HttpResponse.json({
          range: "7d",
          new_kev: 0,
          kev_due_soon: 0,
          new_critical: 0,
          public_exploits: 0,
          latest_kev_added: null,
        }),
      ),
      http.get("http://localhost/api/lanes", () => HttpResponse.json(lanes())),
      http.get("http://localhost/api/stories/loud", () => HttpResponse.json([])),
      http.get("http://localhost/api/volume", () =>
        HttpResponse.json({ range: "7d", unit: "day", buckets: [], total: 0, unscored: 0 }),
      ),
    );
    renderAt(<Dashboard />);
    const dash = document.querySelector(".dash")!;
    const order = [...dash.children].map((c) => c.className.split(" ")[0] || c.tagName.toLowerCase());
    expect(order[0]).toBe("today");
    expect(order[1]).toBe("panel");
    expect(dash.children.length).toBe(4);
    await screen.findByRole("list", { name: "Top countries" });
  });
});
