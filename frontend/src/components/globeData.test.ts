import type { Feature, Geometry, Position } from "geojson";
import { describe, expect, it } from "vitest";
import type { GeoSummaryItem } from "../lib/types";
import {
  CHORO_STEPS,
  NUMERIC_TO_ISO2,
  centroids,
  choroplethBucket,
  countries,
  countryTotals,
  describeGeo,
  iso2FromFeature,
  mixColor,
  rankCountries,
  withBuckets,
} from "./globeData";

const g = (country_code: string | null, kind: string, magnitude = 1, events = 1): GeoSummaryItem => ({
  country_code: country_code as string,
  kind,
  magnitude,
  events,
  last_seen: "2026-11-05T00:00:00Z",
});

const feat = (id: unknown, name?: string): Feature<Geometry | null> =>
  ({ type: "Feature", id, properties: name ? { name } : {}, geometry: null }) as Feature<Geometry | null>;

type BBox = [minLon: number, minLat: number, maxLon: number, maxLat: number];
function inside([lon, lat]: [number, number], [x0, y0, x1, y1]: BBox): boolean {
  return lon >= x0 && lon <= x1 && lat >= y0 && lat <= y1;
}

describe("choroplethBucket", () => {
  it("sqrt-scales into 5 buckets, capped at 4", () => {
    const cases: [number, number, number | null][] = [
      [100, 100, 4],
      [1, 100, 0],
      [4, 100, 1],
      [64, 100, 4],
      [16, 100, 2],
      [36, 100, 3],
      [0, 100, null],
      [5, 0, null],
      [Number.NaN, 10, null],
      [10, Number.NaN, null],
      [-3, 10, null],
    ];
    for (const [n, max, want] of cases) expect(choroplethBucket(n, max), `${n}/${max}`).toBe(want);
  });

  it("a single country is its own maximum and gets bucket 4", () => {
    expect(choroplethBucket(7, 7)).toBe(4);
  });

  it("documents the colour steps", () => {
    expect([...CHORO_STEPS]).toEqual([0.16, 0.32, 0.5, 0.7, 0.9]);
  });
});

describe("countryTotals", () => {
  it("sums events across kinds per valid ISO-2", () => {
    const t = countryTotals([g("US", "scan", 1, 30), g("US", "victim", 1, 4), g("NL", "c2", 1, 2)]);
    expect([...t.entries()].sort()).toEqual([
      ["NL", 2],
      ["US", 34],
    ]);
  });

  it("ignores XX, lowercase, malformed and null codes, and counts NaN or negative events as 0", () => {
    const t = countryTotals([
      g("XX", "scan", 1, 99),
      g("us", "scan", 1, 99),
      g("USA", "scan", 1, 99),
      g(null, "scan", 1, 99),
      g("DE", "scan", 1, Number.NaN),
      g("DE", "c2", 1, -5),
      g("FR", "scan", 1, 3),
    ]);
    expect([...t.entries()].sort()).toEqual([
      ["DE", 0],
      ["FR", 3],
    ]);
  });
});

describe("iso2FromFeature", () => {
  it("maps world-atlas numeric ids", () => {
    expect(iso2FromFeature(feat("840"))).toBe("US");
    expect(iso2FromFeature(feat("528"))).toBe("NL");
    expect(iso2FromFeature(feat("392"))).toBe("JP");
    expect(iso2FromFeature(feat("250"))).toBe("FR");
    expect(iso2FromFeature(feat("036"))).toBe("AU");
    expect(iso2FromFeature(feat("076"))).toBe("BR");
  });

  it("accepts numeric ids given as numbers", () => {
    expect(iso2FromFeature(feat(36))).toBe("AU");
  });

  it("maps the id-less features by name (Kosovo, and ISO's assignment for the two unrecognised ones)", () => {
    expect(iso2FromFeature(feat(undefined, "Kosovo"))).toBe("XK");
    expect(iso2FromFeature(feat(undefined, "Somaliland"))).toBe("SO");
    expect(iso2FromFeature(feat(undefined, "N. Cyprus"))).toBe("CY");
  });

  it("returns null for unknown ids and names", () => {
    expect(iso2FromFeature(feat("999"))).toBeNull();
    expect(iso2FromFeature(feat(undefined))).toBeNull();
    expect(iso2FromFeature(feat(undefined, "Atlantis"))).toBeNull();
    expect(iso2FromFeature(feat("abc"))).toBeNull();
  });

  it("table is well-formed: 3-digit keys, unique upper-case ISO-2 values", () => {
    const entries = Object.entries(NUMERIC_TO_ISO2);
    expect(entries.length).toBe(249);
    for (const [k, v] of entries) {
      expect(k).toMatch(/^\d{3}$/);
      expect(v).toMatch(/^[A-Z]{2}$/);
    }
    expect(new Set(entries.map(([, v]) => v)).size).toBe(entries.length);
  });

  it("every bundled country polygon resolves to an ISO-2 code", () => {
    expect(countries.features.length).toBe(177);
    for (const f of countries.features) expect(f.properties.iso2, String(f.properties.name)).toMatch(/^[A-Z]{2}$/);
  });
});

describe("antimeridian handling", () => {
  function rings(geom: Geometry): Position[][] {
    if (geom.type === "Polygon") return geom.coordinates;
    if (geom.type === "MultiPolygon") return geom.coordinates.flat();
    return [];
  }
  it("no country ring jumps across the antimeridian (Russia, Fiji are unwrapped)", () => {
    for (const f of countries.features) {
      if (f.properties.iso2 === "AQ") continue; // the polar ring legitimately spans 360 degrees
      for (const r of rings(f.geometry)) {
        for (let i = 1; i < r.length; i++) {
          expect(Math.abs(r[i][0] - r[i - 1][0]), `${f.properties.name} ring jump`).toBeLessThan(180);
        }
      }
    }
  });
  it("Antarctica keeps its pole-encircling ring intact", () => {
    const aq = countries.features.find((f) => f.properties.iso2 === "AQ");
    expect(aq).toBeDefined();
    const lons = rings(aq!.geometry)
      .flat()
      .map((p) => p[0]);
    expect(Math.min(...lons)).toBe(-180);
    expect(Math.max(...lons)).toBe(180);
  });
});

describe("centroids", () => {
  const boxes: Record<string, BBox> = {
    US: [-125, 24, -66, 50],
    NL: [3.3, 50.7, 7.3, 53.6],
    JP: [129, 30, 146, 46],
    AU: [113, -44, 154, -10],
    BR: [-74, -34, -34, 6],
    // metropolitan France: overseas territories (French Guiana) must not drag it into the Atlantic
    FR: [-5, 41, 10, 51],
  };
  for (const [iso, box] of Object.entries(boxes)) {
    it(`${iso} centroid lies inside its bbox`, () => {
      const c = centroids.get(iso);
      expect(c, iso).toBeDefined();
      expect(inside(c!, box), `${iso} ${c}`).toBe(true);
    });
  }
  it("Russia and Fiji centroids are sane despite crossing the antimeridian", () => {
    expect(inside(centroids.get("RU")!, [30, 50, 140, 72])).toBe(true);
    const fj = centroids.get("FJ")!;
    expect(Math.abs(Math.abs(fj[0]) - 179)).toBeLessThan(2.5);
    expect(fj[1]).toBeGreaterThan(-19);
    expect(fj[1]).toBeLessThan(-15);
  });
  it("all centroid longitudes are normalised to [-180, 180]", () => {
    for (const [, [lon, lat]] of centroids) {
      expect(lon).toBeGreaterThanOrEqual(-180);
      expect(lon).toBeLessThanOrEqual(180);
      expect(Math.abs(lat)).toBeLessThanOrEqual(90);
    }
  });
  it("has fallback points for small states missing from the 110m polygons", () => {
    expect(inside(centroids.get("SG")!, [103.5, 1.1, 104.2, 1.5])).toBe(true);
    expect(inside(centroids.get("HK")!, [113.8, 22.1, 114.5, 22.6])).toBe(true);
  });
});

describe("withBuckets", () => {
  const feature = (fc: ReturnType<typeof withBuckets>, iso: string) =>
    fc.features.find((f) => f.properties.iso2 === iso)!.properties;

  it("stamps each country with its bucket and count (-1 / 0 when there is no activity)", () => {
    const fc = withBuckets(
      new Map([
        ["US", 100],
        ["DE", 4],
        ["SG", 50],
      ]),
    );
    expect(feature(fc, "US")).toMatchObject({ bucket: 4, n: 100 });
    expect(feature(fc, "DE")).toMatchObject({ bucket: 1, n: 4 });
    expect(feature(fc, "FR")).toMatchObject({ bucket: -1, n: 0 });
  });

  it("a country the 110m atlas cannot draw still counts toward the maximum", () => {
    expect(countries.features.some((f) => f.properties.iso2 === "SG")).toBe(false);
    // US 25 against max 100 (SG) is bucket 2, not 4
    expect(
      feature(
        withBuckets(
          new Map([
            ["US", 25],
            ["SG", 100],
          ]),
        ),
        "US",
      ).bucket,
    ).toBe(2);
  });

  it("one country alone is bucket 4", () => {
    expect(feature(withBuckets(new Map([["JP", 3]])), "JP").bucket).toBe(4);
  });

  it("an empty, all-zero or NaN map paints nothing and does not throw", () => {
    for (const m of [new Map<string, number>(), new Map([["US", 0]]), new Map([["US", Number.NaN]])]) {
      const fc = withBuckets(m);
      expect(fc.features.every((f) => f.properties.bucket === -1 && f.properties.n === 0)).toBe(true);
    }
  });

  it("leaves Antarctica out and keeps every other bundled country", () => {
    const fc = withBuckets(new Map());
    expect(fc.features.some((f) => f.properties.iso2 === "AQ")).toBe(false);
    expect(fc.features.length).toBe(countries.features.filter((f) => f.properties.iso2 !== "AQ").length);
  });
});

describe("rankCountries and describeGeo", () => {
  const totals = countryTotals([
    g("US", "scan", 8, 300),
    g("US", "outage", 2, 5),
    g("NL", "scan", 1, 9),
    g("SG", "scan", 1, 400),
  ]);
  it("ranks by events, keeping countries without a polygon", () => {
    expect(rankCountries(totals).map((r) => r.iso2)).toEqual(["SG", "US", "NL"]);
    expect(rankCountries(totals, 1)).toHaveLength(1);
    expect(rankCountries(totals)[1]).toMatchObject({ name: "United States", events: 305 });
  });
  it("breaks ties by code and drops zero-event countries", () => {
    expect(
      rankCountries(
        new Map([
          ["FR", 5],
          ["DE", 5],
          ["IT", 0],
        ]),
      ).map((r) => r.iso2),
    ).toEqual(["DE", "FR"]);
  });
  it("summarises the data for the map's accessible name", () => {
    expect(describeGeo(totals, "7 days")).toBe(
      "Threat map: 3 countries with activity in the last 7 days; most active Singapore, 400 events",
    );
    expect(describeGeo(new Map(), "7 days")).toBe("Threat map: no geolocated threat activity in the last 7 days");
  });
});

describe("mixColor", () => {
  it("blends hex colours by alpha", () => {
    expect(mixColor("#000000", "#ffffff", 0.5)).toBe("#808080");
    expect(mixColor("#2b3f54", "#ff9a44", 0)).toBe("#2b3f54");
    expect(mixColor("#2b3f54", "#ff9a44", 1)).toBe("#ff9a44");
    expect(mixColor("#fff", "#000", 1)).toBe("#000000");
  });
  it("falls back to the base colour when the overlay is unparseable", () => {
    expect(mixColor("#123456", "not-a-colour", 0.5)).toBe("#123456");
  });
});
