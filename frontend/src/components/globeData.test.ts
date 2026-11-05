import type { Feature, Geometry, Position } from "geojson";
import { describe, expect, it } from "vitest";
import type { GeoSummaryItem } from "../lib/types";
import {
  KIND_OFFSET,
  NUMERIC_TO_ISO2,
  OUTAGE_LEVEL_1_MAX,
  OUTAGE_LEVEL_2_MAX,
  RADIUS_MAX,
  RADIUS_MIN,
  centroids,
  circleRadius,
  countries,
  describeGeo,
  iso2FromFeature,
  mixColor,
  rankCountries,
  toCountryShading,
  toHotspots,
  withShading,
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

describe("toCountryShading", () => {
  it("documents its bucket thresholds as constants", () => {
    expect(OUTAGE_LEVEL_1_MAX).toBe(2);
    expect(OUTAGE_LEVEL_2_MAX).toBe(5);
  });

  it("buckets outage magnitude: 0 none, 1 below 2, 2 below 5, 3 at 5 and above", () => {
    const cases: [number, number][] = [
      [0, 0],
      [0.01, 1],
      [1.99, 1],
      [2, 2],
      [4.99, 2],
      [5, 3],
      [500, 3],
      [-1, 0],
      [Number.NaN, 0],
      [Number.POSITIVE_INFINITY, 0],
    ];
    for (const [m, level] of cases) {
      expect(toCountryShading([g("US", "outage", m)]).get("US") ?? 0, `magnitude ${m}`).toBe(level);
    }
  });

  it("uses only outage items", () => {
    const s = toCountryShading([g("US", "scan", 50), g("DE", "victim", 9), g("FR", "outage", 3)]);
    expect([...s.entries()]).toEqual([["FR", 2]]);
  });

  it("ignores null, lowercase and malformed country codes", () => {
    const s = toCountryShading([g(null, "outage", 9), g("us", "outage", 9), g("USA", "outage", 9), g("", "outage", 9)]);
    expect(s.size).toBe(0);
  });

  it("returns an empty map for empty input", () => {
    expect(toCountryShading([]).size).toBe(0);
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
    const lons = rings(aq!.geometry).flat().map((p) => p[0]);
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

describe("toHotspots", () => {
  it("emits one point per (country, kind) with kind, magnitude, events and iso2", () => {
    const fc = toHotspots([g("US", "scan", 7, 120), g("US", "outage", 3, 4), g("NL", "c2", 1, 2)]);
    expect(fc.type).toBe("FeatureCollection");
    expect(fc.features).toHaveLength(3);
    const us = fc.features.find((f) => f.properties.iso2 === "US" && f.properties.kind === "scan")!;
    expect(us.geometry.type).toBe("Point");
    expect(us.properties).toMatchObject({ kind: "scan", magnitude: 7, events: 120, iso2: "US" });
  });

  it("skips null, unknown, lowercase and malformed countries, and unknown kinds", () => {
    const fc = toHotspots([
      g(null, "scan"),
      g("", "scan"),
      g("ZZ", "scan"),
      g("us", "scan"),
      g("USA", "scan"),
      g("US", "ufo"),
      g("JP", "bgp"),
    ]);
    expect(fc.features.map((f) => f.properties.iso2)).toEqual(["JP"]);
  });

  it("offsets kinds sharing a country deterministically, staying near the centroid", () => {
    const items = ["scan", "outage", "victim", "c2", "bgp"].map((k) => g("DE", k, 2));
    const a = toHotspots(items);
    const b = toHotspots(items);
    expect(a).toEqual(b);
    const coords = a.features.map((f) => f.geometry.coordinates.join(","));
    expect(new Set(coords).size).toBe(5);
    const [cx, cy] = centroids.get("DE")!;
    for (const f of a.features) {
      const [x, y] = f.geometry.coordinates;
      expect(Math.hypot(x - cx, y - cy)).toBeLessThan(2);
    }
    expect(Object.keys(KIND_OFFSET).sort()).toEqual(["bgp", "c2", "outage", "scan", "victim"]);
  });

  it("carries a clamped radius for the circle layer", () => {
    const fc = toHotspots([g("US", "scan", 1e9)]);
    expect(fc.features[0].properties.r).toBe(RADIUS_MAX);
  });

  it("returns an empty collection for empty input", () => {
    expect(toHotspots([]).features).toEqual([]);
  });
});

describe("circleRadius", () => {
  it("clamps to [3, 18] px on a log scale", () => {
    expect(RADIUS_MIN).toBe(3);
    expect(RADIUS_MAX).toBe(18);
    expect(circleRadius(0)).toBe(3);
    expect(circleRadius(-5)).toBe(3);
    expect(circleRadius(Number.NaN)).toBe(3);
    expect(circleRadius(1e12)).toBe(18);
    const r = [0.5, 1, 2, 5, 10, 20].map(circleRadius);
    for (let i = 1; i < r.length; i++) expect(r[i]).toBeGreaterThan(r[i - 1]);
    // log scale: doubling from 10 to 20 adds far less than doubling from 0.5 to 1 relative to magnitude
    expect(circleRadius(20) - circleRadius(10)).toBeLessThan(circleRadius(10) - circleRadius(0));
  });
});

describe("withShading", () => {
  it("stamps each country with its shading level (0 when absent)", () => {
    const fc = withShading(new Map([["US", 3 as const]]));
    const us = fc.features.find((f) => f.properties.iso2 === "US")!;
    const de = fc.features.find((f) => f.properties.iso2 === "DE")!;
    expect(us.properties.level).toBe(3);
    expect(de.properties.level).toBe(0);
    expect(fc.features).toHaveLength(countries.features.length);
  });
});

describe("rankCountries and describeGeo", () => {
  const items = [g("US", "scan", 8, 300), g("US", "outage", 2), g("NL", "scan", 1), g("JP", "outage", 6), g(null, "scan", 99)];
  it("ranks valid countries by total magnitude", () => {
    expect(rankCountries(items).map((r) => r.iso2)).toEqual(["US", "JP", "NL"]);
    expect(rankCountries(items, 1)).toHaveLength(1);
  });
  it("summarises the data for the globe's accessible name", () => {
    expect(describeGeo(items)).toBe(
      "Global threat map: 2 countries with outages, 2 countries with exploit scanning",
    );
    expect(describeGeo([])).toBe("Global threat map: no geolocated threat activity in the last 24 hours");
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
