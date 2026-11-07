/**
 * World geometry for the globe: the bundled world-atlas countries-110m TopoJSON (imported as a
 * JSON module, so it ships inside the lazy globe chunk and is served from self), converted once
 * to GeoJSON, keyed by ISO-2, with antimeridian-safe rings and per-country centroids.
 *
 * This module is only imported by the lazy <Globe> chunk. Atlas-free helpers live in
 * geoSummary.ts and are re-exported here.
 */
import type { Feature, FeatureCollection, Geometry, MultiPolygon, Polygon, Position } from "geojson";
import { feature } from "topojson-client";
import type { GeometryCollection, Topology } from "topojson-specification";
import atlas from "world-atlas/countries-110m.json";
import { choroplethBucket } from "./geoSummary";

export * from "./geoSummary";

/**
 * ISO 3166-1 numeric -> alpha-2, all 249 officially assigned codes. world-atlas feature ids are
 * these numeric codes as zero-padded strings ("840"). Verified against an independent ISO
 * dataset when written; the unit test pins the size and shape.
 */
export const NUMERIC_TO_ISO2: Readonly<Record<string, string>> = {
  "004": "AF",
  "008": "AL",
  "010": "AQ",
  "012": "DZ",
  "016": "AS",
  "020": "AD",
  "024": "AO",
  "028": "AG",
  "031": "AZ",
  "032": "AR",
  "036": "AU",
  "040": "AT",
  "044": "BS",
  "048": "BH",
  "050": "BD",
  "051": "AM",
  "052": "BB",
  "056": "BE",
  "060": "BM",
  "064": "BT",
  "068": "BO",
  "070": "BA",
  "072": "BW",
  "074": "BV",
  "076": "BR",
  "084": "BZ",
  "086": "IO",
  "090": "SB",
  "092": "VG",
  "096": "BN",
  "100": "BG",
  "104": "MM",
  "108": "BI",
  "112": "BY",
  "116": "KH",
  "120": "CM",
  "124": "CA",
  "132": "CV",
  "136": "KY",
  "140": "CF",
  "144": "LK",
  "148": "TD",
  "152": "CL",
  "156": "CN",
  "158": "TW",
  "162": "CX",
  "166": "CC",
  "170": "CO",
  "174": "KM",
  "175": "YT",
  "178": "CG",
  "180": "CD",
  "184": "CK",
  "188": "CR",
  "191": "HR",
  "192": "CU",
  "196": "CY",
  "203": "CZ",
  "204": "BJ",
  "208": "DK",
  "212": "DM",
  "214": "DO",
  "218": "EC",
  "222": "SV",
  "226": "GQ",
  "231": "ET",
  "232": "ER",
  "233": "EE",
  "234": "FO",
  "238": "FK",
  "239": "GS",
  "242": "FJ",
  "246": "FI",
  "248": "AX",
  "250": "FR",
  "254": "GF",
  "258": "PF",
  "260": "TF",
  "262": "DJ",
  "266": "GA",
  "268": "GE",
  "270": "GM",
  "275": "PS",
  "276": "DE",
  "288": "GH",
  "292": "GI",
  "296": "KI",
  "300": "GR",
  "304": "GL",
  "308": "GD",
  "312": "GP",
  "316": "GU",
  "320": "GT",
  "324": "GN",
  "328": "GY",
  "332": "HT",
  "334": "HM",
  "336": "VA",
  "340": "HN",
  "344": "HK",
  "348": "HU",
  "352": "IS",
  "356": "IN",
  "360": "ID",
  "364": "IR",
  "368": "IQ",
  "372": "IE",
  "376": "IL",
  "380": "IT",
  "384": "CI",
  "388": "JM",
  "392": "JP",
  "398": "KZ",
  "400": "JO",
  "404": "KE",
  "408": "KP",
  "410": "KR",
  "414": "KW",
  "417": "KG",
  "418": "LA",
  "422": "LB",
  "426": "LS",
  "428": "LV",
  "430": "LR",
  "434": "LY",
  "438": "LI",
  "440": "LT",
  "442": "LU",
  "446": "MO",
  "450": "MG",
  "454": "MW",
  "458": "MY",
  "462": "MV",
  "466": "ML",
  "470": "MT",
  "474": "MQ",
  "478": "MR",
  "480": "MU",
  "484": "MX",
  "492": "MC",
  "496": "MN",
  "498": "MD",
  "499": "ME",
  "500": "MS",
  "504": "MA",
  "508": "MZ",
  "512": "OM",
  "516": "NA",
  "520": "NR",
  "524": "NP",
  "528": "NL",
  "531": "CW",
  "533": "AW",
  "534": "SX",
  "535": "BQ",
  "540": "NC",
  "548": "VU",
  "554": "NZ",
  "558": "NI",
  "562": "NE",
  "566": "NG",
  "570": "NU",
  "574": "NF",
  "578": "NO",
  "580": "MP",
  "581": "UM",
  "583": "FM",
  "584": "MH",
  "585": "PW",
  "586": "PK",
  "591": "PA",
  "598": "PG",
  "600": "PY",
  "604": "PE",
  "608": "PH",
  "612": "PN",
  "616": "PL",
  "620": "PT",
  "624": "GW",
  "626": "TL",
  "630": "PR",
  "634": "QA",
  "638": "RE",
  "642": "RO",
  "643": "RU",
  "646": "RW",
  "652": "BL",
  "654": "SH",
  "659": "KN",
  "660": "AI",
  "662": "LC",
  "663": "MF",
  "666": "PM",
  "670": "VC",
  "674": "SM",
  "678": "ST",
  "682": "SA",
  "686": "SN",
  "688": "RS",
  "690": "SC",
  "694": "SL",
  "702": "SG",
  "703": "SK",
  "704": "VN",
  "705": "SI",
  "706": "SO",
  "710": "ZA",
  "716": "ZW",
  "724": "ES",
  "728": "SS",
  "729": "SD",
  "732": "EH",
  "740": "SR",
  "744": "SJ",
  "748": "SZ",
  "752": "SE",
  "756": "CH",
  "760": "SY",
  "762": "TJ",
  "764": "TH",
  "768": "TG",
  "772": "TK",
  "776": "TO",
  "780": "TT",
  "784": "AE",
  "788": "TN",
  "792": "TR",
  "795": "TM",
  "796": "TC",
  "798": "TV",
  "800": "UG",
  "804": "UA",
  "807": "MK",
  "818": "EG",
  "826": "GB",
  "831": "GG",
  "832": "JE",
  "833": "IM",
  "834": "TZ",
  "840": "US",
  "850": "VI",
  "854": "BF",
  "858": "UY",
  "860": "UZ",
  "862": "VE",
  "876": "WF",
  "882": "WS",
  "887": "YE",
  "894": "ZM",
};

/**
 * world-atlas features that carry no numeric id. Kosovo uses the user-assigned "XK" that
 * GeoIP databases (DB-IP included) emit. Somaliland and Northern Cyprus have no ISO code;
 * ISO 3166 (and GeoIP data) assigns their territory to SO and CY, so they shade with those.
 */
const NAME_TO_ISO2: Readonly<Record<string, string>> = {
  Kosovo: "XK",
  Somaliland: "SO",
  "N. Cyprus": "CY",
};

/** ISO-2 for a world-atlas feature, or null if its id/name is unknown. */
export function iso2FromFeature(f: Pick<Feature, "id" | "properties"> | null | undefined): string | null {
  if (!f) return null;
  const id = f.id;
  if (typeof id === "number" && Number.isInteger(id) && id >= 0 && id < 1000) {
    return NUMERIC_TO_ISO2[String(id).padStart(3, "0")] ?? null;
  }
  if (typeof id === "string" && /^\d{1,3}$/.test(id)) return NUMERIC_TO_ISO2[id.padStart(3, "0")] ?? null;
  if (id !== undefined && id !== null && id !== "") return null;
  const name = f.properties?.name;
  return typeof name === "string" ? (NAME_TO_ISO2[name] ?? null) : null;
}

// ---- antimeridian ---------------------------------------------------------------

/**
 * TopoJSON quantisation leaves some vertices of the Russian and Fijian rings at -180 while
 * their neighbours sit near +180, so a ring "jumps" 360 degrees and renders as a stripe
 * across the globe. Unwrap such rings into continuous longitudes (e.g. 178 -> 180 -> 181);
 * MapLibre's GeoJSON tiler wraps coordinates beyond +-180 into the adjacent world copy.
 *
 * A ring whose unwrapped walk does not close (net winding of 360, like Antarctica's ring
 * around the south pole) is left untouched: that edge is a legitimate pole-encircling seam.
 */
export function unwrapRing(ring: Position[]): Position[] {
  if (ring.length < 2) return ring;
  const out: Position[] = [ring[0].slice()];
  let shift = 0;
  let jumped = false;
  for (let i = 1; i < ring.length; i++) {
    const d = ring[i][0] - ring[i - 1][0];
    if (d > 180) {
      shift -= 360;
      jumped = true;
    } else if (d < -180) {
      shift += 360;
      jumped = true;
    }
    out.push([ring[i][0] + shift, ...ring[i].slice(1)]);
  }
  if (!jumped || shift !== 0) return ring;
  // Keep the bulk of the ring on the side it mostly lives on (Russia: east of 0, shifted points >180).
  return out;
}

function unwrapGeometry(g: Geometry | null): Polygon | MultiPolygon | null {
  if (!g) return null;
  if (g.type === "Polygon") return { type: "Polygon", coordinates: g.coordinates.map(unwrapRing) };
  if (g.type === "MultiPolygon")
    return { type: "MultiPolygon", coordinates: g.coordinates.map((p) => p.map(unwrapRing)) };
  return null;
}

// ---- countries ----------------------------------------------------------------

export interface CountryProps {
  iso2: string;
  name: string;
  /** Choropleth bucket 0..4 (darker = more alerts), or -1 for no activity. Stamped by withBuckets(). */
  bucket: -1 | 0 | 1 | 2 | 3 | 4;
  /** Events in the selected range (0 for none). */
  n: number;
}
export type CountryFeature = Feature<Polygon | MultiPolygon, CountryProps>;

const topo = atlas as unknown as Topology<{ countries: GeometryCollection<{ name: string }> }>;

function buildCountries(): FeatureCollection<Polygon | MultiPolygon, CountryProps> {
  const raw = feature(topo, topo.objects.countries) as FeatureCollection<Geometry | null, { name: string }>;
  const out: CountryFeature[] = [];
  for (const f of raw.features) {
    const iso2 = iso2FromFeature(f);
    const geometry = unwrapGeometry(f.geometry);
    if (!iso2 || !geometry) continue; // unknown or empty features are skipped, never guessed
    out.push({ type: "Feature", properties: { iso2, name: f.properties?.name ?? iso2, bucket: -1, n: 0 }, geometry });
  }
  return { type: "FeatureCollection", features: out };
}

/** All country polygons (no activity), computed once at module load. */
export const countries = buildCountries();

/**
 * A copy of the countries collection with each feature's choropleth bucket and count set from `totals`
 * (events per ISO-2). The maximum is taken over all totals, including countries the 110m atlas cannot draw.
 * Antarctica is left out: it is never an alert country and dominates a Mercator map.
 */
export function withBuckets(
  totals: ReadonlyMap<string, number>,
): FeatureCollection<Polygon | MultiPolygon, CountryProps> {
  let max = 0;
  for (const v of totals.values()) if (Number.isFinite(v) && v > max) max = v;
  return {
    type: "FeatureCollection",
    features: countries.features
      .filter((f) => f.properties.iso2 !== "AQ")
      .map((f) => {
        const n = totals.get(f.properties.iso2) ?? 0;
        const b = choroplethBucket(n, max);
        return { ...f, properties: { ...f.properties, bucket: b ?? -1, n: b === null ? 0 : n } };
      }),
  };
}

// ---- centroids ----------------------------------------------------------------

/** Signed area and area-weighted centroid of a ring (planar, x scaled by cos(latitude)). */
function ringStats(ring: Position[]): { area: number; cx: number; cy: number } {
  const lat0 = ring.reduce((s, p) => s + p[1], 0) / ring.length;
  const k = Math.cos((lat0 * Math.PI) / 180) || 1e-6;
  let a = 0;
  let cx = 0;
  let cy = 0;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const x0 = ring[j][0] * k;
    const y0 = ring[j][1];
    const x1 = ring[i][0] * k;
    const y1 = ring[i][1];
    const cross = x0 * y1 - x1 * y0;
    a += cross;
    cx += (x0 + x1) * cross;
    cy += (y0 + y1) * cross;
  }
  a /= 2;
  if (Math.abs(a) < 1e-12) {
    const n = ring.length;
    return { area: 0, cx: ring.reduce((s, p) => s + p[0], 0) / n, cy: lat0 };
  }
  return { area: Math.abs(a), cx: cx / (6 * a) / k, cy: cy / (6 * a) };
}

const normLon = (lon: number) => ((((lon + 180) % 360) + 360) % 360) - 180;

/**
 * Centroid of a country: the area-weighted centroid of its LARGEST polygon (outer ring), so
 * France sits in metropolitan France rather than being dragged toward French Guiana.
 */
function largestPolygonCentroid(g: Polygon | MultiPolygon): [number, number] | null {
  const polys = g.type === "Polygon" ? [g.coordinates] : g.coordinates;
  let best: { area: number; cx: number; cy: number } | null = null;
  for (const p of polys) {
    if (!p[0] || p[0].length < 3) continue;
    const s = ringStats(p[0]);
    if (!best || s.area > best.area) best = s;
  }
  return best ? [normLon(best.cx), best.cy] : null;
}

/**
 * Points for states too small for the 110m polygons (used by flyTo).
 * Approximate [lon, lat] of each territory's main island / capital.
 */
const SMALL_TERRITORY_POINTS: Readonly<Record<string, [number, number]>> = {
  SG: [103.82, 1.35],
  HK: [114.17, 22.32],
  MO: [113.55, 22.2],
  MT: [14.45, 35.9],
  BH: [50.55, 26.07],
  MU: [57.55, -20.25],
  MV: [73.22, 3.2],
  SC: [55.49, -4.68],
  BB: [-59.54, 13.19],
  AD: [1.6, 42.55],
  MC: [7.42, 43.74],
  LI: [9.55, 47.16],
  SM: [12.46, 43.94],
  VA: [12.45, 41.9],
  GI: [-5.35, 36.14],
  BM: [-64.75, 32.31],
  KY: [-81.25, 19.31],
  AG: [-61.8, 17.08],
  LC: [-60.98, 13.91],
  GD: [-61.68, 12.12],
  VC: [-61.2, 13.25],
  KN: [-62.72, 17.3],
  DM: [-61.35, 15.42],
  AW: [-69.97, 12.52],
  CW: [-68.98, 12.17],
  GU: [144.79, 13.44],
  WS: [-172.1, -13.76],
  TO: [-175.2, -21.18],
  CV: [-23.6, 15.1],
  ST: [6.61, 0.19],
  KM: [43.87, -11.88],
  IM: [-4.55, 54.24],
  JE: [-2.13, 49.21],
  GG: [-2.58, 49.45],
  FO: [-6.79, 62.0],
  PF: [-149.41, -17.68],
  RE: [55.54, -21.12],
  MQ: [-61.02, 14.64],
  GP: [-61.58, 16.25],
};

function buildCentroids(): Map<string, [number, number]> {
  const best = new Map<string, { area: number; c: [number, number] }>();
  for (const f of countries.features) {
    const polys = f.geometry.type === "Polygon" ? [f.geometry.coordinates] : f.geometry.coordinates;
    const area = Math.max(0, ...polys.map((p) => (p[0] ? ringStats(p[0]).area : 0)));
    const c = largestPolygonCentroid(f.geometry);
    if (!c) continue;
    // Several features can share an ISO-2 (Somalia + Somaliland): the larger one wins.
    const prev = best.get(f.properties.iso2);
    if (!prev || area > prev.area) best.set(f.properties.iso2, { area, c });
  }
  const out = new Map<string, [number, number]>();
  for (const [iso, { c }] of best) out.set(iso, c);
  for (const [iso, c] of Object.entries(SMALL_TERRITORY_POINTS)) if (!out.has(iso)) out.set(iso, c);
  return out;
}

/** ISO-2 -> [lon, lat], computed once from the polygons (plus small-territory points). */
export const centroids: ReadonlyMap<string, [number, number]> = buildCentroids();
