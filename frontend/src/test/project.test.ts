import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";

const root = resolve(__dirname, "../..");

describe("project config", () => {
  it(".nvmrc is 26", () => {
    expect(readFileSync(join(root, ".nvmrc"), "utf8").trim()).toBe("26");
  });
  it('package.json engines.node is ">=22"', () => {
    const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    expect(pkg.engines.node).toBe(">=22");
  });
});

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

/**
 * An allow-list entry. A plain string is stripped wherever it is not merely the prefix of a
 * longer host (see stripExact). `{ literal }` is stricter: stripped only when the URI is a
 * complete string literal, i.e. directly followed by a closing quote or backtick, so
 * "http://localhost:8080/x" or "http://localhost/api" is still flagged.
 */
type Allow = string | { literal: string } | { comment: string };

/**
 * Remote-looking URIs allowed in source:
 *  - W3C SVG / XLink namespace identifiers (never fetched).
 *  - the DB-IP attribution hyperlink required by DB-IP Lite's CC-BY 4.0 licence. It is an
 *    <a href> the user may click (a navigation in a new tab), never a request the page makes.
 */
const ALLOWED: Allow[] = ["http://www.w3.org/2000/svg", "http://www.w3.org/1999/xlink", { literal: "https://db-ip.com" }];

const HOST_CHAR = /[A-Za-z0-9.-]/;
/** Remove exact occurrences of `uri`, but not when it is merely a prefix of a longer host/path (svg.evil.test). */
function stripExact(text: string, uri: string): string {
  let out = "";
  let i = 0;
  for (;;) {
    const j = text.indexOf(uri, i);
    if (j < 0) return out + text.slice(i);
    const next = text[j + uri.length] ?? "";
    out += text.slice(i, j);
    if (next !== "" && HOST_CHAR.test(next) && !uri.endsWith("/")) out += uri;
    i = j + uri.length;
  }
}

const CLOSE_QUOTE = new Set(['"', "'", "`"]);
const LINE_END = new Set(["\n", "\r"]);
/** Remove `uri` only where the next char is in `terminators` (a closing quote, or end of a comment line). */
function stripTerminated(text: string, uri: string, terminators: Set<string>): string {
  let out = "";
  let i = 0;
  for (;;) {
    const j = text.indexOf(uri, i);
    if (j < 0) return out + text.slice(i);
    out += text.slice(i, j);
    if (!terminators.has(text[j + uri.length] ?? "")) out += uri;
    i = j + uri.length;
  }
}

function strip(text: string, a: Allow): string {
  if (typeof a === "string") return stripExact(text, a);
  if ("literal" in a) return stripTerminated(text, a.literal, CLOSE_QUOTE);
  return stripTerminated(text, a.comment, LINE_END);
}

/**
 * Find remote references. Deliberately no comment stripping: the whole text is scanned,
 * so nothing can hide in a comment-looking sequence (comments may not carry URLs either).
 *  - absolute http(s)/ws(s) URLs anywhere (minus the exact allow-list)
 *  - protocol-relative //host directly after a quote/backtick (strings, HTML attributes)
 *  - protocol-relative //host inside CSS url(...) and @import
 * "a//b" is not flagged: the // must start the literal.
 */
function findRemote(text: string, extra: Allow[] = []): string[] {
  let t = text;
  for (const a of [...ALLOWED, ...extra]) t = strip(t, a);
  const hits: string[] = [];
  const patterns = [
    /\b(?:https?|wss?):\/\/[^\s"'`)<>]*/gi,
    /["'`]\s*\/\/[A-Za-z0-9[\-.]+/g,
    /url\(\s*["']?\s*\/\/[^)]*\)/gi,
    /@import\s+(?:url\(\s*)?["']?\s*\/\/[^;)\s]*/gi,
  ];
  for (const re of patterns) for (const m of t.matchAll(re)) hits.push(m[0]);
  return hits;
}

describe("findRemote detector", () => {
  it("flags absolute, ws, protocol-relative and CSS forms", () => {
    expect(findRemote('fetch("https://x.test/a")')).toHaveLength(1);
    expect(findRemote('new WebSocket("wss://x.test")')).toHaveLength(1);
    expect(findRemote("new WebSocket('ws://x.test')")).toHaveLength(1);
    expect(findRemote('const u = "//cdn.test/x.js"')).toHaveLength(1);
    expect(findRemote("a { background: url(//cdn.test/x.png) }")).toHaveLength(1);
    expect(findRemote('@import "//fonts.test/css";')).not.toHaveLength(0);
    expect(findRemote("@import url(//fonts.test/css);")).not.toHaveLength(0);
    expect(findRemote('<script src="//cdn.test/x.js"></script>')).toHaveLength(1);
    expect(findRemote("/* see https://x.test */")).toHaveLength(1);
  });
  it("does not flag benign code or the SVG/XLink namespaces", () => {
    expect(findRemote("const p = 'a//b'; // comment")).toEqual([]);
    expect(findRemote("const n = 'http://www.w3.org/2000/svg'")).toEqual([]);
    expect(findRemote("const n = 'http://www.w3.org/1999/xlink'")).toEqual([]);
    expect(findRemote("const r = 1 //2\n")).toEqual([]);
    expect(findRemote('const n = "http://www.w3.org/2000/svg.evil.test/x"')).not.toEqual([]);
  });
  it("literal allow-list entries are stripped only as complete string literals", () => {
    expect(findRemote('new URL(p, "http://localhost")', DIST_EXTRA)).toEqual([]);
    expect(findRemote("new URL(p, `http://localhost`)", DIST_EXTRA)).toEqual([]);
    expect(findRemote('fetch("http://localhost:8080/x")', DIST_EXTRA)).toHaveLength(1);
    expect(findRemote('fetch("http://localhost/api")', DIST_EXTRA)).toHaveLength(1);
    expect(findRemote('fetch("http://localhost.evil.test/")', DIST_EXTRA)).toHaveLength(1);
    expect(findRemote("see http://localhost for docs", DIST_EXTRA)).toHaveLength(1);
    expect(findRemote("t.href=`https://maplibre.org/`", DIST_EXTRA)).toEqual([]);
    expect(findRemote('fetch("https://maplibre.org/style.json")', DIST_EXTRA)).toHaveLength(1);
  });
  it("comment allow-list entries are stripped only at the end of a line", () => {
    const lic = "https://github.com/maplibre/maplibre-gl-js/blob/v6.15.0/LICENSE.txt";
    expect(findRemote(`* @license BSD: ${lic}\n*/`, DIST_EXTRA)).toEqual([]);
    expect(findRemote(`fetch("${lic}?x")`, DIST_EXTRA)).toHaveLength(1);
    expect(findRemote(`fetch("${lic}")`, DIST_EXTRA)).toHaveLength(1);
  });
  it("the DB-IP attribution link is allowed only as the exact literal", () => {
    expect(findRemote('<ExternalLink href="https://db-ip.com">')).toEqual([]);
    expect(findRemote('fetch("https://db-ip.com/api")')).toHaveLength(1);
    expect(findRemote('fetch("https://db-ip.com.evil.test")')).toHaveLength(1);
  });
});

describe("no third-party runtime requests (source)", () => {
  const publicDir = join(root, "public");
  const files = [
    ...walk(join(root, "src")).filter((f) => !/\.test\.[tj]sx?$/.test(f) && !/[\\/]test[\\/]/.test(f)),
    join(root, "index.html"),
    ...(existsSync(publicDir) ? walk(publicDir) : []),
  ];
  it("scans a non-trivial file set", () => {
    expect(files.length).toBeGreaterThan(3);
  });
  for (const f of files) {
    it(`${f.slice(root.length + 1)} has no remote URL`, () => {
      expect(findRemote(readFileSync(f, "utf8"))).toEqual([]);
    });
  }
});

const dist = join(root, "dist");
/** Inert strings that react-dom and react-router embed in the bundle (namespace identifiers and an error-message link; never requested). */
const DIST_EXTRA: Allow[] = [
  "http://www.w3.org/1998/Math/MathML",
  "http://www.w3.org/XML/1998/namespace",
  "https://react.dev/errors/",
  // react-router: a dummy base for `new URL(path, base)` parsing (exact literal only, so a
  // "http://localhost:8080/..." fetch would still be flagged), and two dev-warning doc links.
  { literal: "http://localhost" },
  "https://reactrouter.com/en/main/routers/picking-a-router.",
  "https://github.com/ungap/url-search-params.",
  // maplibre-gl (lazy globe chunk + worker). All exact literals; none is ever requested:
  //  - XHTML namespace identifier compared against element.namespaceURI in its HTML sanitizer.
  { literal: "http://www.w3.org/1999/xhtml" },
  //  - dummy base for `new URL(href, base)` protocol checks in that sanitizer (.invalid never resolves).
  { literal: "https://maplibre.invalid/" },
  //  - href of the MapLibre logo / default attribution link; both controls are disabled
  //    (attributionControl: false, maplibreLogo: false), and it would only be a link anyway.
  { literal: "https://maplibre.org/" },
  //  - text of the "WebGL2 is required" error and of a "too many glyphs" console warning.
  { literal: "https://wiki.openstreetmap.org/wiki/This_map_requires_WebGL" },
  { literal: "https://github.com/mapbox/mapbox-gl-js/issues/2907" },
  //  - the @license comment heading the worker file (copied verbatim as an asset). Version-pinned
  //    on purpose: a MapLibre upgrade must re-review its embedded URLs.
  { comment: "https://github.com/maplibre/maplibre-gl-js/blob/v6.15.0/LICENSE.txt" },
];
/** `dist-harness/` is `npm run build:harness` (app + dev globe harness): the build that carries MapLibre. */
const distHarness = join(root, "dist-harness");

for (const [label, dir] of [
  ["dist", dist],
  ["dist-harness", distHarness],
] as const) {
  describe.skipIf(!existsSync(dir))(`no third-party runtime requests (${label})`, () => {
    const files = existsSync(dir) ? walk(dir).filter((f) => /\.(html|js|css|mjs|json|svg)$/.test(f)) : [];
    it("scans built output", () => {
      expect(files.length).toBeGreaterThan(0);
    });
    for (const f of files) {
      it(`${label}/${f.slice(dir.length + 1)} has no remote URL`, () => {
        expect(findRemote(readFileSync(f, "utf8"), DIST_EXTRA)).toEqual([]);
      });
    }
  });
}

/** Marker unique to MapLibre's main bundle (the canvas class it creates). */
const MAPLIBRE_MARKER = "maplibregl-canvas-container";
const INITIAL_GZIP_BUDGET = 250 * 1024;

/** The entry script of an HTML page plus every chunk it statically pulls in (modulepreload / imports). */
function initialChunks(dir: string, html: string): string[] {
  const page = readFileSync(join(dir, html), "utf8");
  const seen = new Set<string>();
  const queue = [...page.matchAll(/(?:src|href)="\/(assets\/[^"]+\.js)"/g)].map((m) => m[1]);
  while (queue.length) {
    const rel = queue.shift()!;
    if (seen.has(rel)) continue;
    seen.add(rel);
    const code = readFileSync(join(dir, rel), "utf8");
    // static imports only: `import ... from "./x.js"` / `import "./x.js"` (dynamic import( ) is excluded)
    for (const m of code.matchAll(/(?:^|[;\s}])(?:import|export)\s*(?:[\w${},*\s]+from\s*)?["'`]\.\/([^"'`]+\.js)["'`]/g)) {
      queue.push(`assets/${m[1]}`);
    }
  }
  return [...seen];
}

for (const [label, dir, html] of [
  ["dist", dist, "index.html"],
  ["dist-harness", distHarness, "globe-harness.html"],
] as const) {
  describe.skipIf(!existsSync(join(dir, html)))(`initial bundle budget (${label}/${html})`, () => {
    const chunks = existsSync(join(dir, html)) ? initialChunks(dir, html) : [];
    it(`initial JS is <= 250 KB gzip and excludes MapLibre`, () => {
      expect(chunks.length).toBeGreaterThan(0);
      let gz = 0;
      for (const c of chunks) {
        const code = readFileSync(join(dir, c));
        gz += gzipSync(code).length;
        expect(code.includes(MAPLIBRE_MARKER), `${c} must not contain MapLibre`).toBe(false);
      }
      expect(gz).toBeLessThanOrEqual(INITIAL_GZIP_BUDGET);
    });
  });
}

describe.skipIf(!existsSync(distHarness))("lazy globe chunk (dist-harness)", () => {
  it("MapLibre lives in a lazily imported chunk, and its worker is a same-origin .js asset", () => {
    const js = walk(join(distHarness, "assets")).filter((f) => f.endsWith(".js"));
    const lazy = js.filter((f) => readFileSync(f, "utf8").includes(MAPLIBRE_MARKER));
    expect(lazy).toHaveLength(1);
    expect(js.some((f) => /maplibre-gl-worker-[\w-]+\.js$/.test(f))).toBe(true);
  });
});
