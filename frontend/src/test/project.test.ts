import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
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

/** The only remote-looking URIs allowed: W3C SVG / XLink namespace identifiers (never fetched). */
const ALLOWED = ["http://www.w3.org/2000/svg", "http://www.w3.org/1999/xlink"];

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

/**
 * Find remote references. Deliberately no comment stripping: the whole text is scanned,
 * so nothing can hide in a comment-looking sequence (comments may not carry URLs either).
 *  - absolute http(s)/ws(s) URLs anywhere (minus the exact allow-list)
 *  - protocol-relative //host directly after a quote/backtick (strings, HTML attributes)
 *  - protocol-relative //host inside CSS url(...) and @import
 * "a//b" is not flagged: the // must start the literal.
 */
function findRemote(text: string, extra: string[] = []): string[] {
  let t = text;
  for (const a of [...ALLOWED, ...extra]) t = stripExact(t, a);
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
const DIST_EXTRA = [
  "http://www.w3.org/1998/Math/MathML",
  "http://www.w3.org/XML/1998/namespace",
  "https://react.dev/errors/",
  // react-router: a dummy base for `new URL(path, base)` parsing, and two dev-warning doc links; none is requested.
  "http://localhost",
  "https://reactrouter.com/en/main/routers/picking-a-router.",
  "https://github.com/ungap/url-search-params.",
];
describe.skipIf(!existsSync(dist))("no third-party runtime requests (dist)", () => {
  const files = existsSync(dist) ? walk(dist).filter((f) => /\.(html|js|css|mjs|json|svg)$/.test(f)) : [];
  it("scans built output", () => {
    expect(files.length).toBeGreaterThan(0);
  });
  for (const f of files) {
    it(`dist/${f.slice(dist.length + 1)} has no remote URL`, () => {
      expect(findRemote(readFileSync(f, "utf8"), DIST_EXTRA)).toEqual([]);
    });
  }
});
