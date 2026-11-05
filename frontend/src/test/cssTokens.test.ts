import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "vitest";

const src = join(__dirname, "..");
function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}
const files = walk(src);
const css = files.filter((f) => f.endsWith(".css"));
const tsx = files.filter((f) => f.endsWith(".tsx") && !f.endsWith(".test.tsx"));
const read = (f: string) => readFileSync(f, "utf8");
const declared = (text: string) => [...text.matchAll(/(--[a-z0-9-]+)\s*:/gi)].map((m) => m[1]);

describe("design tokens", () => {
  test("every var(--x) is defined in tokens.css or declared locally", () => {
    const tokens = new Set(declared(read(join(src, "styles", "tokens.css"))));
    const local = new Set<string>();
    for (const f of css) declared(read(f)).forEach((d) => local.add(d));
    // inline custom properties, e.g. style={{ "--swatch": ... }}
    for (const f of tsx) for (const m of read(f).matchAll(/["'](--[a-z0-9-]+)["']\s*:/gi)) local.add(m[1]);
    const bad: string[] = [];
    for (const f of [...css, ...tsx]) {
      for (const m of read(f).matchAll(/var\(\s*(--[a-z0-9-]+)/gi)) {
        if (!tokens.has(m[1]) && !local.has(m[1])) bad.push(`${f.slice(src.length + 1)}: ${m[1]}`);
      }
    }
    expect(bad, `undefined CSS custom properties:\n${bad.join("\n")}`).toEqual([]);
  });
});
