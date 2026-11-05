import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const css = readFileSync(resolve(__dirname, "../styles/tokens.css"), "utf8");

const REQUIRED = [
  "--bg", "--panel", "--panel-2", "--line", "--text", "--muted", "--faint",
  "--sev-crit", "--sev-high", "--sev-med", "--sev-low", "--live", "--scope",
  "--ocean", "--land", "--border-geo",
  "--font-display", "--font-body", "--font-mono",
  "--radius", "--gutter",
];
const THEMED = REQUIRED.filter((t) => !t.startsWith("--font") && t !== "--radius" && t !== "--gutter");

/** Return the declarations of the first block whose selector matches exactly. */
function block(selector: string, source = css): Record<string, string> {
  const idx = source.indexOf(selector + " {");
  if (idx < 0) throw new Error(`no block ${selector}`);
  const start = source.indexOf("{", idx);
  const end = source.indexOf("}", start);
  const out: Record<string, string> = {};
  for (const m of source.slice(start + 1, end).matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)) {
    out[m[1]] = m[2].trim();
  }
  return out;
}

const dark = block(":root");
const light = block(':root[data-theme="light"]');
const mediaSrc = css.slice(css.indexOf("@media (prefers-color-scheme: light)"));
const media = block(':root:not([data-theme="dark"])', mediaSrc);

function lum(hex: string): number {
  const n = parseInt(hex.slice(1), 16);
  const ch = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((v) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2];
}
function contrast(a: string, b: string): number {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

describe("tokens.css", () => {
  it("defines every required token on :root", () => {
    for (const t of REQUIRED) expect(dark, t).toHaveProperty([t]);
  });
  it("overrides every themed token under [data-theme=light]", () => {
    for (const t of THEMED) expect(light, t).toHaveProperty([t]);
  });
  it("honours prefers-color-scheme: light with the same values", () => {
    for (const t of THEMED) expect(media[t], t).toBe(light[t]);
  });
  it("uses self-hosted Plex families", () => {
    expect(dark["--font-display"]).toContain("IBM Plex Sans Condensed");
    expect(dark["--font-body"]).toContain("IBM Plex Sans");
    expect(dark["--font-mono"]).toContain("IBM Plex Mono");
  });
});

describe("WCAG AA contrast", () => {
  const themes = { dark, light };
  for (const [name, t] of Object.entries(themes)) {
    for (const surface of ["--bg", "--panel", "--panel-2"]) {
      it(`${name}: text and muted on ${surface} >= 4.5`, () => {
        expect(contrast(t["--text"], t[surface])).toBeGreaterThanOrEqual(4.5);
        expect(contrast(t["--muted"], t[surface])).toBeGreaterThanOrEqual(4.5);
      });
      it(`${name}: severity, live and scope on ${surface} >= 3 (non-text/large)`, () => {
        for (const k of ["--sev-crit", "--sev-high", "--sev-med", "--sev-low", "--live", "--scope"]) {
          expect(contrast(t[k], t[surface]), `${k}`).toBeGreaterThanOrEqual(3);
        }
      });
    }
    it(`${name}: faint on bg >= 3`, () => {
      expect(contrast(t["--faint"], t["--bg"])).toBeGreaterThanOrEqual(3);
    });
  }
});
