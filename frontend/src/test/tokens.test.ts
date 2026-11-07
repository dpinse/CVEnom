import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const css = readFileSync(resolve(__dirname, "../styles/tokens.css"), "utf8");

const REQUIRED = [
  "--bg",
  "--panel",
  "--panel-2",
  "--line",
  "--text",
  "--muted",
  "--faint",
  "--sev-crit",
  "--sev-high",
  "--sev-med",
  "--sev-low",
  "--live",
  "--scope",
  "--ocean",
  "--land",
  "--border-geo",
  "--well",
  "--font-display",
  "--font-body",
  "--font-mono",
  "--radius",
  "--gutter",
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
  const SIGNAL = ["--sev-crit", "--sev-high", "--sev-med", "--sev-low", "--live", "--scope"];
  const TEXT = ["--text", "--muted", "--faint", ...SIGNAL];
  const SURFACES = ["--bg", "--panel", "--panel-2"];
  for (const [name, t] of Object.entries(themes)) {
    for (const surface of SURFACES) {
      it(`${name}: text tier (text, muted, faint, severity, live, scope) >= 4.5 on ${surface}`, () => {
        for (const k of TEXT) {
          expect(contrast(t[k], t[surface]), `${k} on ${surface}`).toBeGreaterThanOrEqual(4.5);
        }
      });
      it(`${name}: non-text tier (signal colours) >= 3 on ${surface}`, () => {
        for (const k of SIGNAL) {
          expect(contrast(t[k], t[surface]), `${k} on ${surface}`).toBeGreaterThanOrEqual(3);
        }
      });
    }
    it(`${name}: faint stays dimmer than muted on bg`, () => {
      expect(contrast(t["--faint"], t["--bg"])).toBeLessThanOrEqual(contrast(t["--muted"], t["--bg"]));
    });
  }
});

describe("map legend text contrast (text on the translucent legend backdrop)", () => {
  const globeCss = readFileSync(resolve(__dirname, "../styles/globe.css"), "utf8");
  const rule = (sel: string) => {
    // top-level rule only: the selector must start a line
    const css = globeCss.replace(/\r\n/g, "\n");
    const at = css.indexOf(`\n${sel} {`);
    if (at < 0) throw new Error(`no rule ${sel}`);
    const open = css.indexOf("{", at);
    return css.slice(open + 1, css.indexOf("}", open));
  };
  const backdrop = /background:\s*color-mix\(in srgb, var\(--panel\) (\d+)%, transparent\)/.exec(rule(".map-legend"));
  const hintVar = /(?:^|[\s;])color:\s*var\((--[a-z-]+)\)/.exec(rule(".map-legend"));

  /** `over` at `alpha` composited onto `under`, as #rrggbb. */
  function blend(over: string, under: string, alpha: number): string {
    const ch = (h: string) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));
    const o = ch(over);
    return `#${ch(under)
      .map((u, i) =>
        Math.round(u + (o[i] - u) * alpha)
          .toString(16)
          .padStart(2, "0"),
      )
      .join("")}`;
  }

  it("the legend text uses --muted and the backdrop is --panel at a fixed alpha", () => {
    expect(hintVar?.[1]).toBe("--muted");
    expect(backdrop).not.toBeNull();
  });

  // The legend sits on the well/panel and may overlap the globe (ocean or land), so check each.
  for (const [name, t] of Object.entries({ dark, light })) {
    for (const under of ["--panel", "--ocean", "--land"]) {
      it(`${name}: legend text >= 4.5:1 on the backdrop blended over ${under}`, () => {
        const alpha = Number(backdrop![1]) / 100;
        const effective = blend(t["--panel"], t[under], alpha);
        expect(contrast(t[hintVar![1]], effective), `${hintVar![1]} on ${effective}`).toBeGreaterThanOrEqual(4.5);
      });
    }
  }
});
