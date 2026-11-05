import { readdirSync, readFileSync, statSync } from "node:fs";
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
function stripComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:\\])\/\/.*$/gm, "$1")
    .replace(/<!--[\s\S]*?-->/g, "");
}

describe("no third-party runtime requests", () => {
  const files = [
    ...walk(join(root, "src")).filter((f) => !/\.test\.[tj]sx?$/.test(f) && !/[\\/]test[\\/]/.test(f)),
    join(root, "index.html"),
  ];
  it("scans a non-trivial file set", () => {
    expect(files.length).toBeGreaterThan(3);
  });
  for (const f of files) {
    it(`${f.slice(root.length + 1)} has no http(s):// URL outside comments`, () => {
      expect(stripComments(readFileSync(f, "utf8"))).not.toMatch(/https?:\/\//);
    });
  }
});
