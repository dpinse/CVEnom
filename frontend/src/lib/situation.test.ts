import { describe, expect, test } from "vitest";
import { item } from "../test/shell";
import { recentKev, situationLevel } from "./situation";

const NOW = new Date("2026-11-05T12:00:00Z");
const many = (n: number) =>
  Array.from({ length: n }, (_, i) => item({ cve_id: `CVE-2020-${i}`, kev_added: "2026-01-01" }));

describe("situationLevel", () => {
  test.each([
    [0, "Calm", 1],
    [1, "Elevated", 2],
    [2, "Elevated", 2],
    [3, "High", 3],
    [5, "High", 3],
    [6, "Severe", 4],
    [40, "Severe", 4],
  ])("%i exploited items -> %s with %i lit bars", (n, level, lit) => {
    expect(situationLevel(many(n), NOW)).toEqual({ level, lit });
  });

  test("a KEV added 2h ago makes it Severe even with one item", () => {
    const now = new Date("2026-11-05T02:00:00Z");
    const added = new Date(now.getTime() - 2 * 3600_000).toISOString().slice(0, 10); // 2026-11-05 (UTC)
    expect(situationLevel([item({ kev_added: added })], now)).toEqual({ level: "Severe", lit: 4 });
  });

  test("yesterday (UTC) counts as within 24h; two days ago does not", () => {
    expect(situationLevel([item({ kev_added: "2026-11-04" })], NOW).level).toBe("Severe");
    expect(situationLevel([item({ kev_added: "2026-11-03" })], NOW).level).toBe("Elevated");
  });

  test("null kev_added and garbage dates are ignored", () => {
    expect(situationLevel([item({ kev_added: null }), item({ kev_added: "nope" })], NOW).level).toBe("Elevated");
  });
});

describe("recentKev", () => {
  test("returns the newest in-window KEV across all lanes, else null", () => {
    const a = item({ cve_id: "CVE-A", kev_added: "2026-11-04" });
    const b = item({ cve_id: "CVE-B", kev_added: "2026-11-05" });
    const old = item({ cve_id: "CVE-OLD", kev_added: "2026-10-01" });
    expect(recentKev({ EXPLOITED: [a, old], LIKELY: [], LOUD: [b], FRESH: [] }, NOW)?.cve_id).toBe("CVE-B");
    expect(recentKev({ EXPLOITED: [old], LIKELY: [], LOUD: [], FRESH: [] }, NOW)).toBeNull();
    expect(recentKev(undefined, NOW)).toBeNull();
  });
});
