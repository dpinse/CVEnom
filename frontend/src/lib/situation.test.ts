import { describe, expect, test } from "vitest";
import { item } from "../test/shell";
import { recentKev, situationLevel } from "./situation";

const NOW = new Date("2026-11-05T12:00:00Z");
const many = (n: number, kev_added = "2026-01-01") =>
  Array.from({ length: n }, (_, i) => item({ cve_id: `CVE-2020-${i}`, kev_added }));

describe("situationLevel", () => {
  test("0 listings -> Calm", () => {
    expect(situationLevel([], NOW)).toEqual({ level: "Calm", lit: 1 });
  });
  test("one listing 20 days old -> Elevated", () => {
    expect(situationLevel(many(1, "2026-10-16"), NOW)).toEqual({ level: "Elevated", lit: 2 });
  });
  test("3 listings in 7 days -> High; 2 in 7 days plus 10 older -> Elevated", () => {
    expect(situationLevel(many(3, "2026-11-01"), NOW)).toEqual({ level: "High", lit: 3 });
    expect(situationLevel([...many(2, "2026-11-01"), ...many(10, "2026-09-01")], NOW)).toEqual({
      level: "Elevated",
      lit: 2,
    });
  });
  test("6 listings in 7 days -> Severe", () => {
    expect(situationLevel(many(6, "2026-11-01"), NOW)).toEqual({ level: "Severe", lit: 4 });
  });
  test("one listed today -> Severe", () => {
    expect(situationLevel(many(1, "2026-11-05"), NOW)).toEqual({ level: "Severe", lit: 4 });
  });
  test("the 7-day boundary is the UTC date of now minus 7 days (late-evening UTC)", () => {
    const late = new Date("2026-11-05T23:30:00Z");
    expect(situationLevel(many(3, "2026-10-29"), late).level).toBe("High");
    expect(situationLevel(many(3, "2026-10-28"), late).level).toBe("Elevated");
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
    // a non-date string must not sort into the 7-day window ("nope" > "2026-10-29" lexically)
    const junk = [null, "nope", "zzzz-zz-zz"].map((d) => item({ kev_added: d }));
    expect(situationLevel(junk, NOW).level).toBe("Elevated");
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
