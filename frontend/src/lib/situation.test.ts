import { describe, expect, test } from "vitest";
import { item, lanes } from "../test/shell";
import { recentKev, situationLevel } from "./situation";

const NOW = new Date("2026-11-05T12:00:00Z");

const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString().slice(0, 10);

describe("situationLevel", () => {
  test.each([
    ["no listings", 0, null, "Calm", 1],
    ["latest 20 days ago", 1, daysAgo(20), "Elevated", 2],
    ["latest 30 days ago (inclusive)", 1, daysAgo(30), "Elevated", 2],
    ["3 new, none recent", 3, daysAgo(4), "High", 3],
    ["6 new, none recent", 6, daysAgo(4), "Severe", 4],
    ["latest yesterday", 1, daysAgo(1), "Severe", 4],
    ["latest today", 1, daysAgo(0), "Severe", 4],
    ["latest 31 days ago", 0, daysAgo(31), "Calm", 1],
    ["malformed date never counts", 1, "nope", "Calm", 1],
  ] as const)("%s", (_, new_kev, latest_kev_added, level, lit) => {
    expect(situationLevel({ new_kev, latest_kev_added }, NOW)).toEqual({ level, lit });
  });
});

describe("recentKev", () => {
  test("returns the newest in-window KEV across all lanes, else null", () => {
    const a = item({ cve_id: "CVE-A", kev_added: "2026-11-04" });
    const b = item({ cve_id: "CVE-B", kev_added: "2026-11-05" });
    const old = item({ cve_id: "CVE-OLD", kev_added: "2026-10-01" });
    expect(recentKev(lanes([a, old], { LOUD: [b] }), NOW)?.cve_id).toBe("CVE-B");
    expect(recentKev(lanes([old]), NOW)).toBeNull();
    expect(recentKev(undefined, NOW)).toBeNull();
  });
});
