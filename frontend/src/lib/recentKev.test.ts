import { describe, expect, test } from "vitest";
import { item, lanes } from "../test/shell";
import { isRecentKevDate, recentKev } from "./recentKev";

const NOW = new Date("2026-11-05T12:00:00Z");

const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString().slice(0, 10);

describe("isRecentKevDate", () => {
  test("today and yesterday (UTC) count; older, empty and malformed do not", () => {
    expect(isRecentKevDate(daysAgo(0), NOW)).toBe(true);
    expect(isRecentKevDate(daysAgo(1), NOW)).toBe(true);
    expect(isRecentKevDate(daysAgo(2), NOW)).toBe(false);
    expect(isRecentKevDate(null, NOW)).toBe(false);
    expect(isRecentKevDate("nope", NOW)).toBe(false);
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
