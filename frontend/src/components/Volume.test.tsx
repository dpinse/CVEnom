import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, test } from "vitest";
import type { VolumeBucket, VolumeOut } from "../lib/types";
import { SEV_ORDER, VolumeView, volumeBars } from "./Volume";

afterEach(cleanup);

const b = (i: number, crit: number, high: number, med: number, low: number): VolumeBucket => ({
  start: `2026-10-${String(i + 1).padStart(2, "0")}T00:00:00Z`,
  crit,
  high,
  med,
  low,
});
const mk = (buckets: VolumeBucket[], o: Partial<VolumeOut> = {}): VolumeOut => ({
  range: "7d",
  unit: "day",
  buckets,
  total: buckets.reduce((s, x) => s + x.crit + x.high + x.med + x.low, 0),
  unscored: 0,
  ...o,
});

describe("volumeBars", () => {
  test("stacks crit at the top and heights sum to the bucket total scaled", () => {
    const bars = volumeBars([b(0, 1, 2, 3, 4), b(1, 5, 5, 5, 5)], 1000, 110, 18);
    expect(SEV_ORDER).toEqual(["crit", "high", "med", "low"]);
    const full = bars[1];
    expect(full.segs.map((s) => s.sev)).toEqual([...SEV_ORDER]);
    const [crit, high, med, low] = full.segs;
    expect(crit.y).toBeLessThan(high.y);
    expect(high.y).toBeLessThan(med.y);
    expect(med.y).toBeLessThan(low.y);
    expect(low.y + low.height).toBeCloseTo(110 - 18);
    const sum = (i: number) => bars[i].segs.reduce((s, x) => s + x.height, 0);
    expect(sum(1)).toBeCloseTo(110 - 18 - 4);
    expect(sum(0) / sum(1)).toBeCloseTo(10 / 20);
  });

  test("band padding is 0.55 under 15 buckets and 0.2 from 15", () => {
    const mkN = (n: number) =>
      volumeBars(
        Array.from({ length: n }, (_, i) => b(i, 1, 1, 1, 1)),
        1000,
        110,
        18,
      );
    const few = mkN(7);
    const many = mkN(30);
    expect(few[0].width / (few[1].x - few[0].x)).toBeCloseTo(0.45);
    expect(many[0].width / (many[1].x - many[0].x)).toBeCloseTo(0.8);
  });

  test("all-zero buckets give zero heights, no NaN", () => {
    const bars = volumeBars([b(0, 0, 0, 0, 0), b(1, 0, 0, 0, 0)], 1000, 110, 18);
    const nums = bars.flatMap((x) => [x.x, x.width, ...x.segs.flatMap((s) => [s.y, s.height])]);
    expect(nums.every(Number.isFinite)).toBe(true);
    expect(bars.flatMap((x) => x.segs).every((s) => s.height === 0)).toBe(true);
    expect(volumeBars([], 1000, 110, 18)).toEqual([]);
  });
});

describe("VolumeView", () => {
  test("heading says per day, with total, legend and axis", () => {
    render(<VolumeView data={mk([b(0, 1, 1, 1, 1), b(1, 1, 1, 1, 1)])} range="14d" />);
    expect(screen.getByRole("heading", { name: "New CVEs per day" })).toBeTruthy();
    expect(screen.getByText("8 in the last 14 days")).toBeTruthy();
    for (const l of ["Critical", "High", "Medium", "Low"]) expect(screen.getAllByText(l).length).toBeGreaterThan(0);
    expect(screen.getByRole("img", { name: "New CVEs per day, stacked by severity" })).toBeTruthy();
    expect(screen.getByText("Oct 1", { selector: ".vol-axis span" })).toBeTruthy();
    expect(screen.getByText("now")).toBeTruthy();
  });

  test("heading says per hour for 24h", () => {
    render(<VolumeView data={mk([b(0, 1, 0, 0, 0)], { unit: "hour", range: "24h" })} range="24h" />);
    expect(screen.getByRole("heading", { name: "New CVEs per hour" })).toBeTruthy();
    expect(screen.getByText("1 in the last 24 hours")).toBeTruthy();
    expect(screen.getByText("24h ago")).toBeTruthy();
    expect(screen.getByRole("img", { name: "New CVEs per hour, stacked by severity" })).toBeTruthy();
  });

  test("sr table has one row per bucket", () => {
    render(<VolumeView data={mk([b(0, 1, 2, 3, 4), b(1, 0, 0, 0, 9), b(2, 0, 0, 0, 0)])} />);
    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(4);
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((h) => h.textContent),
    ).toEqual(["Start", "Critical", "High", "Medium", "Low"]);
    expect(
      within(rows[1])
        .getAllByRole("cell")
        .map((c) => c.textContent),
    ).toEqual(["1", "2", "3", "4"]);
  });

  test("unscored footnote only when > 0", () => {
    const { rerender } = render(<VolumeView data={mk([b(0, 1, 0, 0, 0)])} />);
    expect(screen.queryByText(/unscored/)).toBeNull();
    rerender(<VolumeView data={mk([b(0, 1, 0, 0, 0)], { unscored: 12 })} />);
    expect(screen.getByText("12 unscored CVEs not shown")).toBeTruthy();
  });

  test("loading and error states", () => {
    const { rerender } = render(<VolumeView loading />);
    expect(screen.getByRole("status").getAttribute("aria-busy")).toBe("true");
    rerender(<VolumeView error={new Error("x")} />);
    expect(screen.getByText("CVE volume is unavailable right now.")).toBeTruthy();
  });
});
