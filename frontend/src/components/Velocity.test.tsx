import { cleanup, render, screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, test } from "vitest";
import type { VelocityOut } from "../lib/types";
import { renderAt, server, setupMsw } from "../test/shell";
import { Velocity, VelocityView, sparkPath } from "./Velocity";

setupMsw();
afterEach(cleanup);

const points = (d: string) => (d.match(/-?\d+(\.\d+)?,-?\d+(\.\d+)?/g) ?? []).length;
const mk = (counts: number[], o: Partial<VelocityOut> = {}): VelocityOut => ({
  series: counts.map((count, i) => ({ day: `2026-10-${String(i + 1).padStart(2, "0")}`, count })),
  current: counts[counts.length - 1] ?? 0,
  rising: false,
  ...o,
});

describe("sparkPath", () => {
  test("line has N points and the end sits at the last point", () => {
    const s = [1, 4, 2, 8, 5];
    const p = sparkPath(s, 100, 40, 2);
    expect(points(p.line)).toBe(5);
    const last = p.line.match(/-?\d+(\.\d+)?,-?\d+(\.\d+)?/g)!.pop()!.split(",").map(Number);
    expect(p.end.x).toBeCloseTo(last[0]);
    expect(p.end.y).toBeCloseTo(last[1]);
    expect(p.end.x).toBeCloseTo(98);
  });
  test("area closes to the baseline", () => {
    const p = sparkPath([1, 2, 3], 100, 40, 2);
    expect(p.area.endsWith("Z")).toBe(true);
  });
  test("all zeros and all equal give a flat middle line, no NaN", () => {
    for (const s of [[0, 0, 0, 0], [7, 7, 7]]) {
      const p = sparkPath(s, 100, 40, 2);
      expect(`${p.line}${p.area}${p.end.x}${p.end.y}`).not.toMatch(/NaN|Infinity/);
      expect(p.end.y).toBeCloseTo(20);
    }
  });
  test("empty and single point are safe", () => {
    const e = sparkPath([], 100, 40, 2);
    expect(`${e.line}${e.area}${e.end.x}${e.end.y}`).not.toMatch(/NaN|Infinity/);
    const one = sparkPath([5], 100, 40, 2);
    expect(`${one.line}${one.area}${one.end.x}${one.end.y}`).not.toMatch(/NaN|Infinity/);
    expect(points(one.line)).toBeGreaterThanOrEqual(1);
  });
  test("max maps to the top, zero to the bottom", () => {
    const p = sparkPath([0, 10], 100, 40, 2);
    expect(p.end.y).toBeCloseTo(2);
  });
});

describe("VelocityView", () => {
  test("formats the big number with a thousands separator", () => {
    render(<VelocityView data={mk([1, 2, 1234], { current: 1234 })} />);
    expect(screen.getByText("1,234")).toBeInTheDocument();
    expect(screen.getByText("CVEs published / day")).toBeInTheDocument();
  });
  test("rising chip only when rising", () => {
    const { rerender } = render(<VelocityView data={mk([1, 2, 3], { rising: true })} />);
    expect(screen.getByText("rising")).toBeInTheDocument();
    expect(screen.queryByText("steady")).toBeNull();
    rerender(<VelocityView data={mk([1, 2, 3], { rising: false })} />);
    expect(screen.getByText("steady")).toBeInTheDocument();
    expect(screen.queryByText("rising")).toBeNull();
  });
  test("sr-only summary and aria-hidden svg", () => {
    const { container } = render(<VelocityView data={mk([1, 9, 3], { current: 3, rising: true })} />);
    expect(
      screen.getByText("CVEs published per day over the last 30 days: today 3, peak 9 on 2026-10-02, trend rising"),
    ).toHaveClass("sr-only");
    expect(container.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
  });
  test("steady wording", () => {
    render(<VelocityView data={mk([1, 9, 3])} />);
    expect(screen.getByText(/trend steady$/)).toBeInTheDocument();
  });
  test("endpoint dot is present", () => {
    const { container } = render(<VelocityView data={mk([1, 2, 3])} />);
    expect(container.querySelector(".velocity-dot")).not.toBeNull();
  });
  test("loading skeleton", () => {
    const { container } = render(<VelocityView loading />);
    expect(container.querySelector(".velocity-skeleton")).not.toBeNull();
    expect(screen.getByLabelText("Loading CVE velocity")).toBeInTheDocument();
  });
  test("error is an inline message", () => {
    render(<VelocityView error={new Error("boom")} />);
    expect(screen.getByText("CVE velocity is unavailable right now.")).toBeInTheDocument();
  });
  test("empty window", () => {
    const { container } = render(<VelocityView data={mk([0, 0, 0])} />);
    expect(screen.getByText("No new CVEs in this window")).toBeInTheDocument();
    expect(container.innerHTML).not.toMatch(/NaN/);
    expect(container.querySelector("path")).not.toBeNull();
  });
});

describe("Velocity", () => {
  test("reads /api/velocity?days=30", async () => {
    let url = "";
    server.use(
      http.get("http://localhost/api/velocity", ({ request }) => {
        url = request.url;
        return HttpResponse.json(mk([1, 2, 3000], { current: 3000, rising: true }));
      }),
    );
    renderAt(<Velocity />);
    expect(await screen.findByText("3,000")).toBeInTheDocument();
    expect(url).toContain("days=30");
  });
});
