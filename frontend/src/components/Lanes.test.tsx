import { act, cleanup, fireEvent, render as rtlRender, renderHook, screen, within } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, test, vi } from "vitest";
import { ApiError, RateLimited } from "../lib/api";
import { relTime } from "../lib/relTime";
import { parseSelection, useSelection } from "../lib/selection";
import type { LoudStory } from "../lib/types";
import { item } from "../test/shell";
import { LANE_CAP, LanesView } from "./Lanes";

afterEach(cleanup);

// The empty Exploited lane renders a router Link, so every LanesView render needs a router.
const render = (ui: ReactNode) => rtlRender(ui, { wrapper: MemoryRouter });

const NOW = new Date("2026-11-05T12:00:00Z");
const foil = item({
  cve_id: "CVE-2026-115560",
  cvss: 9.0,
  epss_percentile: 0.3,
  kev: false,
  kev_source: null,
});
const story = (o: Partial<LoudStory> = {}): LoudStory => ({
  title: "Big &amp; loud",
  summary: "s",
  url: "https://news.example/a",
  source: "Example News",
  published: "2026-11-05T11:00:00Z",
  cve_ids: [],
  ...o,
});
const lane = (name: string) => screen.getByRole("region", { name });
const noop = () => {};

describe("LanesView lane copy", () => {
  test("subtitles name the windows", () => {
    render(<LanesView lanes={{ EXPLOITED: [], LIKELY: [], LOUD: [], FRESH: [] }} onSelect={noop} now={NOW} />);
    expect(within(lane("Exploited now")).getByText("KEV-listed, last 30 days")).toBeInTheDocument();
    expect(within(lane("Likely next")).getByText("published ≤ 30 days, high EPSS")).toBeInTheDocument();
  });
  test("an empty Exploited lane shows the copy and a Browse History link to /history?kev=true", () => {
    render(<LanesView lanes={{ EXPLOITED: [], LIKELY: [], LOUD: [], FRESH: [] }} onSelect={noop} now={NOW} />);
    const ex = within(lane("Exploited now"));
    expect(ex.getByText("No new KEV listings in the last 30 days")).toBeInTheDocument();
    expect(ex.getByRole("link", { name: "Browse History" }).getAttribute("href")).toBe("/history?kev=true");
    expect(within(lane("Likely next")).queryByRole("link")).toBeNull();
  });
});

describe("LanesView double-encoded text", () => {
  test("a summary of &amp;lt;b&amp;gt; renders as literal text &lt;b&gt;, never markup", () => {
    const { container } = render(
      <LanesView
        lanes={{ EXPLOITED: [item({ summary: "&amp;lt;b&amp;gt;" })], LIKELY: [], LOUD: [], FRESH: [] }}
        onSelect={noop}
        now={NOW}
      />,
    );
    expect(screen.getByText("&lt;b&gt;")).toBeInTheDocument();
    expect(container.querySelector("b")).toBeNull();
  });
});

describe("LanesView ransomware credit", () => {
  test("only a ransomware.live story row carries the credit link", () => {
    render(
      <LanesView
        lanes={{ EXPLOITED: [], LIKELY: [], LOUD: [], FRESH: [] }}
        stories={[
          story({ url: "https://news.example/r", source: "ransomware.live", title: "Victim" }),
          story({ url: "https://news.example/n", source: "Example News", title: "News" }),
        ]}
        onSelect={noop}
        now={NOW}
      />,
    );
    const rows = screen.getAllByTestId("story-row");
    expect(rows).toHaveLength(2);
    expect(
      within(rows[0]).queryAllByTestId("ransomware-credit").length +
        within(rows[1]).queryAllByTestId("ransomware-credit").length,
    ).toBe(1);
    const credit = screen.getByTestId("ransomware-credit");
    expect(within(credit).getByRole("link", { name: "ransomware.live" })).toHaveAttribute(
      "href",
      "https://www.ransomware.live/",
    );
  });
});

describe("LanesView", () => {
  test("quiet foil appears only in Fresh, with no in-the-wild marker", () => {
    render(<LanesView lanes={{ EXPLOITED: [], LIKELY: [], LOUD: [], FRESH: [foil] }} onSelect={noop} now={NOW} />);
    expect(within(lane("Fresh criticals")).getByText("CVE-2026-115560")).toBeInTheDocument();
    expect(screen.getAllByText("CVE-2026-115560")).toHaveLength(1);
    expect(screen.queryByText("in the wild")).toBeNull();
  });

  test("KEV shows the strobe marker in every lane", () => {
    const k = (id: string) => item({ cve_id: id, kev: true });
    const { container } = render(
      <LanesView
        lanes={{
          EXPLOITED: [k("CVE-2026-0001")],
          LIKELY: [k("CVE-2026-0002")],
          LOUD: [k("CVE-2026-0003")],
          FRESH: [k("CVE-2026-0004")],
        }}
        onSelect={noop}
        now={NOW}
      />,
    );
    for (const name of ["Exploited now", "Likely next", "Loud now", "Fresh criticals"]) {
      expect(within(lane(name)).getByText("in the wild")).toBeInTheDocument();
    }
    expect(container.querySelectorAll(".strobe")).toHaveLength(4);
  });

  test("null cvss and epss omit their chips without crashing", () => {
    const { container } = render(
      <LanesView
        lanes={{ EXPLOITED: [item({ cvss: null, epss_percentile: null, kev: false })] }}
        onSelect={noop}
        now={NOW}
      />,
    );
    expect(container.querySelector(".chip.num")).toBeNull();
    expect(screen.queryByText(/EPSS p\d/)).toBeNull();
  });

  test("chips: EPSS percentile, KEV date + source, PoC, no patch, news", () => {
    render(
      <LanesView
        lanes={{
          EXPLOITED: [
            item({
              cvss: 7.5,
              epss_percentile: 0.876,
              kev_added: "2026-11-01",
              kev_source: "cisa",
              poc_badge: true,
              patch_available: false,
              recent_story_count: 3,
            }),
          ],
        }}
        onSelect={noop}
        now={NOW}
      />,
    );
    expect(screen.getByText("7.5")).toBeInTheDocument();
    expect(screen.getByText("EPSS p88")).toBeInTheDocument();
    expect(screen.getByText("KEV · 2026-11-01")).toHaveAttribute("title", "cisa");
    expect(screen.getByText("PoC")).toBeInTheDocument();
    expect(screen.getByText("no patch")).toBeInTheDocument();
    expect(screen.getByText("news ×3")).toBeInTheDocument();
  });

  test("patch_available true or null shows no 'no patch' chip", () => {
    render(
      <LanesView
        lanes={{
          EXPLOITED: [item({ patch_available: true }), item({ cve_id: "CVE-2026-0002", patch_available: null })],
        }}
        onSelect={noop}
        now={NOW}
      />,
    );
    expect(screen.queryByText("no patch")).toBeNull();
  });

  test("summary with &lt;script&gt; renders literally with no script element", () => {
    const { container } = render(
      <LanesView
        lanes={{ FRESH: [item({ kev: false, summary: "&lt;script&gt;alert(1)&lt;/script&gt;" })] }}
        onSelect={noop}
        now={NOW}
      />,
    );
    expect(screen.getByText("<script>alert(1)</script>")).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
  });

  test.each([
    [8.9, "high"],
    [9.0, "crit"],
    [6.9, "med"],
    [7.0, "high"],
    [3.9, "low"],
    [4.0, "med"],
    [null, "low"],
  ])("severity bucket for cvss %s is %s", (cvss, sev) => {
    const { container } = render(
      <LanesView lanes={{ FRESH: [item({ cvss, kev: false })] }} onSelect={noop} now={NOW} />,
    );
    const row = container.querySelector(".row")!;
    expect(row).toHaveAttribute("data-sev", sev);
    expect(row).toHaveAttribute("data-edge", sev);
  });

  test("KEV overrides the severity edge", () => {
    const { container } = render(
      <LanesView lanes={{ EXPLOITED: [item({ cvss: 2, kev: true })] }} onSelect={noop} now={NOW} />,
    );
    const row = container.querySelector(".row")!;
    expect(row).toHaveClass("live");
    expect(row).toHaveAttribute("data-edge", "live");
  });

  test("CVE-less stories appear in Loud now with a 'no CVE' chip and decoded title", () => {
    render(<LanesView lanes={{ LOUD: [] }} stories={[story()]} onSelect={noop} now={NOW} />);
    const loud = lane("Loud now");
    expect(within(loud).getByText("Big & loud")).toBeInTheDocument();
    expect(within(loud).getByText("no CVE")).toBeInTheDocument();
    expect(within(loud).getByText(/Example News/)).toHaveTextContent("Example News · 1 hour ago");
    expect(within(loud).queryByRole("link")).toBeNull();
  });

  test("stories are newest first and come after CVE rows", () => {
    render(
      <LanesView
        lanes={{ LOUD: [item({ cve_id: "CVE-2026-0009" })] }}
        stories={[
          story({ title: "older", url: "https://n.example/1", published: "2026-11-04T00:00:00Z" }),
          story({ title: "newer", url: "https://n.example/2", published: "2026-11-05T10:00:00Z" }),
        ]}
        onSelect={noop}
        now={NOW}
      />,
    );
    const order = [...lane("Loud now").querySelectorAll(".row")].map((r) => r.textContent ?? "");
    expect(order[0]).toContain("CVE-2026-0009");
    expect(order[1]).toContain("newer");
    expect(order[2]).toContain("older");
  });

  test("stories whose CVEs are all LOUD CVE rows are not duplicated", () => {
    render(
      <LanesView
        lanes={{ LOUD: [item({ cve_id: "CVE-2026-0001" })] }}
        stories={[
          story({ title: "dupe", url: "https://n.example/d", cve_ids: ["CVE-2026-0001"] }),
          story({ title: "partial", url: "https://n.example/p", cve_ids: ["CVE-2026-0001", "CVE-2026-0002"] }),
        ]}
        onSelect={noop}
        now={NOW}
      />,
    );
    expect(screen.queryByText("dupe")).toBeNull();
    expect(screen.getByText("partial")).toBeInTheDocument();
  });

  test("merged Loud lane is capped at 100 rows", () => {
    const cves = Array.from({ length: 90 }, (_, i) => item({ cve_id: `CVE-2026-${String(1000 + i)}`, kev: false }));
    const stories = Array.from({ length: 30 }, (_, i) => story({ title: `s${i}`, url: `https://n.example/${i}` }));
    const { container } = render(<LanesView lanes={{ LOUD: cves }} stories={stories} onSelect={noop} now={NOW} />);
    expect(lane("Loud now").querySelectorAll(".row")).toHaveLength(LANE_CAP);
    expect(container.querySelector('[data-k="loud"] .n')).toHaveTextContent("100");
    const many = Array.from({ length: 150 }, (_, i) => item({ cve_id: `CVE-2026-${String(2000 + i)}`, kev: false }));
    cleanup();
    render(<LanesView lanes={{ FRESH: many }} onSelect={noop} now={NOW} />);
    expect(lane("Fresh criticals").querySelectorAll(".row")).toHaveLength(100);
  });

  test("clicking a CVE row calls onSelect with the id", () => {
    const onSelect = vi.fn();
    render(<LanesView lanes={{ EXPLOITED: [item({ cve_id: "CVE-2026-4242" })] }} onSelect={onSelect} now={NOW} />);
    fireEvent.click(screen.getByRole("button", { name: /CVE-2026-4242/ }));
    expect(onSelect).toHaveBeenCalledWith({ kind: "cve", id: "CVE-2026-4242" });
  });

  test("story row opens a story selection; CVE chip selects the CVE", () => {
    const onSelect = vi.fn();
    render(
      <LanesView
        lanes={{ LOUD: [] }}
        stories={[story({ cve_ids: ["CVE-2026-7777"] })]}
        onSelect={onSelect}
        now={NOW}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "CVE-2026-7777" }));
    expect(onSelect).toHaveBeenLastCalledWith({ kind: "cve", id: "CVE-2026-7777" });
    fireEvent.click(screen.getByText("Big & loud"));
    expect(onSelect).toHaveBeenLastCalledWith({ kind: "story", url: "https://news.example/a" });
  });

  test("empty states render per lane", () => {
    render(<LanesView lanes={{ EXPLOITED: [], LIKELY: [], LOUD: [], FRESH: [] }} onSelect={noop} now={NOW} />);
    expect(screen.getByText("No new KEV listings in the last 30 days")).toBeInTheDocument();
    expect(screen.getByText("No likely-next CVEs")).toBeInTheDocument();
    expect(screen.getByText("Quiet — no buzz")).toBeInTheDocument();
    expect(screen.getByText("No fresh criticals")).toBeInTheDocument();
  });

  test("loading renders 3 skeleton rows per lane", () => {
    const { container } = render(<LanesView loading onSelect={noop} />);
    expect(container.querySelectorAll(".lane")).toHaveLength(4);
    expect(container.querySelectorAll(".lane-skeleton-row")).toHaveLength(12);
  });

  test("error banner mentions retry and does not crash", () => {
    render(<LanesView error={new Error("x")} onSelect={noop} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/retry/i);
  });

  test("RateLimited banner shows the countdown", () => {
    render(<LanesView error={new RateLimited(30)} onSelect={noop} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Rate limited — retrying in 30s");
  });

  test("a 401 does not promise a retry", () => {
    render(<LanesView error={new ApiError(401, "unauthorized")} onSelect={() => {}} />);
    const text = screen.getByRole("alert").textContent ?? "";
    expect(text).toMatch(/sign in/i);
    expect(text).not.toMatch(/retrying/i);
  });

  test("I3: the banner counts down to the real next refetch, then says it is retrying now", () => {
    const t0 = NOW.getTime();
    const { rerender } = render(<LanesView error={new Error("x")} retryAt={t0 + 30_000} now={NOW} onSelect={noop} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Couldn't load the lanes — retrying in 30s");
    rerender(<LanesView error={new Error("x")} retryAt={t0 + 30_000} now={new Date(t0 + 17_500)} onSelect={noop} />);
    expect(screen.getByRole("alert")).toHaveTextContent("retrying in 13s");
    rerender(<LanesView error={new Error("x")} retryAt={t0 + 30_000} now={new Date(t0 + 31_000)} onSelect={noop} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Couldn't load the lanes — retrying now");
    rerender(
      <LanesView error={new RateLimited(90)} retryAt={t0 + 90_000} now={new Date(t0 + 30_000)} onSelect={noop} />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("Rate limited — retrying in 60s");
  });

  test("M7: duplicate story URLs render without React key warnings", () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    render(
      <LanesView
        lanes={{ LOUD: [] }}
        stories={[story({ title: "one" }), story({ title: "two" })]}
        onSelect={noop}
        now={NOW}
      />,
    );
    expect(screen.getByText("one")).toBeInTheDocument();
    expect(screen.getByText("two")).toBeInTheDocument();
    expect(errors.mock.calls.flat().join(" ")).not.toMatch(/same key/);
    errors.mockRestore();
  });

  test("lane sections are labelled by their headings", () => {
    render(<LanesView lanes={{}} onSelect={noop} />);
    expect(screen.getAllByRole("region")).toHaveLength(4);
  });
});

describe("lanes.css", () => {
  const css = readFileSync(join(__dirname, "..", "styles", "lanes.css"), "utf8");
  test("API text is bidi-isolated and clamped to 2 lines", () => {
    const rule = css.match(/\.row-title\s*\{[^}]*\}/)![0];
    expect(rule).toMatch(/unicode-bidi:\s*isolate/);
    expect(rule).toMatch(/line-clamp:\s*2/);
  });
  test("lane lists scroll independently at 320px", () => {
    expect(css).toMatch(/\.lane-items\s*\{[^}]*max-height:\s*320px/);
  });
});

describe("relTime", () => {
  const at = (s: number) => new Date(NOW.getTime() - s * 1000).toISOString();
  test("boundaries", () => {
    expect(relTime(at(30), NOW)).toBe("just now");
    expect(relTime(at(59), NOW)).toBe("just now");
    expect(relTime(at(60), NOW)).toBe("1 minute ago");
    expect(relTime(at(3599), NOW)).toBe("59 minutes ago");
    expect(relTime(at(3600), NOW)).toBe("1 hour ago");
    expect(relTime(at(86399), NOW)).toBe("23 hours ago");
    expect(relTime(at(86400), NOW)).toBe("yesterday");
    expect(relTime(at(3 * 86400), NOW)).toBe("3 days ago");
    expect(relTime(at(30 * 86400), NOW)).toBe("last month");
  });
  test("future and bad input are safe", () => {
    expect(relTime(at(-120), NOW)).toBe("in 2 minutes");
    expect(relTime("garbage", NOW)).toBe("");
    expect(relTime(null, NOW)).toBe("");
  });
});

describe("selection", () => {
  const wrap = (path: string) =>
    function Wrapper({ children }: { children: ReactNode }) {
      return <MemoryRouter initialEntries={[path]}>{children}</MemoryRouter>;
    };
  test.each(["../x", "cve-2026-1234", "CVE-1-1", "CVE-2026-123", "CVE-2026-12345678"])("rejects bad cve %s", (bad) => {
    const { result } = renderHook(() => useSelection(), { wrapper: wrap(`/?cve=${encodeURIComponent(bad)}`) });
    expect(result.current.selection).toBeNull();
  });
  test("accepts a valid cve", () => {
    const { result } = renderHook(() => useSelection(), { wrapper: wrap("/?cve=CVE-2026-1234") });
    expect(result.current.selection).toEqual({ kind: "cve", id: "CVE-2026-1234" });
  });
  test("rejects a javascript: story url", () => {
    const { result } = renderHook(() => useSelection(), {
      wrapper: wrap(`/?story=${encodeURIComponent("javascript:alert(1)")}`),
    });
    expect(result.current.selection).toBeNull();
    expect(parseSelection(new URLSearchParams({ story: "data:text/html,x" }))).toBeNull();
  });
  test("accepts an https story url", () => {
    const { result } = renderHook(() => useSelection(), {
      wrapper: wrap(`/?story=${encodeURIComponent("https://n.example/a")}`),
    });
    expect(result.current.selection).toEqual({ kind: "story", url: "https://n.example/a" });
  });
  test("select writes and clears the params", () => {
    const { result } = renderHook(() => useSelection(), { wrapper: wrap("/?story=https%3A%2F%2Fn.example%2Fa") });
    act(() => result.current.select({ kind: "cve", id: "CVE-2026-1234" }));
    expect(result.current.selection).toEqual({ kind: "cve", id: "CVE-2026-1234" });
    act(() => result.current.select(null));
    expect(result.current.selection).toBeNull();
  });
});
