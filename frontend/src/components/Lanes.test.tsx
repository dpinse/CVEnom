import { act, cleanup, fireEvent, render as rtlRender, renderHook, screen, within } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, test, vi } from "vitest";
import { ApiError, RateLimited } from "../lib/api";
import { relTime, shortAgo } from "../lib/relTime";
import { parseSelection, useSelection } from "../lib/selection";
import type { CveItem, Lane, LanesOut, LoudStory } from "../lib/types";
import { item } from "../test/shell";
import { laneMeta, productIssue } from "./LaneRow";
import { LANE_FETCH, LanesView } from "./Lanes";

afterEach(cleanup);

// Every lane footer renders a router Link, so every LanesView render needs a router.
const render = (ui: ReactNode) => rtlRender(ui, { wrapper: MemoryRouter });

const NOW = new Date("2026-11-05T12:00:00Z");
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
const cve = (n: number, o: Partial<CveItem> = {}) => item({ cve_id: `CVE-2026-${String(1000 + n)}`, ...o });
/** Plain item arrays -> the {total, items} shape LanesView reads (total defaults to the item count). */
const ln = (o: Partial<Record<Lane, CveItem[]>>, totals: Partial<Record<Lane, number>> = {}): Partial<LanesOut> =>
  Object.fromEntries(Object.entries(o).map(([k, items]) => [k, { total: totals[k as Lane] ?? items.length, items }]));
const EMPTY = ln({ EXPLOITED: [], LIKELY: [], LOUD: [], FRESH: [] });

describe("LanesView copy", () => {
  test("subtitles match the spec copy", () => {
    render(<LanesView lanes={EMPTY} onSelect={noop} now={NOW} />);
    expect(within(lane("Exploited now")).getByText("Added to CISA KEV or VulnCheck KEV")).toBeInTheDocument();
    expect(within(lane("Likely next")).getByText("Not yet exploited, EPSS ≥ p95")).toBeInTheDocument();
    expect(within(lane("Loud now")).getByText("CVEs the news is covering")).toBeInTheDocument();
    expect(within(lane("Fresh criticals")).getByText("New, CVSS ≥ 9, not yet exploited")).toBeInTheDocument();
  });
  test("empty lane copy names the range (24 hours)", () => {
    render(<LanesView lanes={EMPTY} range="24h" onSelect={noop} now={NOW} />);
    for (const name of ["Exploited now", "Likely next", "Loud now", "Fresh criticals"]) {
      expect(within(lane(name)).getByText("Nothing in the last 24 hours.")).toBeInTheDocument();
    }
  });
  test("empty copy follows the range prop (default 7 days)", () => {
    render(<LanesView lanes={EMPTY} onSelect={noop} now={NOW} />);
    expect(within(lane("Likely next")).getByText("Nothing in the last 7 days.")).toBeInTheDocument();
  });
});

describe("LanesView totals, rows and footer", () => {
  test("shows every loaded row and the total in the header; footer says View all 37", () => {
    const five = Array.from({ length: 5 }, (_, i) => cve(i));
    const { container } = render(
      <LanesView lanes={ln({ EXPLOITED: five }, { EXPLOITED: 37 })} range="7d" onSelect={noop} now={NOW} />,
    );
    const ex = lane("Exploited now");
    expect(within(ex).getAllByTestId("lane-row")).toHaveLength(5);
    expect(container.querySelector('[data-k="exploited"] .n')).toHaveTextContent("37");
    const link = within(ex).getByRole("link", { name: "View all 37 in Threats →" });
    expect(link).toHaveAttribute("href", "/threats?status=exploited&added=week");
  });
  test("a lane renders all of its loaded rows (it scrolls) up to the fetch cap", () => {
    const many = Array.from({ length: 9 }, (_, i) => cve(i));
    render(<LanesView lanes={ln({ FRESH: many })} onSelect={noop} now={NOW} />);
    expect(within(lane("Fresh criticals")).getAllByTestId("lane-row")).toHaveLength(9);
    const tooMany = Array.from({ length: LANE_FETCH + 5 }, (_, i) => cve(i));
    cleanup();
    render(<LanesView lanes={ln({ FRESH: tooMany })} onSelect={noop} now={NOW} />);
    expect(within(lane("Fresh criticals")).getAllByTestId("lane-row")).toHaveLength(LANE_FETCH);
  });
  test("when everything in the lane is loaded the footer says Open in Threats", () => {
    render(<LanesView lanes={ln({ LIKELY: [cve(1), cve(2)] })} onSelect={noop} now={NOW} />);
    expect(within(lane("Likely next")).getByRole("link", { name: "Open in Threats →" })).toHaveAttribute(
      "href",
      "/threats?status=likely&added=month",
    );
  });
  test.each([
    ["24h", "day"],
    ["7d", "week"],
    ["14d", "14d"],
    ["30d", "month"],
  ] as const)("footer links map range %s to added=%s and lane to status", (range, added) => {
    render(<LanesView lanes={EMPTY} range={range} onSelect={noop} now={NOW} />);
    const href = (name: string) => within(lane(name)).getByRole("link").getAttribute("href");
    expect(href("Exploited now")).toBe(`/threats?status=exploited&added=${added}`);
    // Likely is "published within likely_window_days (30)", independent of the range.
    expect(href("Likely next")).toBe("/threats?status=likely&added=month");
    expect(href("Loud now")).toBe(`/threats?status=news&added=${added}`);
    expect(href("Fresh criticals")).toBe(`/threats?status=critical&exclude_kev=1&added=${added}`);
  });
  test("loud story-only rows follow the CVE rows, up to the fetch cap", () => {
    const stories = Array.from({ length: 8 }, (_, i) =>
      story({ title: `s${i}`, url: `https://n.example/${i}`, published: `2026-11-0${1 + (i % 4)}T00:00:00Z` }),
    );
    render(<LanesView lanes={ln({ LOUD: [cve(1)] })} stories={stories} onSelect={noop} now={NOW} />);
    const rows = lane("Loud now").querySelectorAll(".row");
    expect(rows).toHaveLength(9);
    expect(rows[0].textContent).toContain("CVE-2026-1001");
    expect(within(lane("Loud now")).getAllByTestId("story-row")).toHaveLength(8);
  });
  test("loud stories are newest first", () => {
    render(
      <LanesView
        lanes={ln({ LOUD: [] })}
        stories={[
          story({ title: "older", url: "https://n.example/1", published: "2026-11-04T00:00:00Z" }),
          story({ title: "newer", url: "https://n.example/2", published: "2026-11-05T10:00:00Z" }),
        ]}
        onSelect={noop}
        now={NOW}
      />,
    );
    const order = screen.getAllByTestId("story-row").map((r) => r.textContent ?? "");
    expect(order[0]).toContain("newer");
    expect(order[1]).toContain("older");
  });
  test("stories whose CVEs are all LOUD CVE rows are not duplicated", () => {
    render(
      <LanesView
        lanes={ln({ LOUD: [cve(1)] })}
        stories={[
          story({ title: "dupe", url: "https://n.example/d", cve_ids: ["CVE-2026-1001"] }),
          story({ title: "partial", url: "https://n.example/p", cve_ids: ["CVE-2026-1001", "CVE-2026-1002"] }),
        ]}
        onSelect={noop}
        now={NOW}
      />,
    );
    expect(screen.queryByText("dupe")).toBeNull();
    expect(screen.getByText("partial")).toBeInTheDocument();
  });
  test("story row shows decoded title and 'source · age', no strobe or edge stripe", () => {
    const { container } = render(<LanesView lanes={ln({ LOUD: [] })} stories={[story()]} onSelect={noop} now={NOW} />);
    const row = within(lane("Loud now")).getByTestId("story-row");
    expect(within(row).getByText("Big & loud")).toBeInTheDocument();
    expect(row).toHaveTextContent("Example News · 1h ago");
    expect(container.querySelector(".strobe, .edge")).toBeNull();
  });
  test("only a ransomware.live story row carries the credit link", () => {
    render(
      <LanesView
        lanes={ln({ LOUD: [] })}
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
    expect(within(rows[0]).queryAllByTestId("ransomware-credit")).toHaveLength(1);
    expect(within(rows[1]).queryAllByTestId("ransomware-credit")).toHaveLength(0);
    expect(
      within(screen.getByTestId("ransomware-credit")).getByRole("link", { name: "ransomware.live" }),
    ).toHaveAttribute("href", "https://www.ransomware.live/");
  });
});

describe("LaneRow", () => {
  test("row text is 'Product: summary' with the full text in title", () => {
    const full = "Auth bypass in the web component allows remote attackers to execute arbitrary code";
    render(
      <LanesView
        lanes={ln({ EXPLOITED: [cve(1, { product: "Ivanti Connect Secure", summary: full })] })}
        onSelect={noop}
        now={NOW}
      />,
    );
    const t = within(screen.getByTestId("lane-row")).getByText(`Ivanti Connect Secure: ${full}`);
    expect(t.closest(".t")).toHaveAttribute("title", `Ivanti Connect Secure: ${full}`);
  });
  test("productIssue falls back to the summary without a product", () => {
    expect(productIssue(item({ product: null, summary: "Just text" }))).toBe("Just text");
    expect(productIssue(item({ product: "Acme Widget", summary: "Boom" }))).toBe("Acme Widget: Boom");
  });
  test("title attribute is decoded exactly once", () => {
    render(
      <LanesView
        lanes={ln({ FRESH: [cve(1, { summary: "A &amp;lt;b&amp;gt; &amp; C" })] })}
        onSelect={noop}
        now={NOW}
      />,
    );
    const t = screen.getByTestId("lane-row").querySelector(".t")!;
    expect(t).toHaveAttribute("title", "A &lt;b&gt; & C");
    expect(t).toHaveTextContent("A &lt;b&gt; & C");
  });
  test("null cvss renders a dash and the dot is named by severity", () => {
    render(
      <LanesView lanes={ln({ FRESH: [cve(1, { cvss: null }), cve(2, { cvss: 9.8 })] })} onSelect={noop} now={NOW} />,
    );
    const [a, b] = screen.getAllByTestId("lane-row");
    expect(a.querySelector(".score")).toHaveTextContent("–");
    expect(b.querySelector(".score")).toHaveTextContent("9.8");
    expect(within(b).getByLabelText("Critical")).toBeInTheDocument();
    expect(a.querySelector(".id")).toHaveTextContent("CVE-2026-1001");
  });
  test.each([
    [8.9, "High"],
    [9.0, "Critical"],
    [6.9, "Medium"],
    [7.0, "High"],
    [3.9, "Low"],
    [4.0, "Medium"],
  ])("severity dot for cvss %s is named %s", (cvss, name) => {
    render(<LanesView lanes={ln({ FRESH: [cve(1, { cvss })] })} onSelect={noop} now={NOW} />);
    expect(within(screen.getByTestId("lane-row")).getByLabelText(name)).toBeInTheDocument();
  });
  test("KEV rows carry no strobe, in-the-wild marker or edge stripe", () => {
    const { container } = render(
      <LanesView lanes={ln({ EXPLOITED: [cve(1, { kev: true })] })} onSelect={noop} now={NOW} />,
    );
    expect(container.querySelector(".strobe, .edge, .wild")).toBeNull();
    expect(screen.queryByText("in the wild")).toBeNull();
  });
  test("meta line renders the lane signal, PoC and no patch", () => {
    render(
      <LanesView
        lanes={ln({ EXPLOITED: [cve(1, { kev_added: "2026-11-04", poc_badge: true, patch_available: false })] })}
        onSelect={noop}
        now={NOW}
      />,
    );
    const meta = screen.getByTestId("lane-row").querySelector(".meta")!;
    expect([...meta.children].map((c) => c.textContent)).toEqual(["KEV 1d ago", "PoC", "no patch"]);
  });
  test("clicking a CVE row calls onSelect with the id", () => {
    const onSelect = vi.fn();
    render(<LanesView lanes={ln({ EXPLOITED: [cve(42)] })} onSelect={onSelect} now={NOW} />);
    fireEvent.click(screen.getByRole("button", { name: /CVE-2026-1042/ }));
    expect(onSelect).toHaveBeenCalledWith({ kind: "cve", id: "CVE-2026-1042" });
  });
  test("a story row opens a story selection", () => {
    const onSelect = vi.fn();
    render(<LanesView lanes={ln({ LOUD: [] })} stories={[story()]} onSelect={onSelect} now={NOW} />);
    fireEvent.click(screen.getByText("Big & loud"));
    expect(onSelect).toHaveBeenLastCalledWith({ kind: "story", url: "https://news.example/a" });
  });
});

describe("laneMeta", () => {
  test.each<[string, Lane, Partial<CveItem>, string[]]>([
    [
      "exploited + PoC + no patch",
      "EXPLOITED",
      { kev_added: "2026-11-04", poc_badge: true, patch_available: false },
      ["KEV 1d ago", "PoC", "no patch"],
    ],
    ["exploited without kev_added", "EXPLOITED", { kev_added: null }, []],
    ["likely", "LIKELY", { epss_percentile: 0.976 }, ["EPSS p98"]],
    ["loud, one story", "LOUD", { recent_story_count: 1 }, ["1 story"]],
    ["loud, many", "LOUD", { recent_story_count: 4 }, ["4 stories"]],
    ["fresh", "FRESH", { published: "2026-11-05T05:00:00Z", poc_badge: true }, ["published 7h ago", "PoC"]],
    ["patch true adds nothing", "LIKELY", { epss_percentile: 0.95, patch_available: true }, ["EPSS p95"]],
  ])("%s", (_n, laneKey, o, want) => {
    expect(laneMeta(item(o), laneKey, NOW)).toEqual(want);
  });
  test("meta never exceeds 3 entries", () => {
    const all = item({ kev_added: "2026-11-04", poc_badge: true, patch_available: false, recent_story_count: 5 });
    for (const l of ["EXPLOITED", "LIKELY", "LOUD", "FRESH"] as Lane[]) {
      expect(laneMeta(all, l, NOW).length).toBeLessThanOrEqual(3);
    }
    expect(laneMeta(all, "EXPLOITED", NOW)).toHaveLength(3);
  });
});

describe("LanesView text safety", () => {
  test("a summary of &amp;lt;b&amp;gt; renders as literal text &lt;b&gt;, never markup", () => {
    const { container } = render(
      <LanesView lanes={ln({ EXPLOITED: [item({ summary: "&amp;lt;b&amp;gt;" })] })} onSelect={noop} now={NOW} />,
    );
    expect(screen.getByText("&lt;b&gt;")).toBeInTheDocument();
    expect(container.querySelector("b")).toBeNull();
  });
  test("summary with &lt;script&gt; renders literally with no script element", () => {
    const { container } = render(
      <LanesView
        lanes={ln({ FRESH: [item({ kev: false, summary: "&lt;script&gt;alert(1)&lt;/script&gt;" })] })}
        onSelect={noop}
        now={NOW}
      />,
    );
    expect(screen.getByText("<script>alert(1)</script>")).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
  });
  test("M7: duplicate story URLs render without React key warnings", () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    render(
      <LanesView
        lanes={ln({ LOUD: [] })}
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
});

describe("LanesView states", () => {
  test("loading renders 3 skeleton rows per lane and no footer", () => {
    const { container } = render(<LanesView loading onSelect={noop} />);
    expect(container.querySelectorAll(".lane")).toHaveLength(4);
    expect(container.querySelectorAll(".lane-skeleton-row")).toHaveLength(12);
    expect(screen.queryByRole("link")).toBeNull();
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
  test("lane sections are labelled by their headings", () => {
    render(<LanesView lanes={ln({})} onSelect={noop} />);
    expect(screen.getAllByRole("region")).toHaveLength(4);
  });
});

describe("lanes.css", () => {
  const css = readFileSync(join(__dirname, "..", "styles", "lanes.css"), "utf8");
  test("no border-left wider than 1px", () => {
    const widths = [...css.matchAll(/border-left(?:-width)?:\s*(\d+(?:\.\d+)?)px/g)].map((m) => Number(m[1]));
    expect(widths.filter((w) => w > 1)).toEqual([]);
  });
  test("grid is 4 columns, 2 under 1100px, 1 under 560px", () => {
    expect(css).toMatch(/\.lanes\s*\{[^}]*repeat\(4,/);
    expect(css).toMatch(/max-width:\s*1100px\)\s*\{\s*\.lanes\s*\{[^}]*repeat\(2,/);
    expect(css).toMatch(/max-width:\s*560px\)\s*\{\s*\.lanes\s*\{[^}]*minmax\(0, 1fr\)\s*;/);
  });
  test("row text and meta are single-line with ellipsis, bidi-isolated", () => {
    const t = css.match(/\.row \.t\s*\{[^}]*\}/)![0];
    expect(t).toMatch(/white-space:\s*nowrap/);
    expect(t).toMatch(/text-overflow:\s*ellipsis/);
    expect(t).toMatch(/unicode-bidi:\s*isolate/);
    expect(css.match(/\.row \.meta\s*\{[^}]*\}/)![0]).toMatch(/white-space:\s*nowrap/);
  });
});

describe("shortAgo", () => {
  const at = (s: number) => new Date(NOW.getTime() - s * 1000).toISOString();
  test("minutes, hours, days, floored with a 1m minimum", () => {
    expect(shortAgo(at(5), NOW)).toBe("1m ago");
    expect(shortAgo(at(59 * 60 + 59), NOW)).toBe("59m ago");
    expect(shortAgo(at(3600), NOW)).toBe("1h ago");
    expect(shortAgo(at(7 * 3600 + 100), NOW)).toBe("7h ago");
    expect(shortAgo(at(86400), NOW)).toBe("1d ago");
    expect(shortAgo(at(40 * 86400), NOW)).toBe("40d ago");
    expect(shortAgo("garbage", NOW)).toBe("");
    expect(shortAgo(null, NOW)).toBe("");
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
  test("a javascript: story url selects a not-found story (url null), never the URL", () => {
    const { result } = renderHook(() => useSelection(), {
      wrapper: wrap(`/?story=${encodeURIComponent("javascript:alert(1)")}`),
    });
    expect(result.current.selection).toEqual({ kind: "story", url: null });
    expect(parseSelection(new URLSearchParams({ story: "data:text/html,x" }))).toEqual({ kind: "story", url: null });
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
