import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { afterEach, describe, expect, test, vi } from "vitest";
import { item, member, renderAt, server, setupMsw, signIn } from "../test/shell";
import type { CveListOut, StoryItem, StoryListOut } from "../lib/types";
import Threats, { DEBOUNCE_MS, parseThreatFilters, toCveQuery } from "./Threats";
import { parseStoryFilters } from "./ThreatsNews";

setupMsw({ ready: true });
afterEach(cleanup);

let lastUrl = "";
function Probe() {
  const loc = useLocation();
  useEffect(() => {
    lastUrl = loc.pathname + loc.search;
  });
  return null;
}
const ui = (
  <>
    <Threats />
    <Probe />
  </>
);

const seen: URLSearchParams[] = [];
function api(body: (sp: URLSearchParams) => CveListOut | Response) {
  seen.length = 0;
  server.use(
    http.get("http://localhost/api/cves", ({ request }) => {
      const sp = new URL(request.url).searchParams;
      seen.push(sp);
      const r = body(sp);
      return r instanceof Response ? r : HttpResponse.json(r);
    }),
  );
}
const list = (items = [item()], total = items.length, page = 1): CveListOut => ({ items, page, page_size: 50, total });
const many = (n: number) => Array.from({ length: n }, (_, i) => item({ cve_id: `CVE-2026-${1000 + i}` }));

const seenStories: URLSearchParams[] = [];
function storiesApi(body: (sp: URLSearchParams) => StoryListOut | Response) {
  seenStories.length = 0;
  server.use(
    http.get("http://localhost/api/stories", ({ request }) => {
      const sp = new URL(request.url).searchParams;
      seenStories.push(sp);
      const r = body(sp);
      return r instanceof Response ? r : HttpResponse.json(r);
    }),
  );
}
const story = (o: Partial<StoryItem> = {}): StoryItem => ({
  title: "Big &amp; loud",
  summary: "s",
  url: "https://news.example/a",
  source: "Example News",
  published: "2026-11-05T11:00:00Z",
  cve_ids: ["CVE-2026-0001"],
  ...o,
});
const sList = (items = [story()], total = items.length, page = 1): StoryListOut => ({
  items,
  page,
  page_size: 50,
  total,
});

describe("parseThreatFilters", () => {
  test("defaults", () => {
    expect(parseThreatFilters(new URLSearchParams(""))).toEqual({
      q: undefined,
      added: "any",
      status: "all",
      excludeKev: false,
      due: false,
      sev: [],
      poc: false,
      nopatch: false,
      sort: "newest",
      page: 1,
    });
  });

  test("junk falls back to defaults", () => {
    const f = parseThreatFilters(
      new URLSearchParams(
        "added=decade&status=bogus&sort=x&sev=zzz,,crit,low,crit&due=30d&exclude_kev=2&page=0&poc=yes",
      ),
    );
    expect(f).toMatchObject({ added: "any", status: "all", sort: "newest", sev: ["low", "crit"], due: false });
    expect(f).toMatchObject({ excludeKev: false, poc: false, page: 1 });
    expect(parseThreatFilters(new URLSearchParams("page=1.5")).page).toBe(1);
  });

  test("reads every valid value, including the dashboard-only 14d window", () => {
    const f = parseThreatFilters(
      new URLSearchParams(
        "q=log4j&added=14d&status=critical&exclude_kev=1&due=7d&sev=high,crit&poc=1&nopatch=1&sort=due&page=3",
      ),
    );
    expect(f).toEqual({
      q: "log4j",
      added: "14d",
      status: "critical",
      excludeKev: true,
      due: true,
      sev: ["high", "crit"],
      poc: true,
      nopatch: true,
      sort: "due",
      page: 3,
    });
  });

  test("truncates q to 200 and drops whitespace-only q", () => {
    expect(parseThreatFilters(new URLSearchParams(`q=${"a".repeat(201)}`)).q).toHaveLength(200);
    expect(parseThreatFilters(new URLSearchParams("q=%20%20")).q).toBeUndefined();
  });
});

describe("toCveQuery", () => {
  test("defaults are omitted", () => {
    expect(toCveQuery(parseThreatFilters(new URLSearchParams("")))).toEqual({ page: 1, page_size: 50 });
  });

  test("maps every filter", () => {
    const f = parseThreatFilters(
      new URLSearchParams(
        "q=x&added=90d&status=exploited&exclude_kev=1&due=7d&sev=crit,low&poc=1&nopatch=1&sort=hot&page=2",
      ),
    );
    expect(toCveQuery(f)).toEqual({
      q: "x",
      added: "90d",
      status: "exploited",
      exclude_kev: true,
      due: "7d",
      sev: "low,crit",
      poc: true,
      nopatch: true,
      sort: "hot",
      page: 2,
      page_size: 50,
    });
  });
});

describe("parseStoryFilters", () => {
  test("reads q, source, added, page; truncates and drops invalid", () => {
    const f = parseStoryFilters(
      new URLSearchParams(`q=${"a".repeat(201)}&source=${"b".repeat(80)}&added=month&page=3`),
    );
    expect(f.q).toHaveLength(200);
    expect(f.source).toHaveLength(64);
    expect(f.added).toBe("month");
    expect(f.page).toBe(3);
    expect(parseStoryFilters(new URLSearchParams("page=0&added=bogus"))).toEqual({ page: 1 });
  });
});

describe("Threats page (CVEs)", () => {
  test("heading, no range control", async () => {
    api(() => list());
    renderAt(ui, "/threats");
    expect(screen.getByRole("heading", { level: 1, name: "Threats" })).toBeInTheDocument();
    expect(screen.queryByText("24h")).toBeNull();
    expect(screen.queryByText("14d")).toBeNull();
    await screen.findByText("CVE-2026-0001");
  });

  test("invalid URL params are never sent to the API", async () => {
    api(() => list());
    renderAt(ui, "/threats?added=x&status=y&sev=z&sort=q&due=1d&page=0");
    await screen.findByText("CVE-2026-0001");
    for (const k of ["added", "status", "sev", "sort", "due"]) expect(seen[0].has(k)).toBe(false);
    expect(seen[0].get("page")).toBe("1");
    expect(seen[0].get("page_size")).toBe("50");
  });

  test("params round-trip into the controls and the request", async () => {
    api(() => list());
    renderAt(ui, "/threats?q=log4j&added=week&status=likely&sev=high,crit&poc=1&sort=trending");
    await screen.findByText("CVE-2026-0001");
    expect((screen.getByLabelText("Search CVEs") as HTMLInputElement).value).toBe("log4j");
    expect((screen.getByLabelText("Added") as HTMLSelectElement).value).toBe("week");
    expect((screen.getByLabelText("Sort") as HTMLSelectElement).value).toBe("trending");
    expect(screen.getByRole("button", { name: "Likely next" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "High" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "Critical", pressed: true })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Low" })).toHaveAttribute("aria-pressed", "false");
    // a set secondary filter opens "All filters" so it is never hidden
    expect(screen.getByRole("button", { name: "Public exploit" })).toHaveAttribute("aria-pressed", "true");
    expect(Object.fromEntries(seen[0].entries())).toMatchObject({
      q: "log4j",
      added: "week",
      status: "likely",
      sev: "high,crit",
      poc: "true",
      sort: "trending",
    });
  });

  test("Added offers the listed windows; 14d appears only when the URL holds it", async () => {
    api(() => list());
    renderAt(ui, "/threats");
    await screen.findByText("CVE-2026-0001");
    const opts = () =>
      within(screen.getByLabelText("Added"))
        .getAllByRole("option")
        .map((o) => o.textContent);
    expect(opts()).toEqual([
      "Added any time",
      "Added past day",
      "Added past week",
      "Added past month",
      "Added past 90 days",
      "Added past year",
    ]);
    cleanup();
    api(() => list());
    renderAt(ui, "/threats?added=14d");
    await screen.findByText("CVE-2026-0001");
    expect((screen.getByLabelText("Added") as HTMLSelectElement).selectedOptions[0].textContent).toBe(
      "Added past 14 days",
    );
    expect(seen[0].get("added")).toBe("14d");
  });

  test("changing Added writes the URL and resets the page", async () => {
    api(() => list(many(50), 120));
    renderAt(ui, "/threats?page=2");
    await screen.findByText("120 CVEs");
    fireEvent.change(screen.getByLabelText("Added"), { target: { value: "month" } });
    await waitFor(() => expect(lastUrl).toBe("/threats?added=month"));
  });

  test.each([
    ["/threats?poc=1&added=week", "Published"],
    ["/threats?status=news&added=week", "Published"],
    ["/threats?status=exploited&added=week", "Added"],
    ["/threats", "Added"],
  ])("the time column header is honest about what it shows (%s)", async (url, header) => {
    api(() => list());
    renderAt(ui, url);
    await screen.findByText("CVE-2026-0001");
    expect(screen.getByRole("columnheader", { name: header })).toBeInTheDocument();
  });

  test("status chip click sets ?status=likely and resets the page; All clears it", async () => {
    api(() => list(many(50), 120));
    renderAt(ui, "/threats?page=2");
    await screen.findByText("120 CVEs");
    fireEvent.click(screen.getByRole("button", { name: "Likely next" }));
    await waitFor(() => expect(lastUrl).toBe("/threats?status=likely"));
    fireEvent.click(screen.getByRole("button", { name: "All" }));
    await waitFor(() => expect(lastUrl).toBe("/threats"));
  });

  test("severity chips are multi-select, ordered low to critical, written to the URL", async () => {
    api(() => list());
    renderAt(ui, "/threats");
    await screen.findByText("CVE-2026-0001");
    const group = screen.getByRole("group", { name: "Severity" });
    expect(Array.from(group.querySelectorAll("button")).map((b) => b.textContent)).toEqual([
      "Low",
      "Medium",
      "High",
      "Critical",
    ]);
    fireEvent.click(within(group).getByRole("button", { name: "Critical" }));
    await waitFor(() => expect(lastUrl).toBe("/threats?sev=crit"));
    fireEvent.click(within(group).getByRole("button", { name: "Low" }));
    await waitFor(() => expect(lastUrl).toBe("/threats?sev=low%2Ccrit"));
    await waitFor(() => expect(seen[seen.length - 1].get("sev")).toBe("low,crit"));
    fireEvent.click(within(group).getByRole("button", { name: "Critical" }));
    await waitFor(() => expect(lastUrl).toBe("/threats?sev=low"));
    fireEvent.click(within(group).getByRole("button", { name: "Low" }));
    await waitFor(() => expect(lastUrl).toBe("/threats"));
  });

  test("All filters reveals Public exploit and No patch", async () => {
    api(() => list());
    renderAt(ui, "/threats");
    await screen.findByText("CVE-2026-0001");
    expect(screen.queryByRole("button", { name: "No patch" })).toBeNull();
    const toggle = screen.getByRole("button", { name: "All filters" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    fireEvent.click(screen.getByRole("button", { name: "No patch" }));
    await waitFor(() => expect(lastUrl).toBe("/threats?nopatch=1"));
    await waitFor(() => expect(seen[seen.length - 1].get("nopatch")).toBe("true"));
  });

  test("deep-link exclude_kev and due show removable active-filter chips", async () => {
    api(() => list());
    renderAt(ui, "/threats?status=critical&exclude_kev=1&due=7d&added=week");
    await screen.findByText("CVE-2026-0001");
    expect(seen[0].get("exclude_kev")).toBe("true");
    expect(seen[0].get("due")).toBe("7d");
    fireEvent.click(screen.getByRole("button", { name: "Remove filter: Not in KEV" }));
    await waitFor(() => expect(lastUrl).not.toContain("exclude_kev"));
    expect(lastUrl).toContain("due=7d");
    fireEvent.click(screen.getByRole("button", { name: "Remove filter: KEV due within 7 days" }));
    await waitFor(() => expect(lastUrl).not.toContain("due="));
    expect(screen.queryByRole("list", { name: "Active filters" })).toBeNull();
  });

  test("sort select shows a description and writes only non-default values", async () => {
    api(() => list());
    renderAt(ui, "/threats");
    await screen.findByText("CVE-2026-0001");
    expect(screen.getByText("Most recently published first")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Sort"), { target: { value: "due" } });
    await waitFor(() => expect(lastUrl).toBe("/threats?sort=due"));
    expect(screen.getByText("Soonest CISA deadline first")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Sort"), { target: { value: "newest" } });
    await waitFor(() => expect(lastUrl).toBe("/threats"));
  });

  test("a row shows severity, link, product, signals, EPSS and the added date", async () => {
    api(() =>
      list([
        item({
          cvss: 7.5,
          product: "Acme Gateway",
          summary: "Remote flaw",
          kev: true,
          poc_badge: true,
          patch_available: false,
          recent_story_count: 3,
          epss_percentile: 0.97,
          published: "2026-11-01T00:00:00Z",
        }),
      ]),
    );
    renderAt(ui, "/threats");
    const row = await screen.findByTestId("search-row");
    for (const t of ["7.5", "High", "Acme Gateway", "Remote flaw", "KEV", "PoC", "no patch", "news ×3", "p97"])
      expect(row.textContent).toContain(t);
    expect(screen.getByRole("link", { name: "CVE-2026-0001" }).getAttribute("href")).toBe("/threats/CVE-2026-0001");
    expect(screen.getAllByRole("columnheader").map((h) => h.textContent)).toEqual([
      "Severity",
      "CVE",
      "Product and issue",
      "Signals",
      "EPSS",
      "Added",
    ]);
  });

  test("an unscored CVE reads Unscored, not Low", async () => {
    api(() => list([item({ cvss: null })]));
    renderAt(ui, "/threats");
    expect((await screen.findByTestId("search-row")).textContent).toContain("Unscored");
  });

  test("row click navigates to the threat page", async () => {
    api(() => list());
    function Where() {
      return <span data-testid="where">{useLocation().pathname}</span>;
    }
    renderAt(
      <>
        {ui}
        <Where />
      </>,
      "/threats",
    );
    fireEvent.click(await screen.findByText("A summary"));
    await waitFor(() => expect(screen.getByTestId("where").textContent).toBe("/threats/CVE-2026-0001"));
  });

  test("typing debounces into a single request", async () => {
    api(() => list());
    renderAt(ui, "/threats");
    await screen.findByText("CVE-2026-0001");
    const before = seen.length;
    const input = screen.getByLabelText("Search CVEs");
    for (const v of ["l", "lo", "log", "log4"]) fireEvent.change(input, { target: { value: v } });
    await new Promise((r) => setTimeout(r, DEBOUNCE_MS / 2));
    expect(seen.length).toBe(before);
    await waitFor(() => expect(seen.length).toBe(before + 1));
    expect(seen[seen.length - 1].get("q")).toBe("log4");
    expect(lastUrl).toBe("/threats?q=log4");
  });

  test("an external URL change cancels a pending debounce", async () => {
    api(() => list());
    function Nav() {
      const nav = useNavigate();
      return <button onClick={() => nav("/threats?q=back")}>go</button>;
    }
    renderAt(
      <>
        {ui}
        <Nav />
      </>,
      "/threats",
    );
    await screen.findByText("CVE-2026-0001");
    const input = screen.getByLabelText("Search CVEs") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "stale" } });
    fireEvent.click(screen.getByText("go"));
    await waitFor(() => expect(input.value).toBe("back"));
    await new Promise((r) => setTimeout(r, DEBOUNCE_MS + 100));
    expect(input.value).toBe("back");
    expect(seen.some((sp) => sp.get("q") === "stale")).toBe(false);
  });

  test("a 201-char q is blocked at the input and truncated from the URL", async () => {
    api(() => list());
    renderAt(ui, `/threats?q=${"a".repeat(201)}`);
    await screen.findByText("CVE-2026-0001");
    expect(seen[0].get("q")).toHaveLength(200);
    expect((screen.getByLabelText("Search CVEs") as HTMLInputElement).maxLength).toBe(200);
  });

  test("q with & # % is encoded correctly", async () => {
    api(() => list());
    renderAt(ui, "/threats?q=a%26b%23c%25d");
    await screen.findByText("CVE-2026-0001");
    expect(seen[0].get("q")).toBe("a&b#c%d");
  });

  test("the drawer selection survives filter changes and Clear filters", async () => {
    api(() => list());
    renderAt(ui, "/threats?cve=CVE-2026-0001");
    await screen.findByText("A summary");
    fireEvent.click(screen.getByRole("button", { name: "Exploited" }));
    await waitFor(() => expect(lastUrl).toContain("status=exploited"));
    expect(lastUrl).toContain("cve=CVE-2026-0001");
    fireEvent.click(screen.getByText("Clear filters"));
    await waitFor(() => expect(lastUrl).not.toContain("status="));
    expect(lastUrl).toContain("cve=CVE-2026-0001");
  });

  test("paging: count line, Skip to pagination, focus moves to the count", async () => {
    api((sp) => list(many(50), 120, Number(sp.get("page") ?? 1)));
    renderAt(ui, "/threats");
    await screen.findByText("120 CVEs");
    expect(screen.getByText("Page 1 of 3")).toBeInTheDocument();
    expect(screen.getByText("Previous")).toBeDisabled();
    fireEvent.click(screen.getByText("Skip to pagination"));
    expect(document.activeElement).toBe(screen.getByRole("navigation", { name: "Pagination" }));
    fireEvent.click(screen.getByText("Next"));
    await waitFor(() => expect(lastUrl).toBe("/threats?page=2"));
    await screen.findByText("Page 2 of 3");
    expect(seen[seen.length - 1].get("page")).toBe("2");
    expect(document.activeElement?.className).toBe("scount");
    fireEvent.click(screen.getByText("Next"));
    await screen.findByText("Page 3 of 3");
    expect(screen.getByText("Next")).toBeDisabled();
  });

  test.each([
    [false, "smooth"],
    [true, "auto"],
  ])("paging scrolls the results into view (reduced motion %s -> %s)", async (reduce, behavior) => {
    const scroll = vi.fn();
    Element.prototype.scrollIntoView = scroll;
    vi.stubGlobal("matchMedia", (q: string) => ({ matches: reduce && q.includes("prefers-reduced-motion"), media: q }));
    try {
      api((sp) => list(many(50), 120, Number(sp.get("page") ?? 1)));
      renderAt(ui, "/threats");
      await screen.findByText("120 CVEs");
      fireEvent.click(screen.getByText("Next"));
      await screen.findByText("Page 2 of 3");
      expect(scroll).toHaveBeenCalledWith(expect.objectContaining({ behavior }));
    } finally {
      vi.stubGlobal("matchMedia", undefined);
      delete (Element.prototype as { scrollIntoView?: unknown }).scrollIntoView;
    }
  });

  test("empty state", async () => {
    api(() => list([], 0));
    renderAt(ui, "/threats?q=zzz");
    expect(await screen.findByText("No CVEs match these filters")).toBeInTheDocument();
  });

  test("a page past the end after a filter change shows No results on this page, the real total and a first-page link", async () => {
    api(() => list([], 7, 4));
    renderAt(ui, "/threats?page=4&status=likely");
    expect(await screen.findByText("No results on this page")).toBeInTheDocument();
    expect(screen.getByText("7 CVEs in total")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go to page 1" }).getAttribute("href")).toBe("/threats?status=likely");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  test("an exact CVE id hidden by the filters shows a one-line note", async () => {
    api(() => ({ ...list(), exact_match: true, exact_match_filtered_out: true }));
    renderAt(ui, "/threats?q=CVE-2026-0001&status=exploited");
    const note = await screen.findByRole("note");
    expect(note.textContent).toContain("CVE-2026-0001");
    expect(note.textContent).toContain("outside your current filters");
  });

  test("no note for an ordinary exact match", async () => {
    api(() => ({ ...list(), exact_match: true, exact_match_filtered_out: false }));
    renderAt(ui, "/threats?q=CVE-2026-0001");
    await screen.findByText("A summary");
    expect(screen.queryByRole("note")).toBeNull();
  });

  test("422 shows a message and resets the page to 1", async () => {
    api(
      () =>
        new HttpResponse(JSON.stringify({ detail: "bad" }), {
          status: 422,
          headers: { "content-type": "application/json" },
        }),
    );
    renderAt(ui, "/threats?page=3");
    expect(await screen.findByText("Some filters aren't valid")).toBeInTheDocument();
    await waitFor(() => expect(lastUrl).not.toContain("page="));
  });

  test("rate limit shows retry seconds", async () => {
    api(() => new HttpResponse(null, { status: 429, headers: { "Retry-After": "17" } }));
    renderAt(ui, "/threats");
    expect(await screen.findByText(/Try again in 17 s/)).toBeInTheDocument();
  });

  test("&lt;script&gt; summary renders as literal text", async () => {
    api(() => list([item({ summary: "&lt;script&gt;alert(1)&lt;/script&gt;" })]));
    const { container } = renderAt(ui, "/threats");
    expect(await screen.findByText("<script>alert(1)</script>")).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
  });
});

describe("Threats tabs", () => {
  test("CVEs is the default tab", async () => {
    api(() => list());
    renderAt(ui, "/threats");
    expect(screen.getByRole("tab", { name: "CVEs" })).toHaveAttribute("aria-selected", "true");
    await screen.findByText("CVE-2026-0001");
  });

  test("?tab=news renders the News tab; switching tabs clears q but keeps the drawer selection", async () => {
    api(() => list());
    storiesApi(() => sList());
    renderAt(ui, "/threats?tab=news&q=foo&cve=CVE-2026-0001");
    expect(screen.getByRole("tab", { name: "News" })).toHaveAttribute("aria-selected", "true");
    await screen.findByText("Big & loud");
    expect((screen.getByLabelText("Search stories") as HTMLInputElement).value).toBe("foo");
    fireEvent.click(screen.getByRole("tab", { name: "CVEs" }));
    await waitFor(() => expect(lastUrl).toBe("/threats?cve=CVE-2026-0001"));
    fireEvent.click(screen.getByRole("tab", { name: "News" }));
    await waitFor(() => expect(lastUrl).toContain("tab=news"));
    expect(lastUrl).not.toContain("q=");
  });

  test("tabs are operable by keyboard arrows", async () => {
    api(() => list());
    storiesApi(() => sList());
    renderAt(ui, "/threats");
    await screen.findByText("CVE-2026-0001");
    fireEvent.keyDown(screen.getByRole("tab", { name: "CVEs" }), { key: "ArrowRight" });
    await waitFor(() => expect(lastUrl).toContain("tab=news"));
    fireEvent.keyDown(screen.getByRole("tab", { name: "News" }), { key: "ArrowRight" });
    await waitFor(() => expect(lastUrl).toContain("tab=ransomware"));
    fireEvent.keyDown(screen.getByRole("tab", { name: "Ransomware" }), { key: "ArrowRight" });
    await waitFor(() => expect(lastUrl).toBe("/threats"));
  });
});

describe("Ransomware tab", () => {
  test("guests get a sign-in notice, no stories request, and the credit", async () => {
    storiesApi(() => sList());
    renderAt(ui, "/threats?tab=ransomware&q=foo");
    expect(screen.getByRole("tab", { name: "Ransomware" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByTestId("ransomware-signin")).toHaveTextContent("Sign in to see ransomware activity");
    expect(screen.getByTestId("ransomware-credit")).toBeInTheDocument();
    expect(seenStories.length).toBe(0);
  });

  test("members get kind=ransomware, the search box, the credit and no source filter", async () => {
    signIn(member);
    storiesApi(() => sList([story({ title: "Acme hit", source: "ransomware.live", url: "https://r.example/1" })]));
    renderAt(ui, "/threats?tab=ransomware&source=foo&added=week");
    await screen.findByText("Acme hit");
    expect(seenStories[0].get("kind")).toBe("ransomware");
    expect(seenStories[0].get("source")).toBeNull();
    expect(seenStories[0].get("added")).toBe("week");
    expect(screen.queryByLabelText("Story source")).toBeNull();
    expect(screen.getByLabelText("Search ransomware activity")).toBeInTheDocument();
    expect(screen.getAllByTestId("ransomware-credit").length).toBeGreaterThanOrEqual(2);
  });

  test("the News tab asks for kind=news", async () => {
    storiesApi(() => sList());
    renderAt(ui, "/threats?tab=news");
    await screen.findByText("Big & loud");
    expect(seenStories[0].get("kind")).toBe("news");
  });
});

describe("News tab", () => {
  test("typing debounces into one /api/stories request; page_size is 50", async () => {
    storiesApi(() => sList());
    renderAt(ui, "/threats?tab=news");
    await screen.findByText("Big & loud");
    expect(seenStories[0].get("page_size")).toBe("50");
    const before = seenStories.length;
    const input = screen.getByLabelText("Search stories");
    for (const v of ["l", "lo", "log", "log4"]) fireEvent.change(input, { target: { value: v } });
    await new Promise((r) => setTimeout(r, DEBOUNCE_MS / 2));
    expect(seenStories.length).toBe(before);
    await waitFor(() => expect(seenStories.length).toBe(before + 1));
    expect(seenStories[seenStories.length - 1].get("q")).toBe("log4");
    expect(lastUrl).toBe("/threats?tab=news&q=log4");
  });

  test("a row shows the decoded title once, the source and CVE chips; clicking sets ?story=", async () => {
    storiesApi(() => sList([story({ title: "&amp;lt;b&amp;gt; x" })]));
    const { container } = renderAt(ui, "/threats?tab=news");
    expect(await screen.findByText("&lt;b&gt; x")).toBeInTheDocument();
    expect(container.querySelector("b")).toBeNull();
    expect(screen.getByText("Example News")).toBeInTheDocument();
    expect(screen.getByTestId("news-story")).toBeInTheDocument();
    fireEvent.click(screen.getByText("&lt;b&gt; x"));
    await waitFor(() => expect(lastUrl).toContain("story=https%3A%2F%2Fnews.example%2Fa"));
  });

  test("a CVE chip opens the drawer quick view", async () => {
    storiesApi(() => sList());
    renderAt(ui, "/threats?tab=news");
    fireEvent.click(await screen.findByRole("button", { name: "CVE-2026-0001" }));
    await waitFor(() => expect(lastUrl).toContain("cve=CVE-2026-0001"));
    expect(lastUrl).toContain("tab=news");
  });

  test("the Added select writes ?added= and sends it with source", async () => {
    storiesApi(() => sList());
    renderAt(ui, "/threats?tab=news&source=Wired");
    await screen.findByText("Big & loud");
    expect(seenStories[0].get("source")).toBe("Wired");
    fireEvent.change(screen.getByLabelText("Added"), { target: { value: "week" } });
    await waitFor(() => expect(lastUrl).toBe("/threats?tab=news&source=Wired&added=week"));
    await waitFor(() => expect(seenStories[seenStories.length - 1].get("added")).toBe("week"));
  });

  test("a 201-char q is blocked at the input and truncated", async () => {
    storiesApi(() => sList());
    renderAt(ui, `/threats?tab=news&q=${"a".repeat(201)}`);
    await screen.findByText("Big & loud");
    expect(seenStories[0].get("q")).toHaveLength(200);
    expect((screen.getByLabelText("Search stories") as HTMLInputElement).maxLength).toBe(200);
  });

  test("page beyond the total shows No results on this page, the real total and a first-page link", async () => {
    storiesApi(() => sList([], 120, 40));
    renderAt(ui, "/threats?tab=news&page=40");
    expect(await screen.findByText("No results on this page")).toBeInTheDocument();
    expect(screen.getByText("120 stories in total")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go to page 1" }).getAttribute("href")).toBe("/threats?tab=news");
  });

  test("pagination requests page 2", async () => {
    storiesApi((sp) =>
      sList(
        Array.from({ length: 50 }, (_, i) => story({ url: `https://n.example/${i}`, title: `T${i}` })),
        120,
        Number(sp.get("page") ?? 1),
      ),
    );
    renderAt(ui, "/threats?tab=news");
    await screen.findByText("120 stories");
    fireEvent.click(screen.getByText("Next"));
    await screen.findByText("Page 2 of 3");
    expect(seenStories[seenStories.length - 1].get("page")).toBe("2");
  });

  test("blurring the source box unchanged keeps the page", async () => {
    storiesApi((sp) => sList([story()], 120, Number(sp.get("page") ?? 1)));
    renderAt(ui, "/threats?tab=news&source=Wired&page=2");
    await screen.findByText("Page 2 of 3");
    const box = screen.getByLabelText("Story source");
    fireEvent.focus(box);
    fireEvent.blur(box);
    await new Promise((r) => setTimeout(r, 50));
    expect(lastUrl).toBe("/threats?tab=news&source=Wired&page=2");
    fireEvent.change(box, { target: { value: "Other" } });
    fireEvent.blur(box);
    await waitFor(() => expect(lastUrl).toBe("/threats?tab=news&source=Other"));
  });

  test("empty state", async () => {
    storiesApi(() => sList([], 0));
    renderAt(ui, "/threats?tab=news&q=zzz");
    expect(await screen.findByText("No stories match these filters")).toBeInTheDocument();
  });
});
