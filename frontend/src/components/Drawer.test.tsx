import { QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { MemoryRouter, useLocation, useNavigate } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { createQueryClient } from "../lib/queries";
import type { CountryActivity, CountryEvent, CveDetail, GeoEventOut, LoudStory, StoryDetailOut } from "../lib/types";
import { guest, member, server, setupMsw, signIn } from "../test/shell";
import { authStore } from "../lib/api";
import { BACKEND_STORIES_CAP } from "./CveDetail";
import { DrawerHost } from "./DrawerHost";

const flyTo = vi.fn();
vi.mock("./GlobeContext", () => ({ useGlobe: () => ({ flyTo }) }));

setupMsw({ ready: true });
beforeEach(() => flyTo.mockClear());
afterEach(cleanup);

const CVE = "CVE-2026-0001";
const detail = (o: Partial<CveDetail> = {}): CveDetail => ({
  cve_id: CVE,
  cvss: 9.8,
  epss: 0.5,
  epss_percentile: 0.97,
  kev: true,
  kev_added: "2026-10-01",
  kev_source: "cisa",
  poc_badge: true,
  patch_available: true,
  published: "2026-09-30T00:00:00Z",
  summary: "A summary",
  recent_story_count: 1,
  affected: ["Acme Widget 1.0"],
  stories: [],
  geo_events: [],
  kev_name: null,
  kev_action: null,
  kev_notes: null,
  kev_due: null,
  kev_ransomware: null,
  cvss_vector: null,
  cvss_severity: null,
  cwes: [],
  references: [],
  last_modified: null,
  ...o,
});
const ev = (o: Partial<GeoEventOut> = {}): GeoEventOut => ({
  kind: "scan",
  country_code: "DE",
  label: "scan burst",
  magnitude: 3,
  observed_at: "2026-11-05T11:00:00Z",
  details: {},
  ...o,
});
const story = (o: Partial<LoudStory> = {}): LoudStory => ({
  title: "Big news",
  summary: "s",
  url: "https://news.example/a",
  source: "Example News",
  published: "2026-11-05T11:00:00Z",
  cve_ids: [],
  ...o,
});

function serveCve(d: CveDetail | number) {
  server.use(
    http.get(`http://localhost/api/cves/${CVE}`, () =>
      typeof d === "number" ? new HttpResponse(null, { status: d }) : HttpResponse.json(d),
    ),
  );
}
function Probe() {
  const loc = useLocation();
  const nav = useNavigate();
  return (
    <>
      <output data-testid="search">{loc.search}</output>
      <button type="button" onClick={() => nav(-1)}>
        history-back
      </button>
    </>
  );
}

function renderHost(entries: string[], index = entries.length - 1) {
  const qc = createQueryClient();
  qc.setDefaultOptions({ queries: { ...qc.getDefaultOptions().queries, retry: false } });
  const utils = render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={entries} initialIndex={index}>
        <span className="skip">skip</span>
        <header className="command">
          <button type="button">header-btn</button>
        </header>
        <aside className="alertbar">
          <button type="button">alert-btn</button>
        </aside>
        <div className="notice" role="status">
          notice
        </div>
        <header className="inner-card-header">
          <button type="button">other-header-btn</button>
        </header>
        <main id="main" tabIndex={-1}>
          <button type="button">the-row</button>
        </main>
        <Probe />
        <DrawerHost />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...utils, queryClient: qc };
}

const dialog = () => screen.findByRole("dialog");

describe("DrawerHost", () => {
  test("renders nothing with no selection", () => {
    renderHost(["/"]);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  test("ignores an invalid cve param", () => {
    renderHost(["/?cve=nope"]);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  test("dialog semantics: role, aria-modal, labelled by its heading, focus on close", async () => {
    serveCve(detail());
    renderHost(["/?cve=" + CVE]);
    const d = await dialog();
    expect(d).toHaveAttribute("aria-modal", "true");
    const label = d.getAttribute("aria-labelledby")!;
    expect(document.getElementById(label)).toHaveTextContent(CVE);
    expect(screen.getByRole("button", { name: "Close" })).toHaveFocus();
  });

  test("Tab and Shift+Tab cycle within the dialog", async () => {
    serveCve(
      detail({
        stories: [{ title: "T", url: "https://news.example/x", source: "S", published: "2026-11-05T10:00:00Z" }],
      }),
    );
    renderHost(["/?cve=" + CVE]);
    const d = await dialog();
    await screen.findByText("Acme Widget 1.0");
    const close = within(d).getByRole("button", { name: "Close" });
    const links = within(d).getAllByRole("link");
    const link = links[links.length - 1]; // the last focusable element
    link.focus();
    fireEvent.keyDown(link, { key: "Tab" });
    expect(close).toHaveFocus();
    fireEvent.keyDown(close, { key: "Tab", shiftKey: true });
    expect(link).toHaveFocus();
  });

  test("Esc closes the drawer and returns focus to the row", async () => {
    serveCve(detail());
    function Opener() {
      const nav = useNavigate();
      return (
        <button type="button" onClick={() => nav("/?cve=" + CVE)}>
          open-row
        </button>
      );
    }
    const qc = createQueryClient();
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <main id="main" tabIndex={-1}>
            <Opener />
          </main>
          <DrawerHost />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const row = screen.getByRole("button", { name: "open-row" });
    row.focus();
    fireEvent.click(row);
    await dialog();
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(row).toHaveFocus();
  });

  test("falls back to <main> when the opener is gone", async () => {
    serveCve(detail());
    renderHost(["/?cve=" + CVE]);
    await dialog();
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.getElementById("main")).toHaveFocus();
  });

  test("scrim click closes", async () => {
    serveCve(detail());
    renderHost(["/?cve=" + CVE]);
    await dialog();
    fireEvent.click(screen.getByTestId("scrim"));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  test("background is inert and body scroll locked while open, restored on close", async () => {
    serveCve(detail());
    renderHost(["/?cve=" + CVE]);
    await dialog();
    expect(document.getElementById("main")).toHaveAttribute("inert");
    expect(document.querySelector("header.command")).toHaveAttribute("inert");
    expect(document.querySelector(".skip")).toHaveAttribute("inert");
    expect(document.querySelector(".alertbar")).toHaveAttribute("inert");
    expect(document.querySelector(".notice")).toHaveAttribute("inert");
    expect(document.querySelector("header.inner-card-header")).not.toHaveAttribute("inert");
    expect(document.body.style.overflow).toBe("hidden");
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.getElementById("main")).not.toHaveAttribute("inert");
    expect(document.querySelector("header.command")).not.toHaveAttribute("inert");
    expect(document.querySelector(".skip")).not.toHaveAttribute("inert");
    expect(document.querySelector(".alertbar")).not.toHaveAttribute("inert");
    expect(document.querySelector(".notice")).not.toHaveAttribute("inert");
    expect(document.body.style.overflow).toBe("");
  });

  test("closing clears the param with replace, so Back does not reopen", async () => {
    serveCve(detail());
    renderHost(["/", "/?cve=" + CVE]);
    await dialog();
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(screen.getByTestId("search")).toHaveTextContent("");
    fireEvent.click(screen.getByRole("button", { name: "history-back" }));
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});

describe("CveDetail", () => {
  test("shows a skeleton while loading", async () => {
    server.use(http.get(`http://localhost/api/cves/${CVE}`, () => new Promise(() => {})));
    renderHost(["/?cve=" + CVE]);
    expect(await screen.findByRole("status", { name: "Loading CVE" })).toBeInTheDocument();
  });

  test("404 shows CVE not found", async () => {
    serveCve(404);
    renderHost(["/?cve=" + CVE]);
    expect(await screen.findByText("CVE not found")).toBeInTheDocument();
  });

  test("other errors show a message with a working retry", async () => {
    serveCve(500);
    renderHost(["/?cve=" + CVE]);
    const retry = await screen.findByRole("button", { name: "Retry" });
    serveCve(detail());
    fireEvent.click(retry);
    expect(await screen.findByText("A summary")).toBeInTheDocument();
  });

  test("meters: widths are clamped to 0-100% and expose meter semantics", async () => {
    serveCve(detail({ cvss: 14, epss_percentile: -3 }));
    renderHost(["/?cve=" + CVE]);
    const cvss = await screen.findByRole("meter", { name: "CVSS" });
    const epss = screen.getByRole("meter", { name: "EPSS percentile" });
    expect((cvss.firstElementChild as HTMLElement).style.width).toBe("100%");
    expect((epss.firstElementChild as HTMLElement).style.width).toBe("0%");
    expect(cvss).toHaveAttribute("aria-valuenow", "10");
    expect(cvss).toHaveAttribute("aria-valuemin", "0");
    expect(cvss).toHaveAttribute("aria-valuemax", "10");
    expect(epss).toHaveAttribute("aria-valuenow", "0");
  });

  test("meters: null values show n/a with an empty meter", async () => {
    serveCve(detail({ cvss: null, epss_percentile: null }));
    renderHost(["/?cve=" + CVE]);
    const cvss = await screen.findByRole("meter", { name: "CVSS" });
    expect(screen.getAllByText("n/a")).toHaveLength(2);
    expect((cvss.firstElementChild as HTMLElement).style.width).toBe("0%");
    expect(cvss).not.toHaveAttribute("aria-valuenow");
  });

  test("EPSS shows as pNN and chips show KEV source/date, PoC, patch", async () => {
    serveCve(detail());
    renderHost(["/?cve=" + CVE]);
    expect(await screen.findByText("p97")).toBeInTheDocument();
    expect(screen.getByText(/KEV · cisa · 2026-10-01/)).toBeInTheDocument();
    expect(screen.getByText("public PoC")).toBeInTheDocument();
    expect(screen.getByText("patch available")).toBeInTheDocument();
    expect(screen.getByText("in the wild")).toBeInTheDocument();
  });

  test("patch unknown when null", async () => {
    serveCve(detail({ patch_available: null }));
    renderHost(["/?cve=" + CVE]);
    expect(await screen.findByText("patch unknown")).toBeInTheDocument();
  });

  test("double-encoded summary renders as literal text (decoded once, no innerHTML)", async () => {
    serveCve(detail({ summary: "&amp;lt;b&amp;gt;" }));
    renderHost(["/?cve=" + CVE]);
    const d = await dialog();
    await waitFor(() => expect(d).toHaveTextContent("&lt;b&gt;"));
    expect(d.querySelector("b")).toBeNull();
  });

  test("a javascript: story url renders no anchor; safe links carry rel and target", async () => {
    serveCve(
      detail({
        stories: [
          { title: "Bad", url: "javascript:alert(1)", source: "S", published: "2026-11-05T09:00:00Z" },
          { title: "Good", url: "https://news.example/g", source: "S", published: "2026-11-05T10:00:00Z" },
        ],
      }),
    );
    renderHost(["/?cve=" + CVE]);
    const d = await dialog();
    await screen.findByText("Good");
    expect(screen.getByText("Bad")).toBeInTheDocument();
    const links = d.querySelectorAll(".slinks a"); // the standard NVD / KEV / cve.org links are covered below
    expect(links).toHaveLength(1);
    d.querySelectorAll("a").forEach((a) => {
      expect(a).toHaveAttribute("rel", "noopener noreferrer");
      expect(a).toHaveAttribute("target", "_blank");
    });
  });

  test("stories are listed newest first", async () => {
    serveCve(
      detail({
        stories: [
          { title: "Older", url: "https://n.example/1", source: "S", published: "2026-11-01T00:00:00Z" },
          { title: "Newer", url: "https://n.example/2", source: "S", published: "2026-11-04T00:00:00Z" },
        ],
      }),
    );
    renderHost(["/?cve=" + CVE]);
    await screen.findByText("Newer");
    const titles = Array.from(document.querySelectorAll(".slinks a")).map((a) => a.textContent);
    expect(titles).toEqual(["Newer", "Older"]);
  });

  test("affected: non-string items render as JSON text and the list is capped with +N more", async () => {
    const many = Array.from({ length: 53 }, (_, i) => `prod-${i}`);
    serveCve(detail({ affected: [{ vendor: "Acme", v: ["1", "2"] }, ...many] }));
    renderHost(["/?cve=" + CVE]);
    expect(await screen.findByText('{"vendor":"Acme","v":["1","2"]}')).toBeInTheDocument();
    expect(screen.getByText("prod-48")).toBeInTheDocument();
    expect(screen.queryByText("prod-49")).toBeNull();
    expect(screen.getByText("+4 more")).toBeInTheDocument();
  });

  test("geo event details: keys and values are text, nested values are JSON, capped at 12", async () => {
    const details: Record<string, unknown> = { "<img src=x onerror=alert(1)>": "<b>v</b>", nested: { a: [1] } };
    for (let i = 0; i < 12; i++) details[`k${i}`] = i;
    serveCve(detail({ geo_events: [ev({ details })] }));
    renderHost(["/?cve=" + CVE]);
    const d = await dialog();
    expect(await screen.findByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(screen.getByText("<b>v</b>")).toBeInTheDocument();
    expect(screen.getByText('{"a":[1]}')).toBeInTheDocument();
    expect(d.querySelector("img")).toBeNull();
    expect(d.querySelector("dd b")).toBeNull();
    expect(screen.getByText("+2 more")).toBeInTheDocument();
    expect(screen.queryByText("k11")).toBeNull();
  });

  test("geo event shows kind and country name; flies once to the top-magnitude country", async () => {
    serveCve(
      detail({
        geo_events: [
          ev({ country_code: "DE", magnitude: 2 }),
          ev({ country_code: "FR", magnitude: 9, kind: "outage" }),
          ev({ country_code: "xx", magnitude: 99 }),
        ],
      }),
    );
    renderHost(["/?cve=" + CVE]);
    expect(await screen.findByText("France")).toBeInTheDocument();
    expect(screen.getByText("Germany")).toBeInTheDocument();
    expect(screen.getByText("infrastructure outage")).toBeInTheDocument();
    await waitFor(() => expect(flyTo).toHaveBeenCalledTimes(1));
    expect(flyTo).toHaveBeenCalledWith("FR");
  });

  test("a refetch with a fresh d for the same CVE does not fly again", async () => {
    serveCve(detail({ geo_events: [ev({ country_code: "FR", magnitude: 9 })] }));
    const r = renderHost(["/?cve=" + CVE]);
    await waitFor(() => expect(flyTo).toHaveBeenCalledTimes(1));
    serveCve(detail({ summary: "A fresher summary", geo_events: [ev({ country_code: "FR", magnitude: 9 })] }));
    const qc = r.queryClient;
    await qc.invalidateQueries({ queryKey: ["cve", CVE] });
    expect(await screen.findByText("A fresher summary")).toBeInTheDocument();
    expect(flyTo).toHaveBeenCalledTimes(1);
  });

  test("an invalid country_code is skipped and does not call flyTo", async () => {
    serveCve(detail({ geo_events: [ev({ country_code: "deu" }), ev({ country_code: null })] }));
    renderHost(["/?cve=" + CVE]);
    await screen.findByText("Geo events");
    expect(flyTo).not.toHaveBeenCalled();
    expect(screen.queryByText("Germany")).toBeNull();
  });
});

describe("anonymous story-count note and ransomware credit (CveDetail)", () => {
  const NOTE = "Some sources are visible to signed-in users only.";
  test("anonymous with recent_story_count above the stories shown: muted note", async () => {
    guest();
    serveCve(
      detail({
        recent_story_count: 3,
        stories: [{ title: "T", url: "https://news.example/a", source: "Example", published: "2026-11-05T11:00:00Z" }],
      }),
    );
    renderHost(["/?cve=" + CVE]);
    expect(await screen.findByText(NOTE)).toBeInTheDocument();
  });
  test("note shows even when no stories are visible at all", async () => {
    guest();
    serveCve(detail({ recent_story_count: 2, stories: [] }));
    renderHost(["/?cve=" + CVE]);
    expect(await screen.findByText(NOTE)).toBeInTheDocument();
  });
  test("no fetch and no note while auth is not ready yet; the guest view loads once it settles", async () => {
    authStore.setReady(false);
    let calls = 0;
    server.use(
      http.get(`http://localhost/api/cves/${CVE}`, () => {
        calls++;
        return HttpResponse.json(detail({ recent_story_count: 3, stories: [] }));
      }),
    );
    renderHost(["/?cve=" + CVE]);
    await dialog();
    await new Promise((r) => setTimeout(r, 30));
    expect(calls).toBe(0);
    expect(screen.queryByText("A summary")).toBeNull();
    expect(screen.queryByText(NOTE)).toBeNull();
    act(() => guest());
    expect(await screen.findByText("A summary")).toBeInTheDocument();
    expect(calls).toBe(1);
    expect(screen.getByText(NOTE)).toBeInTheDocument();
  });
  test("no note when the story list is just capped at the backend limit", async () => {
    guest();
    const many = Array.from({ length: BACKEND_STORIES_CAP }, (_, i) => ({
      title: `S${i}`,
      url: `https://news.example/${i}`,
      source: "Example",
      published: "2026-11-05T11:00:00Z",
    }));
    serveCve(detail({ recent_story_count: BACKEND_STORIES_CAP + 7, stories: many }));
    renderHost(["/?cve=" + CVE]);
    await screen.findByText("S0");
    expect(screen.queryByText(NOTE)).toBeNull();
  });
  test("no note when the counts match, or when signed in", async () => {
    serveCve(detail({ recent_story_count: 0, stories: [] }));
    const { unmount } = renderHost(["/?cve=" + CVE]);
    await screen.findByText("A summary");
    expect(screen.queryByText(NOTE)).toBeNull();
    unmount();
    signIn(member);
    serveCve(detail({ recent_story_count: 4, stories: [] }));
    renderHost(["/?cve=" + CVE]);
    await screen.findByText("A summary");
    expect(screen.queryByText(NOTE)).toBeNull();
  });
  test("a ransomware.live story carries the credit link; other sources do not", async () => {
    signIn(member);
    serveCve(
      detail({
        recent_story_count: 2,
        stories: [
          {
            title: "Victim",
            url: "https://www.ransomware.live/id/x",
            source: "ransomware.live",
            published: "2026-11-05T11:00:00Z",
          },
          { title: "News", url: "https://news.example/a", source: "Example", published: "2026-11-05T10:00:00Z" },
        ],
      }),
    );
    renderHost(["/?cve=" + CVE]);
    const credit = await screen.findByTestId("ransomware-credit");
    expect(screen.getAllByTestId("ransomware-credit")).toHaveLength(1);
    expect(credit).toHaveTextContent("Ransomware data: ransomware.live");
    const a = within(credit).getByRole("link", { name: "ransomware.live" });
    expect(a).toHaveAttribute("href", "https://www.ransomware.live/");
    expect(a).toHaveAttribute("rel", "noopener noreferrer");
  });
});

const full = (): CveDetail =>
  detail({
    kev_name: "Acme Gateway Auth Bypass",
    kev_action: "Apply the vendor patch.",
    kev_notes: "See the advisory.",
    kev_due: "2026-10-22",
    kev_ransomware: true,
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvss_severity: "CRITICAL",
    cwes: ["CWE-79", "NVD-CWE-Other"],
    references: [
      { url: "https://vendor.example/advisory?a=1&amp;b=2", tags: ["Vendor Advisory", "Patch"] },
      { url: "javascript:alert(1)", tags: [] },
      { url: "http://abcdef.onion/x", tags: [] },
    ],
    last_modified: "2026-10-05T00:00:00Z",
    stories: [{ title: "Story A", url: "https://news.example/a", source: "S", published: "2026-11-05T10:00:00Z" }],
    geo_events: [ev()],
  });

describe("CveDetail sections", () => {
  const SECTIONS = [
    "Summary",
    "Scores",
    "Key dates",
    "Required action",
    "Affected products",
    "Weaknesses",
    "References",
    "Related stories",
    "Geo events",
    "Links",
  ];
  const headings = (d: HTMLElement) => Array.from(d.querySelectorAll(".seclabel")).map((e) => e.textContent);

  test("a full fixture renders every section in order, with the header chips", async () => {
    serveCve(full());
    renderHost(["/?cve=" + CVE]);
    const d = await dialog();
    await screen.findByText("Required action");
    expect(headings(d)).toEqual(SECTIONS);
    expect(within(d).getByText("Acme Gateway Auth Bypass")).toBeInTheDocument();
    expect(within(d).getByText("CRITICAL")).toBeInTheDocument();
    expect(within(d).getByText("ransomware use")).toBeInTheDocument();
    expect(within(d).getByTestId("cvss-vector")).toHaveTextContent("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(within(d).getByText("EPSS score 0.500")).toBeInTheDocument();
    for (const [k, v] of [
      ["Published", "2026-09-30"],
      ["Last modified", "2026-10-05"],
      ["KEV added", "2026-10-01"],
      ["CISA due", "2026-10-22"],
    ])
      expect(within(d).getByText(k).nextElementSibling).toHaveTextContent(v);
    expect(within(d).getByText("Apply the vendor patch.")).toBeInTheDocument();
  });

  test("NULL and empty data render no empty section headings", async () => {
    serveCve(
      detail({
        summary: "",
        affected: [],
        published: null as unknown as string,
        kev: false,
        kev_added: null,
        recent_story_count: 0,
        cvss: null,
        epss: null,
        epss_percentile: null,
        cwes: [],
        references: null as unknown as CveDetail["references"],
      }),
    );
    renderHost(["/?cve=" + CVE]);
    const d = await dialog();
    await screen.findByText("Links");
    expect(headings(d)).toEqual(["Links"]);
    expect(within(d).queryByText("Scores")).toBeNull();
    expect(within(d).queryByText("References")).toBeNull();
    expect(within(d).queryByText("Weaknesses")).toBeNull();
    expect(within(d).queryByText("ransomware use")).toBeNull();
  });

  test("a severity chip is derived from the CVSS score when cvss_severity is null", async () => {
    serveCve(detail({ cvss: 9.8, cvss_severity: null }));
    renderHost(["/?cve=" + CVE]);
    expect(await within(await dialog()).findByText("Critical")).toBeInTheDocument();
  });

  test("a CWE links to cwe.mitre.org; a non-numeric one is plain text", async () => {
    serveCve(full());
    renderHost(["/?cve=" + CVE]);
    const d = await dialog();
    const a = await within(d).findByRole("link", { name: "CWE-79" });
    expect(a).toHaveAttribute("href", "https://cwe.mitre.org/data/definitions/79.html");
    expect(within(d).getByText("NVD-CWE-Other").closest("a")).toBeNull();
  });

  test("a reference shows its hostname (decoded once) and tags; unsafe and .onion references render no anchor", async () => {
    serveCve(full());
    renderHost(["/?cve=" + CVE]);
    const d = await dialog();
    const a = await within(d).findByRole("link", { name: "vendor.example" });
    expect(a).toHaveAttribute("href", "https://vendor.example/advisory?a=1&b=2");
    expect(within(d).getByText("Vendor Advisory")).toBeInTheDocument();
    expect(within(d).getByText("Patch")).toBeInTheDocument();
    const refs = d.querySelector(".refs")!;
    expect(refs.querySelectorAll("a")).toHaveLength(1);
    expect(within(d).getByText("javascript:alert(1)").closest("a")).toBeNull();
    expect(within(d).getByText("http://abcdef.onion/x").closest("a")).toBeNull();
  });

  test("NVD and cve.org links are always present, CISA KEV only for KEV; all carry rel and target", async () => {
    serveCve(detail({ kev: false }));
    const first = renderHost(["/?cve=" + CVE]);
    let d = await dialog();
    await within(d).findByText("Links");
    expect(within(d).getByRole("link", { name: "NVD" })).toHaveAttribute(
      "href",
      `https://nvd.nist.gov/vuln/detail/${CVE}`,
    );
    expect(within(d).getByRole("link", { name: "cve.org" })).toHaveAttribute(
      "href",
      `https://www.cve.org/CVERecord?id=${CVE}`,
    );
    expect(within(d).queryByRole("link", { name: "CISA KEV" })).toBeNull();
    first.unmount();
    serveCve(detail({ kev: true }));
    renderHost(["/?cve=" + CVE]);
    d = await dialog();
    const kev = await within(d).findByRole("link", { name: "CISA KEV" });
    expect(kev.getAttribute("href")).toContain("cisa.gov/known-exploited-vulnerabilities-catalog");
    d.querySelectorAll("a").forEach((a) => {
      expect(a).toHaveAttribute("rel", "noopener noreferrer");
      expect(a).toHaveAttribute("target", "_blank");
    });
  });
});

describe("StoryDetail", () => {
  const url = "https://news.example/a";
  const open = () => renderHost(["/?story=" + encodeURIComponent(url)]);
  const serveStory = (s: StoryDetailOut | number, u = url) =>
    server.use(
      http.get("http://localhost/api/story", ({ request }) => {
        expect(new URL(request.url).searchParams.get("url")).toBe(u);
        return typeof s === "number" ? HttpResponse.json({ error: "not_found" }, { status: s }) : HttpResponse.json(s);
      }),
    );
  const sd = (o: Partial<StoryDetailOut> = {}): StoryDetailOut => ({ ...story(), details: {}, ...o });
  const RURL = "https://www.ransomware.live/id/x";
  const ransom = (o: Partial<StoryDetailOut> = {}): StoryDetailOut =>
    sd({
      url: RURL,
      source: "ransomware.live",
      details: {
        victim: "Victim &amp; Co",
        group: "grp",
        activity: "Manufacturing",
        country: "DE",
        attackdate: "2026-10-30",
        discovered: "2026-11-01",
        website: "victim.example",
        description: "Desc &amp;amp; more",
        press: ["https://press.example/a?x=1&amp;y=2", "http://abcdef.onion/p"],
      },
      ...o,
    });

  test("a story outside the loud feed loads through /api/story, with Open article and CVE chips that select ?cve=", async () => {
    serveStory(sd({ title: "Big &amp; loud", summary: "&amp;lt;b&amp;gt;", cve_ids: [CVE] }));
    serveCve(detail());
    open();
    const d = await dialog();
    expect(await screen.findByText("Big & loud")).toBeInTheDocument();
    await waitFor(() => expect(d).toHaveTextContent("&lt;b&gt;"));
    expect(d.querySelector("b")).toBeNull();
    const a = screen.getByRole("link", { name: "Open article" });
    expect(a).toHaveAttribute("rel", "noopener noreferrer");
    fireEvent.click(screen.getByRole("button", { name: CVE }));
    await waitFor(() => expect(screen.getByTestId("search")).toHaveTextContent("cve=" + CVE));
    expect(await screen.findByText("A summary")).toBeInTheDocument();
  });

  test("ransomware details render; the website is text, not a link; the .onion press link is plain text; no img", async () => {
    serveStory(ransom(), RURL);
    renderHost(["/?story=" + encodeURIComponent(RURL)]);
    const d = await dialog();
    const block = await within(d).findByTestId("ransom-details");
    for (const [k, v] of [
      ["Victim", "Victim & Co"],
      ["Group", "grp"],
      ["Sector", "Manufacturing"],
      ["Country", "Germany"],
      ["Attack date", "2026-10-30"],
      ["Discovered", "2026-11-01"],
      ["Website", "victim.example"],
    ])
      expect(within(block).getByText(k).nextElementSibling).toHaveTextContent(v);
    expect(block.querySelector("a")).toBeNull();
    expect(within(d).getByText("Desc &amp; more")).toBeInTheDocument();
    const press = await within(d).findByRole("link", { name: "press.example" });
    expect(press).toHaveAttribute("href", "https://press.example/a?x=1&y=2");
    expect(press).toHaveAttribute("rel", "noopener noreferrer");
    expect(within(d).getByText("http://abcdef.onion/p").closest("a")).toBeNull();
    expect(within(d).getByRole("link", { name: "View on ransomware.live" })).toHaveAttribute("href", RURL);
    expect(within(d).getByTestId("ransomware-credit")).toBeInTheDocument();
    expect(d.querySelector("img")).toBeNull();
  });

  test("a null website omits that line", async () => {
    serveStory(ransom({ details: { victim: "V", website: null } }), RURL);
    renderHost(["/?story=" + encodeURIComponent(RURL)]);
    const d = await dialog();
    await within(d).findByTestId("ransom-details");
    expect(within(d).queryByText("Website")).toBeNull();
  });

  test("other sources show no credit and no details block", async () => {
    serveStory(sd());
    open();
    await dialog();
    await screen.findByText("Big news");
    expect(screen.queryByTestId("ransomware-credit")).toBeNull();
    expect(screen.queryByTestId("ransom-details")).toBeNull();
  });

  test("a 404 shows the not-found copy with no anchor and never the URL", async () => {
    const evil = "https://evil.example/login";
    serveStory(404, evil);
    renderHost(["/?story=" + encodeURIComponent(evil)]);
    const d = await dialog();
    expect(await within(d).findByText("Story not found (it may have been removed)")).toBeInTheDocument();
    expect(d.querySelector("a")).toBeNull();
    expect(d).not.toHaveTextContent("evil.example");
  });

  test("M7: duplicate CVE ids on a story render without React key warnings", async () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    serveStory(sd({ cve_ids: [CVE, CVE, "junk", "junk"] }));
    open();
    await dialog();
    expect(await screen.findAllByRole("button", { name: CVE })).toHaveLength(2);
    expect(errors.mock.calls.flat().join(" ")).not.toMatch(/same key/);
    errors.mockRestore();
  });

  test("a server error says it could not load, not that the story is gone", async () => {
    server.use(http.get("http://localhost/api/story", () => new HttpResponse(null, { status: 500 })));
    open();
    expect(await screen.findByText("Couldn't load this story")).toBeInTheDocument();
    expect(screen.queryByText(/not found/)).toBeNull();
  });

  test("empty references and cwes lists render no References or Weaknesses heading", async () => {
    serveCve(detail({ references: [], cwes: [] }));
    renderHost(["/?cve=" + CVE]);
    const d = await dialog();
    await screen.findByText("Scores");
    expect(within(d).queryByText("References")).toBeNull();
    expect(within(d).queryByText("Weaknesses")).toBeNull();
  });

  for (const bad of ["javascript:alert(1)", "http://abcdef.onion/old-story"]) {
    test(`an unsafe ?story= (${bad.slice(0, 10)}) shows not-found: no fetch, no anchor, no echo; Esc clears it`, async () => {
      let calls = 0;
      server.use(
        http.get("http://localhost/api/story", () => {
          calls++;
          return HttpResponse.json({ error: "not_found" }, { status: 404 });
        }),
      );
      renderHost(["/?story=" + encodeURIComponent(bad)]);
      const d = await dialog();
      expect(within(d).getByText("Story not found (it may have been removed)")).toBeInTheDocument();
      expect(d.querySelector("a")).toBeNull();
      expect(d.innerHTML).not.toMatch(/onion|javascript/i);
      await new Promise((r) => setTimeout(r, 30));
      expect(calls).toBe(0);
      fireEvent.keyDown(document, { key: "Escape" });
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
      expect(screen.getByTestId("search")).toHaveTextContent("");
    });
  }
});

describe("CountryDetail", () => {
  const trend = (vals: number[]) =>
    vals.map((events, i) => ({ bucket: `2026-11-05T${String(i).padStart(2, "0")}:00:00Z`, events }));
  const act1 = (o: Partial<CountryActivity> = {}): CountryActivity => ({
    country_code: "DE",
    window_hours: 24,
    counts: [
      { kind: "scan", events: 12, magnitude: 5 },
      { kind: "outage", events: 2, magnitude: 3 },
    ],
    top_sources: [{ source: "greynoise", events: 10 }],
    trend: trend([0, 5, 0, 7]),
    events: null,
    ...o,
  });
  const cev = (o: Partial<CountryEvent> = {}): CountryEvent => ({
    source: "greynoise",
    kind: "scan",
    label: "scan burst",
    magnitude: 3,
    observed_at: "2026-11-05T11:00:00Z",
    asn: null,
    story_url: null,
    details: {},
    ...o,
  });
  const serve = (a: CountryActivity) => server.use(http.get("http://localhost/api/geo/DE", () => HttpResponse.json(a)));
  const open = () => renderHost(["/?country=DE"]);

  test("opens a Germany dialog, flies the globe there, lists counts and sources; anonymous gets no events", async () => {
    serve(act1());
    open();
    const d = await dialog();
    expect(within(d).getByRole("heading", { name: "Germany" })).toBeInTheDocument();
    expect(await within(d).findByText("exploit scanning")).toBeInTheDocument();
    expect(within(d).getByText("greynoise")).toBeInTheDocument();
    expect(within(d).getByText("Sign in to see individual events")).toBeInTheDocument();
    expect(within(d).queryByTestId("country-events")).toBeNull();
    expect(flyTo).toHaveBeenCalledWith("DE");
  });

  test("lowercase or unknown country params open no drawer", () => {
    renderHost(["/?country=de"]);
    expect(screen.queryByRole("dialog")).toBeNull();
    cleanup();
    renderHost(["/?country=QQ"]);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  test("signed in: events with decoded label, source, link, and the ransomware credit", async () => {
    signIn(member);
    serve(
      act1({
        events: [
          cev({
            label: "Victim &amp; Co",
            source: "ransomware.live",
            kind: "victim",
            story_url: "https://www.ransomware.live/id/x",
          }),
          cev({ label: "second", story_url: "https://news.example/a?x=1&amp;y=2" }),
        ],
      }),
    );
    open();
    const d = await dialog();
    const list = await within(d).findByTestId("country-events");
    expect(within(list).getByText("Victim & Co")).toBeInTheDocument();
    expect(within(d).getByTestId("ransomware-credit")).toBeInTheDocument();
    const a = within(list)
      .getAllByRole("link")
      .find((l) => l.getAttribute("href") === "https://news.example/a?x=1&y=2")!;
    expect(a).toHaveAttribute("target", "_blank");
    expect(a).toHaveAttribute("rel", "noopener noreferrer");
    expect(within(d).queryByText("Sign in to see individual events")).toBeNull();
  });

  test("no credit without a ransomware.live event", async () => {
    signIn(member);
    serve(act1({ events: [cev()] }));
    open();
    const d = await dialog();
    await within(d).findByTestId("country-events");
    expect(within(d).queryByTestId("ransomware-credit")).toBeNull();
  });

  test("a label with an escaped <script> renders literally; a .onion story_url renders no anchor", async () => {
    signIn(member);
    serve(
      act1({
        events: [cev({ label: "&lt;script&gt;alert(1)&lt;/script&gt;", story_url: "http://abcdef.onion/x" })],
      }),
    );
    open();
    const d = await dialog();
    const list = await within(d).findByTestId("country-events");
    expect(within(list).getByText("<script>alert(1)</script>")).toBeInTheDocument();
    expect(list.querySelector("script")).toBeNull();
    expect(within(list).queryAllByRole("link")).toHaveLength(0);
    expect(list.textContent).toContain("abcdef.onion");
  });

  test("the trend shows for a busy window and is omitted when sparse; it holds no API text", async () => {
    serve(act1());
    const { unmount } = open();
    const d = await dialog();
    const svg = await within(d).findByTestId("country-trend");
    expect(svg.tagName.toLowerCase()).toBe("svg");
    expect(svg.querySelectorAll("text")).toHaveLength(0);
    unmount();
    serve(act1({ counts: [{ kind: "scan", events: 2, magnitude: 1 }], trend: trend([0, 2, 0]) }));
    open();
    const d2 = await dialog();
    await within(d2).findByText("exploit scanning");
    expect(within(d2).queryByTestId("country-trend")).toBeNull();
    cleanup();
    serve(act1({ trend: trend([0, 0, 9, 0]) })); // 12 events but a single non-zero bucket
    open();
    const d3 = await dialog();
    await within(d3).findByText("exploit scanning");
    expect(within(d3).queryByTestId("country-trend")).toBeNull();
  });

  test("no counts shows the empty note", async () => {
    serve(act1({ counts: [], top_sources: [], trend: [] }));
    open();
    const d = await dialog();
    expect(
      await within(d).findByText("No activity recorded for this country in the last 24 hours"),
    ).toBeInTheDocument();
  });

  test("a failed load shows an alert with Retry", async () => {
    server.use(http.get("http://localhost/api/geo/DE", () => HttpResponse.json({ error: "x" }, { status: 500 })));
    open();
    const d = await dialog();
    expect(await within(d).findByRole("alert")).toBeInTheDocument();
    expect(within(d).getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });
});
