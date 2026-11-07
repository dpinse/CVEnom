import { cleanup, screen, waitFor, within } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, test, vi } from "vitest";
import { renderAt, server, setupMsw } from "../test/shell";
import type { CveDetail } from "../lib/types";
import ThreatPage from "./ThreatPage";

setupMsw({ ready: true });
afterEach(cleanup);

const ID = "CVE-2026-1001";
const T0 = "2026-11-03T10:00:00Z";

const base: CveDetail = {
  cve_id: ID,
  cvss: 9.8,
  epss_percentile: 0.99,
  kev: true,
  kev_added: "2026-11-04",
  kev_source: "cisa",
  poc_badge: true,
  patch_available: false,
  published: T0,
  summary: "Auth bypass in the admin console. A second sentence follows.",
  recent_story_count: 1,
  product: "Acme Gateway",
  last_seen: null,
  epss: 0.9,
  affected: [],
  stories: [
    { title: "Gateway flaw hits thousands", url: "https://news.example/g", source: "Example News", published: T0 },
  ],
  geo_events: [],
  kev_name: null,
  kev_action: "Apply the vendor patch.",
  kev_notes: null,
  kev_due: "2026-11-25",
  kev_ransomware: null,
  cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  cvss_severity: "CRITICAL",
  cwes: ["CWE-287"],
  references: [{ url: "https://vendor.example/advisory?a=1&amp;b=2", tags: ["Vendor Advisory"] }],
  last_modified: null,
  events: [
    { kind: "published", occurred_at: T0, source: "NVD", detail: {} },
    { kind: "kev_added", occurred_at: "2026-11-04T00:00:00Z", source: "CISA KEV", detail: {} },
  ],
  affected_versions: [
    {
      product: "Acme Gateway",
      vendor: "Acme",
      ecosystem: null,
      introduced: "4.0",
      fixed: "4.2.1",
      last_affected: null,
      source: "OSV",
    },
  ],
  related: [{ cve_id: "CVE-2026-1002", cvss: 8.1, kev: false, epss_percentile: 0.5, product: "Acme Gateway" }],
  geo_top: [{ country_code: "DE", events: 12 }],
  updated_at: "2026-11-05T12:30:00Z",
};

function serve(over: Partial<CveDetail> = {}, status = 200) {
  const seen: string[] = [];
  server.use(
    http.get("http://localhost/api/cves/:id", ({ request }) => {
      seen.push(new URL(request.url).pathname + new URL(request.url).search);
      return status === 200
        ? HttpResponse.json({ ...base, ...over })
        : HttpResponse.json({ error: "not_found" }, { status });
    }),
  );
  return seen;
}

const page = (id: string) =>
  renderAt(
    <Routes>
      <Route path="/threats/:cveId" element={<ThreatPage />} />
    </Routes>,
    `/threats/${id}`,
  );

describe("ThreatPage", () => {
  test("a malformed id is the not-found view and makes no request", async () => {
    // onUnhandledRequest is "error": any fetch would fail the test run
    page("not-a-cve");
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeInTheDocument();
  });

  test("a 404 says there is no record", async () => {
    serve({}, 404);
    page(ID);
    expect(await screen.findByText(`We have no record of ${ID}.`)).toBeInTheDocument();
  });

  test("requests the CVE with the fixed 7d window", async () => {
    const seen = serve();
    page(ID);
    await screen.findByRole("heading", { level: 1 });
    expect(seen).toEqual([`/api/cves/${ID}?range=7d`]);
  });

  test("renders the headline, status line and sections in spec order", async () => {
    serve();
    page(ID);
    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent(
      "Acme Gateway: Auth bypass in the admin console",
    );
    expect(screen.getByTestId("status-line")).toHaveTextContent("Data as of 2026-11-05 12:30 UTC");
    expect(screen.getByRole("link", { name: "Threats" })).toHaveAttribute("href", "/threats");
    expect(screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent)).toEqual([
      "Exploitation evidence",
      "What to do",
      "Timeline",
      "Description",
      "CVSS vector",
      "Weakness",
      "References",
    ]);
    expect(screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent)).toEqual([
      "In the news",
      "Related threats",
      "Where it's seen",
    ]);
    expect(screen.getAllByTestId("metrics")[0].querySelectorAll(".metric")).toHaveLength(4);
  });

  test("shows the ladder, timeline with offsets, versions and the decoded vector", async () => {
    serve();
    page(ID);
    await screen.findByRole("heading", { level: 1 });
    const ladder = screen.getByRole("heading", { name: "Exploitation evidence" }).closest("section")!;
    expect(within(ladder).getAllByRole("listitem")).toHaveLength(5);
    expect(ladder).toHaveTextContent("CISA KEV · 2026-11-04");
    const tl = screen.getByRole("heading", { name: "Timeline" }).closest("section")!;
    expect(tl).toHaveTextContent("Published");
    expect(tl).toHaveTextContent("t = 0");
    expect(tl).toHaveTextContent("+14h");
    const table = screen.getByRole("table");
    expect(within(table).getByText("from 4.0 before 4.2.1")).toBeInTheDocument();
    expect(screen.getByText("Network")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "vendor.example/advisory" })).toHaveAttribute(
      "href",
      "https://vendor.example/advisory?a=1&b=2",
    );
    expect(screen.getByText("Vendor Advisory")).toBeInTheDocument();
  });

  test("names the CWE once the lazy map loads", async () => {
    serve();
    page(ID);
    expect(await screen.findByText(/Improper Authentication/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "MITRE definition" })).toHaveAttribute(
      "href",
      "https://cwe.mitre.org/data/definitions/287.html",
    );
  });

  test("empty affected versions show the vendor-advisory note and no table", async () => {
    serve({ affected_versions: [] });
    page(ID);
    expect(await screen.findByText("No version data yet. See the vendor advisory.")).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
  });

  test("the description is verbatim text inside .prose", async () => {
    const summary = `<img src=x onerror=alert(1)> ${"A".repeat(400)}`;
    serve({ summary });
    page(ID);
    await screen.findByRole("heading", { level: 1 });
    const desc = screen.getByText(summary);
    expect(desc.closest(".prose")).not.toBeNull();
    expect(desc.querySelector("img")).toBeNull();
    expect(screen.getByText("Source: NVD")).toBeInTheDocument();
  });

  test("markup in the CISA action renders as literal text", async () => {
    const evil = "<script>alert(1)</script> &lt;b&gt;bold&lt;/b&gt;";
    serve({ kev_action: evil });
    page(ID);
    const box = await screen.findByTestId("kev-action");
    expect(box).toHaveTextContent("<script>alert(1)</script> <b>bold</b>");
    expect(box.querySelector("script")).toBeNull();
    expect(box.querySelector("b > b")).toBeNull();
    expect(box).toHaveTextContent("Federal agencies must comply by 2026-11-25.");
  });

  test("an unsafe reference URL is replaced by a neutral label", async () => {
    serve({ references: [{ url: "javascript:alert(1)", tags: [] }] });
    page(ID);
    expect(await screen.findByText("link removed")).toBeInTheDocument();
    expect(document.querySelector('a[href^="javascript"]')).toBeNull();
  });

  test("no CISA action box without kev_action", async () => {
    serve({ kev_action: null });
    page(ID);
    await screen.findByRole("heading", { level: 1 });
    expect(screen.queryByTestId("kev-action")).toBeNull();
  });

  test("Where it's seen is hidden without geo data and lists countries with it", async () => {
    serve({ geo_top: [] });
    page(ID);
    await screen.findByRole("heading", { level: 1 });
    expect(screen.queryByRole("heading", { name: "Where it's seen" })).toBeNull();
    cleanup();
    serve({ geo_top: [{ country_code: "DE", events: 12 }] });
    page(ID);
    const box = (await screen.findByRole("heading", { name: "Where it's seen" })).closest(".aside-box")!;
    expect(box).toHaveTextContent("Germany");
    expect(box).toHaveTextContent("last 7 days");
    expect(within(box as HTMLElement).getByRole("link", { name: "IP geolocation by DB-IP.com" })).toBeInTheDocument();
  });

  test("related threats link to their own page, capped at four", async () => {
    const related = Array.from({ length: 6 }, (_, i) => ({
      cve_id: `CVE-2026-20${i}0`,
      cvss: 5,
      kev: i === 0,
      epss_percentile: 0.5,
      product: null,
    }));
    serve({ related });
    page(ID);
    const box = (await screen.findByRole("heading", { name: "Related threats" })).closest(".aside-box")!;
    const links = within(box as HTMLElement).getAllByRole("link");
    expect(links).toHaveLength(4);
    expect(links[0]).toHaveAttribute("href", "/threats/CVE-2026-2000");
  });

  test("a server error offers a retry", async () => {
    server.use(http.get("http://localhost/api/cves/:id", () => HttpResponse.json({ error: "x" }, { status: 500 })));
    page(ID);
    await waitFor(() => expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument(), { timeout: 4000 });
    vi.clearAllTimers();
  });
});
