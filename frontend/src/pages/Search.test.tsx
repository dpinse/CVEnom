import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { afterEach, describe, expect, test, vi } from "vitest";
import { item, renderAt, server, setupMsw } from "../test/shell";
import type { CveListOut } from "../lib/types";
import Search, { DEBOUNCE_MS, parseFilters } from "./Search";

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
    <Search />
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

describe("parseFilters", () => {
  test("drops invalid values", () => {
    const f = parseFilters(new URLSearchParams("lane=BOGUS&source=x&min_cvss=11&from=2026-13-45&to=nope&page=0&kev=maybe"));
    expect(f).toEqual({ page: 1 });
    expect(parseFilters(new URLSearchParams("min_cvss=abc&page=1.5")).min_cvss).toBeUndefined();
    expect(parseFilters(new URLSearchParams("page=1.5")).page).toBe(1);
  });
  test("truncates q to 200", () => {
    expect(parseFilters(new URLSearchParams(`q=${"a".repeat(201)}`)).q).toHaveLength(200);
  });
});

describe("Search page", () => {
  test("invalid URL params are never sent to the API", async () => {
    api(() => list());
    renderAt(ui, "/search?lane=BOGUS&min_cvss=11&from=2026-13-45&page=0");
    await screen.findByText("CVE-2026-0001");
    const sp = seen[0];
    for (const k of ["lane", "min_cvss", "from"]) expect(sp.has(k)).toBe(false);
    expect(sp.get("page")).toBe("1");
    expect(sp.get("page_size")).toBe("50");
  });

  test("params round-trip through the URL into inputs and request", async () => {
    api(() => list());
    renderAt(ui, "/search?q=log4j&lane=LOUD&source=cisa&min_cvss=7.5&kev=true&from=2026-01-01&to=2026-02-01&page=1");
    await screen.findByText("CVE-2026-0001");
    expect((screen.getByLabelText("Search CVEs") as HTMLInputElement).value).toBe("log4j");
    expect((screen.getByLabelText("Lane") as HTMLSelectElement).value).toBe("LOUD");
    expect((screen.getByLabelText("Source") as HTMLSelectElement).value).toBe("cisa");
    expect((screen.getByLabelText("Min CVSS") as HTMLInputElement).value).toBe("7.5");
    expect((screen.getByLabelText("KEV only") as HTMLInputElement).checked).toBe(true);
    expect((screen.getByLabelText("From") as HTMLInputElement).value).toBe("2026-01-01");
    expect((screen.getByLabelText("To") as HTMLInputElement).value).toBe("2026-02-01");
    const sp = seen[0];
    expect(sp.get("q")).toBe("log4j");
    expect(sp.get("lane")).toBe("LOUD");
    expect(sp.get("source")).toBe("cisa");
    expect(sp.get("min_cvss")).toBe("7.5");
    expect(sp.get("kev")).toBe("true");
    expect(sp.get("from")).toBe("2026-01-01");
    expect(sp.get("to")).toBe("2026-02-01");
  });

  test("changing a filter writes the URL", async () => {
    api(() => list());
    renderAt(ui, "/search");
    await screen.findByText("CVE-2026-0001");
    fireEvent.change(screen.getByLabelText("Lane"), { target: { value: "FRESH" } });
    await waitFor(() => expect(lastUrl).toBe("/search?lane=FRESH"));
  });

  test("typing debounces into a single request", async () => {
    api(() => list());
    renderAt(ui, "/search");
    await screen.findByText("CVE-2026-0001");
    const before = seen.length;
    const input = screen.getByLabelText("Search CVEs");
    for (const v of ["l", "lo", "log", "log4"]) fireEvent.change(input, { target: { value: v } });
    await new Promise((r) => setTimeout(r, DEBOUNCE_MS / 2));
    expect(seen.length).toBe(before);
    await waitFor(() => expect(seen.length).toBe(before + 1));
    expect(seen[seen.length - 1].get("q")).toBe("log4");
    expect(lastUrl).toBe("/search?q=log4");
  });

  test("whitespace-only q sends nothing; padded q is trimmed", async () => {
    api(() => list());
    renderAt(ui, "/search");
    await screen.findByText("CVE-2026-0001");
    const before = seen.length;
    const input = screen.getByLabelText("Search CVEs");
    fireEvent.change(input, { target: { value: "   " } });
    await new Promise((r) => setTimeout(r, DEBOUNCE_MS + 100));
    expect(lastUrl).toBe("/search");
    expect(seen.length).toBe(before);
    fireEvent.change(input, { target: { value: "  log4j  " } });
    await waitFor(() => expect(seen[seen.length - 1].get("q")).toBe("log4j"));
    expect(lastUrl).toBe("/search?q=log4j");
    expect(parseFilters(new URLSearchParams("q=%20%20%20")).q).toBeUndefined();
  });

  test("an external URL change cancels a pending debounce", async () => {
    api(() => list());
    function Nav() {
      const nav = useNavigate();
      return <button onClick={() => nav("/search?q=back")}>go</button>;
    }
    renderAt(
      <>
        {ui}
        <Nav />
      </>,
      "/search",
    );
    await screen.findByText("CVE-2026-0001");
    const input = screen.getByLabelText("Search CVEs") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "stale" } });
    fireEvent.click(screen.getByText("go"));
    await waitFor(() => expect(input.value).toBe("back"));
    await new Promise((r) => setTimeout(r, DEBOUNCE_MS + 100));
    expect(input.value).toBe("back");
    expect(lastUrl).toBe("/search?q=back");
    expect(seen.some((sp) => sp.get("q") === "stale")).toBe(false);
  });

  test("paging moves focus to the result count; table has explicit roles", async () => {
    api((sp) => list(many(50), 120, Number(sp.get("page") ?? 1)));
    renderAt(ui, "/search");
    await screen.findByText("Showing 1–50 of 120");
    expect(screen.getAllByRole("columnheader").length).toBe(6);
    expect(screen.getAllByRole("cell").length).toBeGreaterThan(0);
    fireEvent.click(screen.getByText("Next"));
    await screen.findByText("Showing 51–100 of 120");
    expect(document.activeElement?.className).toBe("scount");
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
      renderAt(ui, "/search");
      await screen.findByText("Showing 1–50 of 120");
      fireEvent.click(screen.getByText("Next"));
      await screen.findByText("Showing 51–100 of 120");
      expect(scroll).toHaveBeenCalledWith(expect.objectContaining({ behavior }));
    } finally {
      vi.stubGlobal("matchMedia", undefined);
      delete (Element.prototype as { scrollIntoView?: unknown }).scrollIntoView;
    }
  });

  test("a 201-char q is blocked at the input and truncated from the URL", async () => {
    api(() => list());
    renderAt(ui, `/search?q=${"a".repeat(201)}`);
    await screen.findByText("CVE-2026-0001");
    expect(seen[0].get("q")).toHaveLength(200);
    const input = screen.getByLabelText("Search CVEs") as HTMLInputElement;
    expect(input.maxLength).toBe(200);
    expect(input.value).toHaveLength(200);
  });

  test("q with & # % is encoded correctly", async () => {
    api(() => list());
    renderAt(ui, "/search?q=a%26b%23c%25d");
    await screen.findByText("CVE-2026-0001");
    expect(seen[0].get("q")).toBe("a&b#c%d");
    expect(seen[0].has("c")).toBe(false);
  });

  test("the cve param survives filter changes", async () => {
    api(() => list());
    renderAt(ui, "/search?cve=CVE-2026-0001");
    await screen.findByText("CVE-2026-0001");
    fireEvent.change(screen.getByLabelText("Lane"), { target: { value: "LOUD" } });
    await waitFor(() => expect(lastUrl).toContain("lane=LOUD"));
    expect(lastUrl).toContain("cve=CVE-2026-0001");
    fireEvent.click(screen.getByText("Clear filters"));
    await waitFor(() => expect(lastUrl).not.toContain("lane="));
    expect(lastUrl).toContain("cve=CVE-2026-0001");
  });

  test("pagination requests page 2; prev disabled on 1; next disabled at the end", async () => {
    api((sp) => list(many(50), 120, Number(sp.get("page") ?? 1)));
    renderAt(ui, "/search");
    await screen.findByText("Showing 1–50 of 120");
    expect(screen.getByText("Previous")).toBeDisabled();
    fireEvent.click(screen.getByText("Next"));
    await screen.findByText("Showing 51–100 of 120");
    expect(seen[seen.length - 1].get("page")).toBe("2");
    expect(lastUrl).toBe("/search?page=2");
    fireEvent.click(screen.getByText("Next"));
    await screen.findByText("Showing 101–120 of 120");
    expect(screen.getByText("Next")).toBeDisabled();
    expect(screen.getByText("Previous")).not.toBeDisabled();
  });

  test("empty state", async () => {
    api(() => list([], 0));
    renderAt(ui, "/search?q=zzz");
    expect(await screen.findByText("No CVEs match these filters")).toBeInTheDocument();
  });

  test("422 shows a message and resets the page to 1", async () => {
    api(() => new HttpResponse(JSON.stringify({ detail: "bad" }), { status: 422, headers: { "content-type": "application/json" } }));
    renderAt(ui, "/search?page=3");
    expect(await screen.findByText("Some filters aren't valid")).toBeInTheDocument();
    await waitFor(() => expect(lastUrl).not.toContain("page="));
  });

  test("rate limit shows retry seconds", async () => {
    api(() => new HttpResponse(null, { status: 429, headers: { "Retry-After": "17" } }));
    renderAt(ui, "/search");
    expect(await screen.findByText(/Try again in 17 s/)).toBeInTheDocument();
  });

  test("date order hint", async () => {
    api(() => list());
    renderAt(ui, "/search?from=2026-05-01&to=2026-01-01");
    expect(await screen.findByRole("note")).toBeInTheDocument();
  });

  test("row click opens the drawer via ?cve=", async () => {
    api(() => list());
    renderAt(ui, "/search");
    fireEvent.click(await screen.findByText("CVE-2026-0001"));
    await waitFor(() => expect(lastUrl).toContain("cve=CVE-2026-0001"));
  });

  test("&lt;script&gt; summary renders as literal text", async () => {
    api(() => list([item({ summary: "&lt;script&gt;alert(1)&lt;/script&gt;" })]));
    const { container } = renderAt(ui, "/search");
    expect(await screen.findByText("<script>alert(1)</script>")).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
  });
});
