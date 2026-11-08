import { QueryClientProvider, type QueryClient } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { setupServer } from "msw/node";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, beforeEach, vi } from "vitest";
import { authStore } from "../lib/api";
import { createQueryClient } from "../lib/queries";
import type { CveItem, Lane, LaneOut, LanesOut, Me, SummaryOut } from "../lib/types";

export const server = setupServer();

/**
 * Wires MSW + a relative-URL fetch into the calling test file. `ready: true` marks the auth
 * bootstrap settled (as a guest) before each test, since data reads wait for it.
 */
export function setupMsw(opts: { ready?: boolean } = {}) {
  if (opts.ready) beforeEach(() => authStore.setReady(true));
  beforeAll(() => {
    server.listen({ onUnhandledRequest: "error" });
    const mswFetch = globalThis.fetch;
    vi.stubGlobal("fetch", (u: RequestInfo | URL, i?: RequestInit) =>
      mswFetch(new URL(String(u), "http://localhost"), i),
    );
  });
  afterEach(() => {
    server.resetHandlers();
    authStore.clear();
    authStore.setReady(false);
    try {
      sessionStorage.clear();
      localStorage.clear();
    } catch {
      // ignore
    }
  });
  afterAll(() => {
    server.close();
    vi.unstubAllGlobals();
  });
}

export const item = (o: Partial<CveItem> = {}): CveItem => ({
  cve_id: "CVE-2026-0001",
  cvss: 9.8,
  epss_percentile: 0.9,
  kev: true,
  kev_added: null,
  kev_source: "cisa",
  poc_badge: false,
  patch_available: null,
  published: null,
  summary: "A summary",
  recent_story_count: 0,
  product: null,
  last_seen: null,
  ...o,
});

export const laneOut = (items: CveItem[] = []): LaneOut => ({ total: items.length, items });

/** LanesOut from plain item arrays; `total` is the item count. */
export const lanes = (exploited: CveItem[] = [], rest: Partial<Record<Lane, CveItem[]>> = {}): LanesOut => ({
  EXPLOITED: laneOut(exploited),
  LIKELY: laneOut(rest.LIKELY),
  LOUD: laneOut(rest.LOUD),
  FRESH: laneOut(rest.FRESH),
});

/** The /summary a given lanes fixture implies (newest KEV date, EXPLOITED total as new_kev). */
const summaryOf = (l: LanesOut): SummaryOut => ({
  range: "7d",
  new_kev: l.EXPLOITED.total,
  kev_due_soon: 0,
  new_critical: l.FRESH.total,
  public_exploits: 0,
  latest_kev_added:
    l.EXPLOITED.items
      .map((c) => c.kev_added ?? "")
      .sort()
      .at(-1) || null,
});

export function handlers(opts: { publicRead?: boolean; lanes?: LanesOut } = {}) {
  server.use(
    http.get("http://localhost/api/health", () =>
      HttpResponse.json({ status: "ok", public_read: opts.publicRead ?? true }),
    ),
    http.get("http://localhost/api/lanes", () => HttpResponse.json(opts.lanes ?? lanes())),
    http.get("http://localhost/api/summary", () => HttpResponse.json(summaryOf(opts.lanes ?? lanes()))),
    http.post("http://localhost/api/auth/logout", () => new HttpResponse(null, { status: 204 })),
  );
}

export const member: Me = { id: 2, email: "member@example.com", role: "member" };
export const admin: Me = { id: 1, email: "admin@example.com", role: "admin" };

export function signIn(u: Me) {
  authStore.setUser(u);
  authStore.setReady(true);
}
export function guest() {
  authStore.setReady(true);
}

export function renderAt(ui: ReactNode, path = "/", qc: QueryClient = createQueryClient()) {
  qc.setDefaultOptions({ queries: { ...qc.getDefaultOptions().queries, retry: false } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}
