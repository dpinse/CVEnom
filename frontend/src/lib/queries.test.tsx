import { QueryClientProvider, focusManager, type QueryClient } from "@tanstack/react-query";
import { cleanup, renderHook, waitFor } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { setupServer } from "msw/node";
import type { ReactNode } from "react";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test, vi } from "vitest";
import { ApiError, AuthError, NetworkError, RateLimited, authStore } from "./api";
import {
  createQueryClient,
  cveSearchPath,
  errorRefetchInterval,
  errorRefetchMs,
  isCoolingOff,
  qk,
  retryAfterOf,
  shouldRetry,
  useCve,
  useCountry,
  useCveSearch,
  useStory,
  useStorySearch,
  useSummary,
  useVolume,
  storySearchPath,
  useGeo,
  useLanes,
  useLoudStories,
} from "./queries";

const B = "http://localhost/api";
const server = setupServer();
beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });
  const mswFetch = globalThis.fetch; // patched by MSW
  // the app client fetches relative URLs; resolve them against the jsdom origin
  vi.stubGlobal("fetch", (u: RequestInfo | URL, i?: RequestInit) =>
    mswFetch(new URL(String(u), "http://localhost"), i),
  );
});
beforeEach(() => authStore.setReady(true)); // data reads wait for the auth bootstrap
afterEach(() => {
  cleanup();
  server.resetHandlers();
  authStore.setReady(false);
});
afterAll(() => {
  server.close();
  vi.unstubAllGlobals();
});

let qc: QueryClient;
function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}
const fresh = () => {
  qc = createQueryClient();
  qc.setDefaultOptions({ queries: { ...qc.getDefaultOptions().queries, retryDelay: 5 } });
};

describe("keys", () => {
  test("qk matches the agreed shapes", () => {
    expect(qk.lanes("7d", 5)).toEqual(["lanes", "7d", 5]);
    expect(qk.summary("24h")).toEqual(["summary", "24h"]);
    expect(qk.volume("30d")).toEqual(["volume", "30d"]);
    expect(qk.geo("14d")).toEqual(["geo", "14d"]);
    expect(qk.loud("7d", 20)).toEqual(["loud", "7d", 20]);
    expect(qk.cve("CVE-1", "7d")).toEqual(["cve", "CVE-1", "7d"]);
    expect(qk.cves({ q: "a" })).toEqual(["cves", { q: "a" }]);
    expect(qk.health()).toEqual(["health"]);
  });
  test("qk.lanes keys differ by range and limit", () => {
    expect(qk.lanes("24h", 5)).not.toEqual(qk.lanes("7d", 5));
    expect(qk.lanes("7d", 5)).not.toEqual(qk.lanes("7d", 100));
  });
  test("threats keys include every filter param", () => {
    expect(qk.cves({ added: "week", status: "exploited" })).not.toEqual(qk.cves({ added: "day", status: "exploited" }));
    expect(qk.cves({ sev: "crit" })).not.toEqual(qk.cves({ sev: "crit,high" }));
  });
});

describe("retry policy", () => {
  test("never retries AuthError, RateLimited or 4xx; retries others up to 2 times", () => {
    expect(shouldRetry(0, new AuthError())).toBe(false);
    expect(shouldRetry(0, new RateLimited(5))).toBe(false);
    expect(shouldRetry(0, new ApiError(404, "not_found"))).toBe(false);
    expect(shouldRetry(0, new ApiError(422, "validation_error"))).toBe(false);
    expect(shouldRetry(0, new ApiError(500, "http_500"))).toBe(true);
    expect(shouldRetry(1, new NetworkError())).toBe(true);
    expect(shouldRetry(2, new NetworkError())).toBe(false);
  });

  test("a 500 is retried twice (3 requests) then surfaces", async () => {
    fresh();
    let n = 0;
    server.use(
      http.get(`${B}/lanes`, () => {
        n++;
        return HttpResponse.json({ error: "boom" }, { status: 500 });
      }),
    );
    const { result } = renderHook(() => useLanes("7d"), { wrapper });
    await waitFor(() => expect(result.current.isError).toBe(true), { timeout: 3000 });
    expect(n).toBe(3);
  });

  test("a 404 is not retried", async () => {
    fresh();
    let n = 0;
    server.use(
      http.get(`${B}/cves/CVE-2025-9`, () => {
        n++;
        return HttpResponse.json({ error: "not_found" }, { status: 404 });
      }),
    );
    const { result } = renderHook(() => useCve("CVE-2025-9"), { wrapper });
    await waitFor(() => expect(result.current.isError).toBe(true));
    await new Promise((r) => setTimeout(r, 100));
    expect(n).toBe(1);
  });
});

describe("rate limiting", () => {
  test("a 429 surfaces RateLimited with retryAfter and no retry storm", async () => {
    fresh();
    let n = 0;
    server.use(
      http.get(`${B}/lanes`, () => {
        n++;
        return HttpResponse.json({ error: "rate_limited" }, { status: 429, headers: { "Retry-After": "30" } });
      }),
    );
    const { result } = renderHook(() => useLanes("7d"), { wrapper });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.error).toBeInstanceOf(RateLimited);
    expect(retryAfterOf(result.current.error)).toBe(30);
    await new Promise((r) => setTimeout(r, 300)); // retryDelay is 5ms: a retry would have fired
    expect(n).toBe(1);
    // window focus inside the Retry-After window does not refetch either
    focusManager.setFocused(false);
    focusManager.setFocused(true);
    await new Promise((r) => setTimeout(r, 100));
    expect(n).toBe(1);
    // ...nor does an invalidation honouring the cooldown (what the live hook does)
    const q = qc.getQueryCache().find({ queryKey: qk.lanes("7d", 5) })!;
    expect(isCoolingOff(q)).toBe(true);
    expect(isCoolingOff(q, Date.now() + 31_000)).toBe(false);
  });
});

describe("hooks", () => {
  test("dashboard reads build range-keyed URLs", async () => {
    fresh();
    const seen: string[] = [];
    server.use(
      http.get(`${B}/*`, ({ request }) => {
        const u = new URL(request.url);
        seen.push(u.pathname + u.search);
        return HttpResponse.json({});
      }),
    );
    const hs = [
      renderHook(() => useLanes("24h", 5), { wrapper }),
      renderHook(() => useSummary("14d"), { wrapper }),
      renderHook(() => useVolume("30d"), { wrapper }),
    ];
    await waitFor(() => {
      for (const h of hs) expect(h.result.current.isSuccess).toBe(true);
    });
    expect(seen.sort()).toEqual(["/api/lanes?range=24h&limit=5", "/api/summary?range=14d", "/api/volume?range=30d"]);
  });

  test("paths: geo, loud, cve, search", async () => {
    fresh();
    const seen: string[] = [];
    server.use(
      http.get(`${B}/*`, ({ request }) => {
        const u = new URL(request.url);
        seen.push(u.pathname + u.search);
        return HttpResponse.json({});
      }),
    );
    const g = renderHook(() => useGeo("7d"), { wrapper });
    const l = renderHook(() => useLoudStories("24h", 10), { wrapper });
    const c = renderHook(() => useCve("CVE-2025-1", "14d"), { wrapper });
    const s = renderHook(() => useCveSearch({ q: "log4j", kev: true, min_cvss: 7, page: 2, lane: undefined }), {
      wrapper,
    });
    await waitFor(() => {
      for (const h of [g, l, c, s]) expect(h.result.current.isSuccess).toBe(true);
    });
    expect(seen.sort()).toEqual(
      [
        "/api/geo?range=7d",
        "/api/stories/loud?range=24h&limit=10",
        "/api/cves/CVE-2025-1?range=14d",
        "/api/cves?q=log4j&kev=true&min_cvss=7&page=2",
      ].sort(),
    );
    expect(qc.getQueryData(qk.geo("7d"))).toBeDefined();
  });

  test("useCve is disabled without an id; search path omits empty params", () => {
    fresh();
    const { result } = renderHook(() => useCve(undefined), { wrapper });
    expect(result.current.fetchStatus).toBe("idle");
    expect(cveSearchPath({})).toBe("/cves");
    expect(cveSearchPath({ q: "", page: 1 })).toBe("/cves?page=1");
  });
});

describe("mount gate", () => {
  test("remounting a rate-limited query inside Retry-After does not refetch it", async () => {
    fresh();
    let n = 0;
    server.use(
      http.get(`${B}/lanes`, () => {
        n++;
        return HttpResponse.json({ error: "rate_limited" }, { status: 429, headers: { "Retry-After": "30" } });
      }),
    );
    const first = renderHook(() => useLanes("7d"), { wrapper });
    await waitFor(() => expect(first.result.current.isError).toBe(true));
    first.unmount();
    renderHook(() => useLanes("7d"), { wrapper });
    await new Promise((r) => setTimeout(r, 150));
    expect(n).toBe(1);
  });

  test("a non-429 error still retries on mount", async () => {
    fresh();
    qc.setDefaultOptions({ queries: { ...qc.getDefaultOptions().queries, retry: false } });
    let n = 0;
    server.use(
      http.get(`${B}/lanes`, () => {
        n++;
        return HttpResponse.json({ error: "boom" }, { status: 500 });
      }),
    );
    const first = renderHook(() => useLanes("7d"), { wrapper });
    await waitFor(() => expect(first.result.current.isError).toBe(true));
    first.unmount();
    renderHook(() => useLanes("7d"), { wrapper });
    await waitFor(() => expect(n).toBe(2));
  });
});

describe("I3: error-state polling", () => {
  test("errorRefetchMs: 30 s by default, Retry-After for a 429, never under 15 s", () => {
    expect(errorRefetchMs(new ApiError(500, "x"))).toBe(30_000);
    expect(errorRefetchMs(new RateLimited(90))).toBe(90_000);
    expect(errorRefetchMs(new RateLimited(3))).toBe(15_000);
    expect(errorRefetchInterval({ state: { status: "success" } } as never)).toBe(false);
    expect(errorRefetchInterval({ state: { status: "error", error: new RateLimited(45) } } as never)).toBe(45_000);
  });

  test("a capped Retry-After keeps the interval within 3_600_000 ms", () => {
    const interval = errorRefetchInterval({
      state: { status: "error", error: new RateLimited(99_999_999) },
    } as never) as number;
    expect(interval).toBeLessThanOrEqual(3_600_000);
  });

  test("401/403 never poll; 500 and 429 still do", () => {
    const at = (error: unknown) => errorRefetchInterval({ state: { status: "error", error } } as never);
    expect(at(new ApiError(401, "unauthorized"))).toBe(false);
    expect(at(new ApiError(403, "forbidden"))).toBe(false);
    expect(at(new ApiError(500, "x"))).toBe(30_000);
    expect(at(new RateLimited(45))).toBe(45_000);
  });

  test("an errored lanes query refetches after 30 s", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      fresh();
      let calls = 0;
      server.use(
        http.get(`${B}/lanes`, () => {
          calls++;
          return calls === 1
            ? HttpResponse.json({ error: "gone" }, { status: 404 })
            : HttpResponse.json({ EXPLOITED: [] });
        }),
      );
      const { result } = renderHook(() => useLanes("7d"), { wrapper });
      await waitFor(() => expect(result.current.isError).toBe(true));
      expect(calls).toBe(1);
      await vi.advanceTimersByTimeAsync(25_000);
      expect(calls).toBe(1);
      await vi.advanceTimersByTimeAsync(6_000);
      await waitFor(() => expect(result.current.isSuccess).toBe(true));
      expect(calls).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });

  test("a 429 on lanes waits its Retry-After (not 30 s) before refetching", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      fresh();
      let calls = 0;
      server.use(
        http.get(`${B}/lanes`, () => {
          calls++;
          return calls === 1
            ? HttpResponse.json({ error: "rate_limited" }, { status: 429, headers: { "Retry-After": "75" } })
            : HttpResponse.json({ EXPLOITED: [] });
        }),
      );
      const { result } = renderHook(() => useLanes("7d"), { wrapper });
      await waitFor(() => expect(result.current.isError).toBe(true));
      await vi.advanceTimersByTimeAsync(70_000);
      expect(calls).toBe(1);
      await vi.advanceTimersByTimeAsync(6_000);
      await waitFor(() => expect(result.current.isSuccess).toBe(true));
      expect(calls).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("history and country hooks", () => {
  test("useStory requests /api/story?url=<encoded>; disabled without a url", async () => {
    fresh();
    const url = "https://x.test/a?b=1&c=2";
    let seen = "";
    server.use(
      http.get(`${B}/story`, ({ request }) => {
        seen = new URL(request.url).search;
        return HttpResponse.json({
          title: "t",
          summary: "",
          url,
          source: "s",
          published: "2026-11-01T00:00:00Z",
          cve_ids: [],
          details: {},
        });
      }),
    );
    const off = renderHook(() => useStory(undefined), { wrapper });
    expect(off.result.current.fetchStatus).toBe("idle");
    const { result } = renderHook(() => useStory(url), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(seen).toBe(`?url=${encodeURIComponent(url)}`);
  });

  test("story search keys and path; empty params are omitted", async () => {
    fresh();
    expect(storySearchPath({})).toBe("/stories");
    expect(storySearchPath({ q: "a b", source: "", page: 2 })).toBe("/stories?q=a+b&page=2");
    expect(qk.stories({ q: "x" })).toEqual(["stories", { q: "x" }]);
    expect(qk.story("u")).toEqual(["story", "u"]);
    expect(qk.country("DE", "7d")).toEqual(["geo", "country", "DE", "7d"]);
    server.use(http.get(`${B}/stories`, () => HttpResponse.json({ items: [], page: 1, page_size: 25, total: 0 })));
    const { result } = renderHook(() => useStorySearch({ q: "x" }), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
  });

  test("useCountry requests /api/geo/DE?range=; disabled without a cc", async () => {
    fresh();
    let seen = "";
    server.use(
      http.get(`${B}/geo/DE`, ({ request }) => {
        seen = new URL(request.url).search;
        return HttpResponse.json({
          country_code: "DE",
          window_hours: 48,
          counts: [],
          top_sources: [],
          trend: [],
          trend_unit: "day",
          top_cves: [],
          events: null,
        });
      }),
    );
    const off = renderHook(() => useCountry(undefined, "7d"), { wrapper });
    expect(off.result.current.fetchStatus).toBe("idle");
    const { result } = renderHook(() => useCountry("DE", "30d"), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(seen).toBe("?range=30d");
  });
});
