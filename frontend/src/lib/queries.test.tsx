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
  useCveSearch,
  useGeo,
  useLanes,
  useLoudStories,
  useVelocity,
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
    expect(qk.lanes()).toEqual(["lanes"]);
    expect(qk.velocity(7)).toEqual(["velocity", 7]);
    expect(qk.geo(24)).toEqual(["geo", 24]);
    expect(qk.loud(50)).toEqual(["loud", 50]);
    expect(qk.cve("CVE-1")).toEqual(["cve", "CVE-1"]);
    expect(qk.cves({ q: "a" })).toEqual(["cves", { q: "a" }]);
    expect(qk.health()).toEqual(["health"]);
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
    const { result } = renderHook(() => useLanes(), { wrapper });
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
    const { result } = renderHook(() => useLanes(), { wrapper });
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
    const q = qc.getQueryCache().find({ queryKey: qk.lanes() })!;
    expect(isCoolingOff(q)).toBe(true);
    expect(isCoolingOff(q, Date.now() + 31_000)).toBe(false);
  });
});

describe("hooks", () => {
  test("paths: velocity, geo, loud, cve, search", async () => {
    fresh();
    const seen: string[] = [];
    server.use(
      http.get(`${B}/*`, ({ request }) => {
        const u = new URL(request.url);
        seen.push(u.pathname + u.search);
        return HttpResponse.json({});
      }),
    );
    const v = renderHook(() => useVelocity(7), { wrapper });
    const g = renderHook(() => useGeo(), { wrapper });
    const l = renderHook(() => useLoudStories(10), { wrapper });
    const c = renderHook(() => useCve("CVE-2025-1"), { wrapper });
    const s = renderHook(() => useCveSearch({ q: "log4j", kev: true, min_cvss: 7, page: 2, lane: undefined }), { wrapper });
    await waitFor(() => {
      for (const h of [v, g, l, c, s]) expect(h.result.current.isSuccess).toBe(true);
    });
    expect(seen.sort()).toEqual(
      [
        "/api/velocity?days=7",
        "/api/geo?window_hours=24",
        "/api/stories/loud?limit=10",
        "/api/cves/CVE-2025-1",
        "/api/cves?q=log4j&kev=true&min_cvss=7&page=2",
      ].sort(),
    );
    expect(qc.getQueryData(qk.velocity(7))).toBeDefined();
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
    const first = renderHook(() => useLanes(), { wrapper });
    await waitFor(() => expect(first.result.current.isError).toBe(true));
    first.unmount();
    renderHook(() => useLanes(), { wrapper });
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
    const first = renderHook(() => useLanes(), { wrapper });
    await waitFor(() => expect(first.result.current.isError).toBe(true));
    first.unmount();
    renderHook(() => useLanes(), { wrapper });
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
          return calls === 1 ? HttpResponse.json({ error: "gone" }, { status: 404 }) : HttpResponse.json({ EXPLOITED: [] });
        }),
      );
      const { result } = renderHook(() => useLanes(), { wrapper });
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
      const { result } = renderHook(() => useLanes(), { wrapper });
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
