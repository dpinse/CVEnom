import {
  QueryClient,
  keepPreviousData,
  useQuery,
  useQueryClient,
  type Query,
  type UseQueryOptions,
} from "@tanstack/react-query";
import { ApiError, AuthError, RateLimited, api } from "./api";
import type { CveDetail, CveListOut, CveQuery, GeoSummaryItem, Health, LanesOut, LoudStory, VelocityOut } from "./types";

/** Query keys. Shared with the live-update invalidation map (live.ts) and later tasks. */
export const qk = {
  lanes: () => ["lanes"] as const,
  velocity: (days: number) => ["velocity", days] as const,
  geo: (windowHours: number) => ["geo", windowHours] as const,
  loud: (limit: number) => ["loud", limit] as const,
  cve: (id: string) => ["cve", id] as const,
  cves: (params: CveQuery) => ["cves", params] as const,
  health: () => ["health"] as const,
};

export const STALE_TIME_MS = 30_000;
export const MAX_RETRIES = 2;

/** Seconds to wait if `error` is a 429, else null. Lets the UI show "try again in N s". */
export function retryAfterOf(error: unknown): number | null {
  return error instanceof RateLimited ? error.retryAfter : null;
}

/** True while a 429'd query is still inside its Retry-After window. */
export function isCoolingOff(query: Pick<Query, "state">, now = Date.now()): boolean {
  const { error, errorUpdatedAt } = query.state;
  const s = retryAfterOf(error);
  return s !== null && now < errorUpdatedAt + s * 1000;
}

/**
 * Retry up to MAX_RETRIES times, but never for AuthError, RateLimited or any 4xx.
 * RateLimited policy (chosen: no retry at all): a 429 is not retried, and no automatic
 * refetch trigger (window focus, reconnect, mount, WebSocket invalidation) fires until its
 * Retry-After has elapsed. The error is on the query so the UI can show `retryAfterOf(error)`.
 * Mount gate: React Query's retryOnMount would re-fetch a data-less errored query on mount
 * regardless of refetchOnMount, so `useRead` sets `retryOnMount` per observer to false while the
 * query is inside its Retry-After window (not globally: other errors still retry on mount).
 */
export function shouldRetry(failureCount: number, error: unknown): boolean {
  if (error instanceof AuthError || error instanceof RateLimited) return false;
  if (error instanceof ApiError && error.status >= 400 && error.status < 500) return false;
  return failureCount < MAX_RETRIES;
}

const notCooling = (query: Query) => !isCoolingOff(query);

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: STALE_TIME_MS,
        retry: shouldRetry,
        refetchOnWindowFocus: notCooling,
        refetchOnReconnect: notCooling,
        refetchOnMount: notCooling,
      },
    },
  });
}

/** useQuery plus the per-observer cooldown gate on retryOnMount (see shouldRetry). */
function useRead<T>(options: UseQueryOptions<T, Error, T, readonly unknown[]>) {
  const qc = useQueryClient();
  const existing = qc.getQueryCache().find({ queryKey: options.queryKey, exact: true });
  return useQuery({ ...options, retryOnMount: !(existing && isCoolingOff(existing)) });
}

// ---- hooks -----------------------------------------------------------------

export function fetchHealth(): Promise<Health> {
  return api<Health>("/health");
}

export function useLanes() {
  return useRead({
    queryKey: qk.lanes(),
    queryFn: ({ signal }) => api<LanesOut>("/lanes", { signal }),
  });
}

export function useVelocity(days = 30) {
  return useRead({
    queryKey: qk.velocity(days),
    queryFn: ({ signal }) => api<VelocityOut>(`/velocity?days=${days}`, { signal }),
  });
}

export function useGeo(windowHours = 24) {
  return useRead({
    queryKey: qk.geo(windowHours),
    queryFn: ({ signal }) => api<GeoSummaryItem[]>(`/geo?window_hours=${windowHours}`, { signal }),
  });
}

export function useLoudStories(limit = 50) {
  return useRead({
    queryKey: qk.loud(limit),
    queryFn: ({ signal }) => api<LoudStory[]>(`/stories/loud?limit=${limit}`, { signal }),
  });
}

export function useCve(id: string | undefined) {
  return useRead({
    queryKey: qk.cve(id ?? ""),
    queryFn: ({ signal }) => api<CveDetail>(`/cves/${encodeURIComponent(id ?? "")}`, { signal }),
    enabled: !!id,
  });
}

export function cveSearchPath(params: CveQuery): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    sp.set(k, String(v));
  }
  const qs = sp.toString();
  return qs ? `/cves?${qs}` : "/cves";
}

export function useCveSearch(params: CveQuery) {
  return useRead({
    queryKey: qk.cves(params),
    queryFn: ({ signal }) => api<CveListOut>(cveSearchPath(params), { signal }),
    placeholderData: keepPreviousData,
  });
}
