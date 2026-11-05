import {
  QueryClient,
  keepPreviousData,
  useQuery,
  useQueryClient,
  type Query,
  type UseQueryOptions,
} from "@tanstack/react-query";
import { useSyncExternalStore } from "react";
import { ApiError, AuthError, RateLimited, api, authStore } from "./api";
import type { AuthSnapshot } from "./tokenStore";
import type {
  CountryActivity,
  CveDetail,
  CveListOut,
  CveQuery,
  GeoSummaryItem,
  Health,
  LanesOut,
  LoudStory,
  StoryDetailOut,
  StoryListOut,
  StoryQuery,
  VelocityOut,
} from "./types";

/** Query keys. Shared with the live-update invalidation map (live.ts) and later tasks. */
export const qk = {
  lanes: () => ["lanes"] as const,
  velocity: (days: number) => ["velocity", days] as const,
  geo: (windowHours: number) => ["geo", windowHours] as const,
  loud: (limit: number) => ["loud", limit] as const,
  cve: (id: string) => ["cve", id] as const,
  cves: (params: CveQuery) => ["cves", params] as const,
  stories: (params: StoryQuery) => ["stories", params] as const,
  story: (url: string) => ["story", url] as const,
  country: (cc: string, windowHours: number) => ["geo", "country", cc, windowHours] as const,
  health: () => ["health"] as const,
  sessions: () => ["sessions"] as const,
  /** status only (enabled, remaining count): never the secret or the recovery codes */
  mfa: () => ["mfa"] as const,
  alerts: () => ["alerts"] as const,
  rules: () => ["alerts", "rules"] as const,
  deliveries: (p: { status: string; rule: string; page: number }) => ["alerts", "deliveries", p] as const,
  users: () => ["users"] as const,
  invites: () => ["invites"] as const,
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

// ---- identity scoping --------------------------------------------------------

/** Who the cached data belongs to. A token rotation for the same user is not a change. */
export function identityKey(s: Pick<AuthSnapshot, "user" | "authenticated">): string {
  if (s.user) return `user:${s.user.id}`;
  return s.authenticated ? "pending" : "anon";
}

/** Everything except the server's public /health answer belongs to an identity. */
const identityScoped = (q: Query) => q.queryKey[0] !== qk.health()[0];

/**
 * Scope the whole query cache to the signed-in identity. Whenever it changes (login, logout,
 * a peer tab's logout or user switch, a failed refresh) every query but health is reset: cached
 * data disappears at once from any observer, and active queries refetch as the new identity.
 * "pending" (a token adopted, its user not yet loaded) to that user is not a change: the data
 * fetched in between already used the new token. Returns the unsubscribe function.
 */
export function bindQueryCacheToAuth(
  qc: QueryClient,
  store: { getSnapshot(): Pick<AuthSnapshot, "user" | "authenticated">; subscribe(fn: () => void): () => void },
): () => void {
  let prev = identityKey(store.getSnapshot());
  return store.subscribe(() => {
    const next = identityKey(store.getSnapshot());
    if (next === prev) return;
    const settling = prev === "pending" && next.startsWith("user:");
    prev = next;
    if (settling) return;
    void qc.resetQueries({ predicate: identityScoped });
  });
}

/** Data reads wait for the startup auth bootstrap, so nothing is fetched (and cached) as a guest first. */
function useAuthReady(): boolean {
  return useSyncExternalStore(authStore.subscribe, () => authStore.getSnapshot().ready);
}

// ---- error-state polling --------------------------------------------------------

/** After a final failure a dashboard read polls at this pace (ms): Retry-After for a 429, else 30 s; never under 15 s. */
export function errorRefetchMs(error: unknown): number {
  return Math.max((retryAfterOf(error) ?? 30) * 1000, 15_000);
}
/** refetchInterval for dashboard reads: only while the query is in its error state. */
export function errorRefetchInterval(query: Pick<Query, "state">): number | false {
  if (query.state.status !== "error") return false;
  return pollsAfterError(query.state.error) ? errorRefetchMs(query.state.error) : false;
}
/** A 401/403 is futile to poll: only an identity change fixes it, and that resets the cache. */
export function pollsAfterError(error: unknown): boolean {
  if (error instanceof AuthError) return false;
  return !(error instanceof ApiError && (error.status === 401 || error.status === 403));
}
/** When an errored query will next be refetched by errorRefetchInterval (epoch ms). */
export function nextRetryAt(query: { errorUpdatedAt: number; error: unknown }): number {
  return query.errorUpdatedAt + errorRefetchMs(query.error);
}

/**
 * useQuery plus the per-observer cooldown gate on retryOnMount (see shouldRetry), gated on the
 * auth bootstrap having settled (`ungated` only for /health, which the bootstrap does not need).
 */
function useRead<T>(options: UseQueryOptions<T, Error, T, readonly unknown[]>, ungated = false) {
  const qc = useQueryClient();
  const ready = useAuthReady();
  const existing = qc.getQueryCache().find({ queryKey: options.queryKey, exact: true });
  const enabled = (ungated || ready) && options.enabled !== false;
  return useQuery({ ...options, enabled, retryOnMount: !(existing && isCoolingOff(existing)) });
}

// ---- hooks -----------------------------------------------------------------

export function fetchHealth(): Promise<Health> {
  return api<Health>("/health");
}

export function useHealth() {
  return useRead(
    {
      queryKey: qk.health(),
      queryFn: () => fetchHealth(),
    },
    true,
  );
}

export function useLanes() {
  return useRead({
    queryKey: qk.lanes(),
    queryFn: ({ signal }) => api<LanesOut>("/lanes", { signal }),
    refetchInterval: errorRefetchInterval,
  });
}

export function useVelocity(days = 30) {
  return useRead({
    queryKey: qk.velocity(days),
    queryFn: ({ signal }) => api<VelocityOut>(`/velocity?days=${days}`, { signal }),
    refetchInterval: errorRefetchInterval,
  });
}

export function useGeo(windowHours = 24) {
  return useRead({
    queryKey: qk.geo(windowHours),
    queryFn: ({ signal }) => api<GeoSummaryItem[]>(`/geo?window_hours=${windowHours}`, { signal }),
    refetchInterval: errorRefetchInterval,
  });
}

export function useLoudStories(limit = 50) {
  return useRead({
    queryKey: qk.loud(limit),
    queryFn: ({ signal }) => api<LoudStory[]>(`/stories/loud?limit=${limit}`, { signal }),
    refetchInterval: errorRefetchInterval,
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

export function storySearchPath(params: StoryQuery): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    sp.set(k, String(v));
  }
  const qs = sp.toString();
  return qs ? `/stories?${qs}` : "/stories";
}

export function useStorySearch(params: StoryQuery) {
  return useRead({
    queryKey: qk.stories(params),
    queryFn: ({ signal }) => api<StoryListOut>(storySearchPath(params), { signal }),
    placeholderData: keepPreviousData,
  });
}

export function useStory(url: string | undefined) {
  return useRead({
    queryKey: qk.story(url ?? ""),
    queryFn: ({ signal }) => api<StoryDetailOut>(`/story?url=${encodeURIComponent(url ?? "")}`, { signal }),
    enabled: !!url,
  });
}

/** Disabled while `cc` is undefined. */
export function useCountry(cc: string | undefined, windowHours = 24) {
  return useRead({
    queryKey: qk.country(cc ?? "", windowHours),
    queryFn: ({ signal }) =>
      api<CountryActivity>(`/geo/${encodeURIComponent(cc ?? "")}?window_hours=${windowHours}`, { signal }),
    enabled: !!cc,
  });
}
