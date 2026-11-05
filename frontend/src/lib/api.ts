import { createTokenStore, type TokenStore } from "./tokenStore";
import type { Me, TokenResponse } from "./types";

// ---- errors ---------------------------------------------------------------

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  /** parsed JSON body when there was one (e.g. a 422's `detail`) */
  readonly body: unknown;
  constructor(status: number, code: string, body?: unknown) {
    super(`${status} ${code}`);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.body = body;
  }
}
export class RateLimited extends ApiError {
  /** seconds, from the Retry-After header */
  readonly retryAfter: number;
  constructor(retryAfter: number, body?: unknown) {
    super(429, "rate_limited", body);
    this.name = "RateLimited";
    this.retryAfter = retryAfter;
  }
}
export class NetworkError extends Error {
  constructor() {
    super("network_error");
    this.name = "NetworkError";
  }
}
/** The session could not be refreshed: the user must log in again. */
export class AuthError extends Error {
  constructor() {
    super("auth_required");
    this.name = "AuthError";
  }
}

// ---- cross-tab coordination seams (real: navigator.locks, BroadcastChannel) ----

export interface LocksLike {
  request<T>(name: string, cb: () => Promise<T>): Promise<T>;
}
export interface ChannelLike {
  postMessage(message: unknown): void;
  onmessage: ((e: { data: unknown }) => void) | null;
  close(): void;
}

export type ApiInit = Omit<RequestInit, "body" | "credentials"> & { body?: unknown };

export interface ApiClientOptions {
  store: TokenStore;
  fetchFn?: typeof fetch;
  /** undefined: use navigator.locks when present; null: none (no proactive refresh then) */
  locks?: LocksLike | null;
  /** undefined: a BroadcastChannel("cvenom-auth") when available; null: none. Events only, never locking. */
  channel?: ChannelLike | null;
  /** random source for the proactive-refresh jitter (tests) */
  random?: () => number;
  base?: string;
}

export interface ApiClient {
  api<T = unknown>(path: string, init?: ApiInit): Promise<T>;
  /** Hold a token in memory and schedule its proactive refresh. */
  adopt(token: string, expiresIn: number): void;
  /** Single-flight refresh (within and across tabs). Throws AuthError if the session is gone. */
  refresh(): Promise<string>;
  /** Tell other tabs about a login/logout (events only). */
  announce(message: Record<string, unknown>): void;
  clear(): void;
  dispose(): void;
}

const LOCK_NAME = "cvenom-refresh";
const CHANNEL_NAME = "cvenom-auth";
const MAX_TIMEOUT_MS = 2 ** 31 - 1;
const PEER_TOKEN_WINDOW_MS = 15_000;
/** 401 on these never triggers refresh or logout: the error belongs to the form. */
const REFRESH_EXEMPT = new Set(["/auth/login", "/auth/password", "/auth/refresh", "/auth/invites/accept"]);

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

/** Unverified read of the access token's `sub` claim, for UI identity only. */
export function subOf(token: string): string | null {
  try {
    const part = token.split(".")[1];
    if (!part) return null;
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const json: unknown = JSON.parse(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)));
    return isRecord(json) && json.sub !== undefined ? String(json.sub) : null;
  } catch {
    return null;
  }
}

interface PeerToken {
  token: string;
  expiresIn: number;
  sub: string | null;
  at: number;
}

export function createApiClient(opts: ApiClientOptions): ApiClient {
  const { store } = opts;
  const base = opts.base ?? "/api";
  const random = opts.random ?? Math.random;
  const doFetch: typeof fetch = opts.fetchFn ?? ((u, i) => globalThis.fetch(u, i));

  const locks: LocksLike | null =
    opts.locks !== undefined
      ? opts.locks
      : typeof navigator !== "undefined" && navigator.locks
        ? (navigator.locks as unknown as LocksLike)
        : null;
  const channel: ChannelLike | null =
    opts.channel !== undefined
      ? opts.channel
      : typeof BroadcastChannel !== "undefined"
        ? (new BroadcastChannel(CHANNEL_NAME) as unknown as ChannelLike)
        : null;

  let timer: ReturnType<typeof setTimeout> | undefined;
  let inflight: Promise<string> | null = null;
  let lastPeer: PeerToken | null = null;
  /** Bumped by every clear() (logout, failed refresh, peer logout). In-flight work that began
   *  under an older epoch must not apply its result. */
  let epoch = 0;
  let inflightEpoch = 0;

  // ---- token + proactive refresh ------------------------------------------

  /**
   * Proactive refresh only exists with Web Locks (cross-tab mutual exclusion). Without it
   * every tab's timer would fire together and two tabs would present the same refresh
   * cookie, so refreshes are reactive (on 401) and naturally staggered. Jitter spreads
   * tabs further: the timer fires 60 to 80 s before expiry.
   */
  function schedule(expiresIn: number) {
    clearTimeout(timer);
    timer = undefined;
    if (!locks || !Number.isFinite(expiresIn) || expiresIn <= 0) return;
    const sec = expiresIn > 120 ? expiresIn - 60 - random() * 20 : expiresIn / 2;
    const ms = Math.min(MAX_TIMEOUT_MS, Math.max(1000, sec * 1000));
    timer = setTimeout(() => {
      const t = store.getToken();
      if (t) refreshShared(t).catch(() => undefined);
    }, ms);
  }

  function adopt(token: string, expiresIn: number) {
    store.setToken(token);
    schedule(expiresIn);
  }

  function clear() {
    clearTimeout(timer);
    timer = undefined;
    epoch++;
    lastPeer = null;
    store.clear();
  }

  /** Reload the signed-in identity from the server (fire and forget). */
  function loadMe() {
    const startEpoch = epoch;
    const startSub = subOf(store.getToken() ?? "");
    api<Me>("/auth/me").then(
      (me) => {
        // Drop a result that began before a logout or a switch to another user.
        const t = store.getToken();
        if (epoch !== startEpoch || !t || subOf(t) !== startSub) return;
        store.setUser(me);
      },
      () => undefined,
    );
  }

  /** After adopting a token for user `sub`: reload /me if it is not the user we show. */
  function syncIdentity(sub: string | null) {
    const u = store.getUser();
    if (!u || (sub !== null && String(u.id) !== sub)) loadMe();
  }

  // ---- channel events ------------------------------------------------------

  if (channel) {
    channel.onmessage = (e) => {
      const m = e.data;
      if (!isRecord(m)) return;
      const sub = typeof m.sub === "string" ? m.sub : null;
      if (m.type === "refreshed" || m.type === "login") {
        const { access_token, expires_in } = m;
        if (typeof access_token !== "string" || access_token === "") return;
        if (typeof expires_in !== "number" || !Number.isFinite(expires_in)) return;
        if (m.type === "refreshed") {
          // A guest tab must not be signed in by a peer's refresh (nor undo a logout).
          if (!store.getToken() && !(inflight && inflightEpoch === epoch)) return;
          lastPeer = { token: access_token, expiresIn: expires_in, sub, at: Date.now() };
          adopt(access_token, expires_in);
          syncIdentity(sub);
        } else {
          const u = store.getUser();
          if (sub === null || (u && String(u.id) === sub)) return;
          adopt(access_token, expires_in);
          loadMe();
        }
      } else if (m.type === "logout") {
        const u = store.getUser();
        if (u && sub !== null && String(u.id) !== sub) return; // a different user's logout
        clear();
      }
    };
  }

  // ---- low-level request ---------------------------------------------------

  async function send(path: string, init: ApiInit): Promise<{ res: Response; sentToken: string | null }> {
    const { body, headers: h, ...rest } = init;
    const headers = new Headers(h);
    if (!headers.has("Accept")) headers.set("Accept", "application/json");
    const sentToken = store.getToken();
    if (sentToken) headers.set("Authorization", `Bearer ${sentToken}`);
    let payload: BodyInit | undefined;
    if (body !== undefined) {
      payload = typeof body === "string" ? body : JSON.stringify(body);
      if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    }
    try {
      const res = await doFetch(base + path, { ...rest, headers, body: payload, credentials: "same-origin" });
      return { res, sentToken };
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") throw e;
      throw new NetworkError();
    }
  }

  async function readBody(res: Response): Promise<unknown> {
    try {
      const text = await res.text();
      return text === "" ? undefined : JSON.parse(text);
    } catch {
      return undefined;
    }
  }

  async function toError(res: Response): Promise<ApiError> {
    const body = await readBody(res);
    if (res.status === 429) {
      const n = Number.parseInt(res.headers.get("Retry-After") ?? "", 10);
      return new RateLimited(Number.isFinite(n) && n >= 0 ? n : 60, body);
    }
    const code = isRecord(body) && typeof body.error === "string" ? body.error : `http_${res.status}`;
    return new ApiError(res.status, code, body);
  }

  async function finish<T>(res: Response): Promise<T> {
    if (!res.ok) throw await toError(res);
    if (res.status === 204) return undefined as T;
    return (await readBody(res)) as T;
  }

  // ---- refresh (single flight in tab; Web Locks across tabs) ------------------

  async function doRefresh(): Promise<string> {
    const startEpoch = epoch;
    let res: Response;
    try {
      res = await doFetch(`${base}/auth/refresh`, {
        method: "POST",
        headers: { "X-CVEnom-CSRF": "1", Accept: "application/json" },
        credentials: "same-origin",
      });
    } catch {
      throw new NetworkError();
    }
    if (res.ok) {
      const body = await readBody(res);
      if (epoch !== startEpoch) throw new AuthError(); // logged out meanwhile: discard
      const b = body as Partial<TokenResponse> | undefined;
      if (!b || typeof b.access_token !== "string" || typeof b.expires_in !== "number") {
        throw new ApiError(res.status, "bad_refresh_response");
      }
      adopt(b.access_token, b.expires_in);
      const sub = subOf(b.access_token);
      // Tell every other tab so none of them presents the same refresh cookie again.
      channel?.postMessage({ type: "refreshed", access_token: b.access_token, expires_in: b.expires_in, sub });
      // The shared cookie may now belong to another user than the one this tab shows.
      const u = store.getUser();
      if (u && sub !== null && String(u.id) !== sub) loadMe();
      return b.access_token;
    }
    if (res.status === 401 || res.status === 403) {
      // A peer tab may have rotated the cookie a moment ago (the backend's grace window
      // rejects us): use the token it broadcast rather than logging everyone out.
      if (epoch !== startEpoch) throw new AuthError(); // already logged out: never clear newer state
      const p = lastPeer;
      const u = store.getUser();
      if (p && Date.now() - p.at < PEER_TOKEN_WINDOW_MS && (!u || p.sub === null || String(u.id) === p.sub)) {
        adopt(p.token, p.expiresIn);
        return p.token;
      }
      clear();
      throw new AuthError();
    }
    throw await toError(res);
  }

  /** Runs inside the lock: skip the refresh if another tab already delivered a newer token. */
  async function refreshGuarded(stale: string | null): Promise<string> {
    const cur = store.getToken();
    if (cur && cur !== stale) return cur;
    return doRefresh();
  }

  function refreshShared(stale: string | null): Promise<string> {
    const cur = store.getToken();
    if (cur && cur !== stale) return Promise.resolve(cur); // already replaced
    if (inflight) return inflight;
    const p = (async () => {
      try {
        return locks ? await locks.request(LOCK_NAME, () => refreshGuarded(stale)) : await refreshGuarded(stale);
      } finally {
        inflight = null;
      }
    })();
    inflight = p;
    inflightEpoch = epoch;
    return p;
  }

  async function api<T = unknown>(path: string, init: ApiInit = {}): Promise<T> {
    const first = await send(path, init);
    // Guests (no token sent) never burn /refresh; bootstrap() handles the cookie-only case.
    if (first.res.status !== 401 || first.sentToken === null || REFRESH_EXEMPT.has(path.split("?")[0])) {
      return finish<T>(first.res);
    }
    await refreshShared(first.sentToken); // AuthError propagates (store already cleared)
    const second = await send(path, init);
    return finish<T>(second.res);
  }

  return {
    api,
    adopt,
    refresh: () => refreshShared(store.getToken()),
    announce: (message) => channel?.postMessage(message),
    clear,
    dispose() {
      clearTimeout(timer);
      if (channel) {
        channel.onmessage = null;
        channel.close();
      }
    },
  };
}

// ---- default app-wide instance (lazy so importing the types opens no channel) ----

export const authStore: TokenStore = createTokenStore();
let shared: ApiClient | null = null;
export function getApiClient(): ApiClient {
  return (shared ??= createApiClient({ store: authStore }));
}
export function api<T = unknown>(path: string, init?: ApiInit): Promise<T> {
  return getApiClient().api<T>(path, init);
}
