import { createTokenStore, type TokenStore } from "./tokenStore";
import type { TokenResponse } from "./types";

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
  /** undefined: use navigator.locks when present; null: none */
  locks?: LocksLike | null;
  /** undefined: a BroadcastChannel("cvenom-auth") when available; null: none */
  channel?: ChannelLike | null;
  /** how long to wait for a peer tab's refresh (fallback mode only) */
  peerWaitMs?: number;
  base?: string;
}

export interface ApiClient {
  api<T = unknown>(path: string, init?: ApiInit): Promise<T>;
  /** Hold a token in memory and schedule its proactive refresh. */
  adopt(token: string, expiresIn: number): void;
  /** Single-flight refresh (within and across tabs). Throws AuthError if the session is gone. */
  refresh(): Promise<string>;
  clear(): void;
  dispose(): void;
}

const LOCK_NAME = "cvenom-refresh";
const CHANNEL_NAME = "cvenom-auth";
/** 401 on these never triggers refresh or logout: the error belongs to the form. */
const REFRESH_EXEMPT = new Set(["/auth/login", "/auth/password", "/auth/refresh", "/auth/invites/accept"]);

type PeerResult = { token: string } | { authFailed: true } | null;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

export function createApiClient(opts: ApiClientOptions): ApiClient {
  const { store } = opts;
  const base = opts.base ?? "/api";
  const peerWaitMs = opts.peerWaitMs ?? 5000;
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
  let peerSince = 0; // when a peer last announced "refreshing" (0: none)
  const waiters = new Set<(r: PeerResult) => void>();

  // ---- token + proactive refresh ------------------------------------------

  function schedule(expiresIn: number) {
    clearTimeout(timer);
    if (!Number.isFinite(expiresIn) || expiresIn <= 0) return;
    const sec = expiresIn > 120 ? expiresIn - 60 : expiresIn / 2;
    timer = setTimeout(() => {
      const t = store.getToken();
      if (t) refreshShared(t).catch(() => undefined);
    }, sec * 1000);
  }

  function adopt(token: string, expiresIn: number) {
    store.setToken(token);
    schedule(expiresIn);
  }

  function clear() {
    clearTimeout(timer);
    store.clear();
  }

  // ---- channel -------------------------------------------------------------

  if (channel) {
    channel.onmessage = (e) => {
      const m = e.data;
      if (!isRecord(m)) return;
      if (m.type === "refreshed") {
        const { access_token, expires_in } = m;
        if (typeof access_token !== "string" || access_token === "") return;
        if (typeof expires_in !== "number" || !Number.isFinite(expires_in)) return;
        adopt(access_token, expires_in);
        peerSince = 0;
        for (const w of [...waiters]) w({ token: access_token });
      } else if (m.type === "refreshing") {
        peerSince = Date.now();
      } else if (m.type === "refresh_failed") {
        peerSince = 0;
        for (const w of [...waiters]) w(m.reason === "auth" ? { authFailed: true } : null);
      }
    };
  }

  const peerActive = () => peerSince !== 0 && Date.now() - peerSince < peerWaitMs;

  function waitForPeer(): Promise<PeerResult> {
    return new Promise((resolve) => {
      const done = (r: PeerResult) => {
        clearTimeout(t);
        waiters.delete(done);
        resolve(r);
      };
      const t = setTimeout(() => done(null), peerWaitMs);
      waiters.add(done);
    });
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

  // ---- refresh (single flight: in tab, across tabs) ---------------------------

  async function doRefresh(): Promise<string> {
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
      const b = body as Partial<TokenResponse> | undefined;
      if (!b || typeof b.access_token !== "string" || typeof b.expires_in !== "number") {
        throw new ApiError(res.status, "bad_refresh_response");
      }
      adopt(b.access_token, b.expires_in);
      // Tell every other tab so none of them presents the same refresh cookie again.
      channel?.postMessage({ type: "refreshed", access_token: b.access_token, expires_in: b.expires_in });
      return b.access_token;
    }
    if (res.status === 401 || res.status === 403) {
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

  async function refreshViaChannel(stale: string | null): Promise<string> {
    if (channel && peerActive()) {
      const r = await waitForPeer();
      if (r && "token" in r) return r.token;
      if (r && "authFailed" in r) {
        clear();
        throw new AuthError();
      }
    }
    const cur = store.getToken();
    if (cur && cur !== stale) return cur;
    channel?.postMessage({ type: "refreshing" });
    try {
      return await doRefresh();
    } catch (e) {
      channel?.postMessage({ type: "refresh_failed", reason: e instanceof AuthError ? "auth" : "other" });
      throw e;
    }
  }

  function refreshShared(stale: string | null): Promise<string> {
    const cur = store.getToken();
    if (cur && cur !== stale) return Promise.resolve(cur); // already replaced
    if (inflight) return inflight;
    const p = (async () => {
      try {
        return locks
          ? await locks.request(LOCK_NAME, () => refreshGuarded(stale))
          : await refreshViaChannel(stale);
      } finally {
        inflight = null;
      }
    })();
    inflight = p;
    return p;
  }

  async function api<T = unknown>(path: string, init: ApiInit = {}): Promise<T> {
    const first = await send(path, init);
    if (first.res.status !== 401 || REFRESH_EXEMPT.has(path.split("?")[0])) return finish<T>(first.res);
    await refreshShared(first.sentToken); // AuthError propagates (store already cleared)
    const second = await send(path, init);
    return finish<T>(second.res);
  }

  return {
    api,
    adopt,
    refresh: () => refreshShared(store.getToken()),
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
