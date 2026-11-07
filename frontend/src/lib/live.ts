import { useQueryClient, type QueryClient } from "@tanstack/react-query";
import { useEffect, useSyncExternalStore } from "react";
import { AuthError, RateLimited, getApiClient } from "./api";
import { getAuth } from "./auth";
import { fetchHealth, isCoolingOff, qk } from "./queries";
import type { Health } from "./types";

export type LiveStatus = "live" | "reconnecting" | "offline";
export interface LiveState {
  status: LiveStatus;
  /** Date.now() of the last `updated` message, or null. */
  lastUpdated: number | null;
}

/** The slice of the WebSocket API the controller uses (a mock implements the same). */
export interface SocketLike {
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose: ((ev: { code: number }) => void) | null;
  onerror: ((ev: unknown) => void) | null;
  send(data: string): void;
  close(code?: number): void;
}

export interface LiveDeps {
  wsFactory?: (url: string) => SocketLike;
  /** Auth store seam: token for the first message, subscribe for login/logout events. */
  auth?: { getToken(): string | null; subscribe(fn: () => void): () => void };
  /**
   * Single-flight token refresh (rejects if the session is gone). `stale` is the token the
   * socket authenticated with, so a newer stored token is reused instead of rotating again.
   */
  refresh?: (stale: string | null) => Promise<unknown>;
  /** `fresh` forces a network fetch instead of the cached value. */
  getHealth?: (qc: QueryClient, fresh?: boolean) => Promise<Health>;
  random?: () => number;
  now?: () => number;
  url?: string;
}

export const DEBOUNCE_MS = 500;
export const BACKOFF_BASE_MS = 1000;
export const BACKOFF_CAP_MS = 60_000;
export const STABLE_MS = 60_000;
export const THROTTLE_MIN_MS = 60_000;
export const THROTTLE_JITTER_MS = 15_000;
/** A socket live for at least this long counts as healthy (ends a 4401 streak). */
export const HEALTHY_MS = 10_000;

/** Server `what` value -> query-key roots to invalidate. Unknown values are ignored. */
const INVALIDATES = new Map<string, readonly string[]>(
  Object.entries({
    lanes: ["lanes", "summary", "volume", "cve", "cves"],
    stories: ["loud", "stories", "story", "lanes"],
    geo: ["geo"],
  }),
);

export function liveUrl(loc: Pick<Location, "protocol" | "host"> = location): string {
  return `${loc.protocol === "https:" ? "wss:" : "ws:"}//${loc.host}/api/ws/live`;
}

export interface LiveController {
  start(): void;
  stop(): void;
  getState(): LiveState;
  subscribe(fn: () => void): () => void;
}

export function createLiveController(qc: QueryClient, deps: LiveDeps = {}): LiveController {
  const wsFactory = deps.wsFactory ?? ((u: string) => new WebSocket(u) as unknown as SocketLike);
  const auth = deps.auth ?? getAuth();
  const refresh = deps.refresh ?? ((stale: string | null) => getApiClient().refresh(stale));
  const getHealth =
    deps.getHealth ??
    ((c: QueryClient, fresh?: boolean) =>
      c.fetchQuery({ queryKey: qk.health(), queryFn: fetchHealth, staleTime: fresh ? 0 : Infinity }));
  const random = deps.random ?? Math.random;
  const now = deps.now ?? Date.now;

  let state: LiveState = { status: "reconnecting", lastUpdated: null };
  const listeners = new Set<() => void>();
  const setState = (patch: Partial<LiveState>) => {
    const next = { ...state, ...patch };
    if (next.status === state.status && next.lastUpdated === state.lastUpdated) return;
    state = next;
    for (const fn of [...listeners]) fn();
  };

  let started = false;
  let stopped = false;
  let socket: SocketLike | null = null;
  let connecting = false;
  let gen = 0; // bumped by every connect() and dropSocket(): stale async work bails out
  let attempt = 0;
  let hasOpened = false;
  let openedAt: number | null = null;
  let consecutive4401 = 0;
  let freshHealth = false;
  let publicRead = false;
  let wasAuthed = false;
  /** The token the current/last socket authenticated with (null: anonymous). */
  let socketToken: string | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  let stableTimer: ReturnType<typeof setTimeout> | undefined;
  let debounceTimer: ReturnType<typeof setTimeout> | undefined;
  let unsubAuth: (() => void) | undefined;
  const pending = new Set<string>();

  // ---- invalidation (debounced, merged) ---------------------------------

  function flush() {
    debounceTimer = undefined;
    const roots = [...pending];
    pending.clear();
    for (const root of roots) {
      // A 429'd query stays untouched until its Retry-After has elapsed.
      void qc.invalidateQueries({ queryKey: [root], predicate: (q) => !isCoolingOff(q, now()) });
    }
  }
  function queueInvalidation(what: readonly string[]) {
    for (const w of what) for (const root of INVALIDATES.get(w) ?? []) pending.add(root);
    if (pending.size > 0 && debounceTimer === undefined) debounceTimer = setTimeout(flush, DEBOUNCE_MS);
  }

  // ---- socket lifecycle -------------------------------------------------

  function clearReconnect() {
    clearTimeout(reconnectTimer);
    reconnectTimer = undefined;
  }

  /** Detach and close the current socket without triggering reconnect logic. */
  function dropSocket(code = 1000) {
    gen++;
    clearTimeout(stableTimer);
    stableTimer = undefined;
    const s = socket;
    socket = null;
    connecting = false;
    if (s) {
      s.onopen = s.onmessage = s.onclose = s.onerror = null;
      try {
        s.close(code);
      } catch {
        // already closed
      }
    }
  }

  function scheduleReconnect(delayMs: number) {
    if (stopped) return;
    clearReconnect();
    setState({ status: "reconnecting" });
    reconnectTimer = setTimeout(() => {
      reconnectTimer = undefined;
      void connect();
    }, delayMs);
  }
  /** Seconds a 429 asked us to wait, as ms; 0 for any other error. */
  const minDelayOf = (e: unknown) => (e instanceof RateLimited ? e.retryAfter * 1000 : 0);
  function scheduleBackoff(minMs = 0) {
    const delay = Math.max(minMs, random() * Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2 ** attempt));
    attempt++;
    scheduleReconnect(delay);
  }

  async function connect() {
    if (stopped) return;
    clearReconnect();
    dropSocket();
    const myGen = gen;
    connecting = true;
    setState({ status: "reconnecting" });

    let health: Health;
    const fresh = freshHealth;
    freshHealth = false;
    try {
      health = await getHealth(qc, fresh);
    } catch (e) {
      if (stopped || myGen !== gen) return;
      connecting = false;
      if (fresh) freshHealth = true; // still owed
      scheduleBackoff(minDelayOf(e)); // honours Retry-After on a 429
      return;
    }
    if (stopped || myGen !== gen) return;
    publicRead = health.public_read === true;

    if (!publicRead && !auth.getToken()) {
      connecting = false;
      setState({ status: "offline" }); // waits for a login event
      return;
    }

    let ws: SocketLike;
    try {
      ws = wsFactory(deps.url ?? liveUrl());
    } catch {
      connecting = false;
      scheduleBackoff();
      return;
    }
    socket = ws;
    connecting = false;

    ws.onopen = () => {
      if (ws !== socket) return;
      const token = auth.getToken();
      socketToken = token;
      if (token) ws.send(JSON.stringify({ type: "auth", token }));
      else if (!publicRead) {
        // The token vanished between connect and open: stand down directly (no backoff).
        dropSocket(1000);
        setState({ status: "offline" });
        return;
      }
      openedAt = now();
      setState({ status: "live" });
      // Anything pushed while we were away was missed: refresh everything once. Kept on the
      // routine 4401 reconnect too (token expiry): that gap can drop an `updated` push like any
      // other, and the cost is one debounced refetch of the observed, non-cooling queries.
      if (hasOpened) queueInvalidation([...INVALIDATES.keys()]);
      hasOpened = true;
      clearTimeout(stableTimer);
      stableTimer = setTimeout(() => {
        attempt = 0;
      }, STABLE_MS);
    };
    ws.onmessage = (ev) => {
      if (ws !== socket || typeof ev.data !== "string") return;
      let msg: unknown;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      if (typeof msg !== "object" || msg === null) return;
      const m = msg as { type?: unknown; what?: unknown };
      if (m.type !== "updated") return; // ping and anything else: ignore
      const known = Array.isArray(m.what)
        ? m.what.filter((w): w is string => typeof w === "string" && INVALIDATES.has(w))
        : [];
      if (known.length === 0) return; // nothing we recognise: not an update for us
      setState({ lastUpdated: now() });
      queueInvalidation(known);
    };
    ws.onerror = () => {
      // a close event always follows; reconnect is handled there
    };
    ws.onclose = (ev) => {
      if (ws !== socket) return;
      socket = null;
      clearTimeout(stableTimer);
      stableTimer = undefined;
      if (stopped) return;
      const code = typeof ev?.code === "number" ? ev.code : 1006;
      const healthy = openedAt !== null && now() - openedAt >= HEALTHY_MS;
      openedAt = null;
      if (healthy) consecutive4401 = 0;
      if (code === 4401) {
        freshHealth = true; // public_read may have flipped
        // The server also sends 4401 on internal auth/DB errors. Only the first 4401 of a
        // streak refreshes and reconnects at once; the rest back off without refreshing
        // (each refresh rotates the cookie) until a socket has stayed live for HEALTHY_MS.
        if (consecutive4401 === 0) {
          consecutive4401 = 1;
          void recoverFrom4401();
        } else scheduleBackoff();
      }
      // Browsers report a rejected handshake (e.g. 4403 Origin) as 1006 and never expose the
      // code, so 4403 normally arrives here as a plain failure and follows normal backoff.
      else if (code === 4429 || code === 4403) scheduleReconnect(THROTTLE_MIN_MS + random() * THROTTLE_JITTER_MS);
      else scheduleBackoff();
    };
  }

  async function recoverFrom4401() {
    const myGen = gen;
    setState({ status: "reconnecting" });
    try {
      // Exactly one attempt per 4401. Usually the socket's token simply expired after a proactive
      // refresh already stored a newer one: naming it as stale reuses that token, no rotation.
      await refresh(socketToken);
    } catch (e) {
      if (stopped || myGen !== gen || socket || connecting || reconnectTimer !== undefined) return;
      if (!(e instanceof AuthError)) {
        // Transient (network, 5xx, 429): the session is intact, so retry with backoff.
        scheduleBackoff(minDelayOf(e));
        return;
      }
      // The session is gone. Public servers still serve anonymous clients.
      if (publicRead) void connect();
      else setState({ status: "offline" });
      return;
    }
    if (stopped || myGen !== gen || socket || connecting) return;
    void connect();
  }

  // ---- auth events --------------------------------------------------------

  function onAuthChange() {
    if (stopped) return;
    const authed = auth.getToken() !== null;
    if (authed === wasAuthed) return; // token rotation: nothing to do
    wasAuthed = authed;
    if (authed) {
      if (socket && state.status === "live") {
        // anonymous socket on a public server: identify (harmless, keeps behaviour uniform)
        const token = auth.getToken();
        if (token) {
          socketToken = token;
          socket.send(JSON.stringify({ type: "auth", token }));
        }
      } else {
        attempt = 0;
        void connect();
      }
    } else {
      dropSocket(1000);
      clearReconnect();
      if (publicRead) void connect();
      else setState({ status: "offline" });
    }
  }

  return {
    start() {
      if (started) return;
      started = true;
      wasAuthed = auth.getToken() !== null;
      unsubAuth = auth.subscribe(onAuthChange);
      void connect();
    },
    stop() {
      if (stopped) return;
      stopped = true;
      unsubAuth?.();
      clearReconnect();
      clearTimeout(debounceTimer);
      debounceTimer = undefined;
      pending.clear();
      dropSocket(1000);
      setState({ status: "offline" });
    },
    getState: () => state,
    subscribe(fn) {
      listeners.add(fn);
      return () => {
        listeners.delete(fn);
      };
    },
  };
}

// ---- shared controller (one socket per QueryClient, ref-counted) -------------

interface Hub {
  refs: number;
  ctl: LiveController | null;
  unsub: (() => void) | null;
  state: LiveState;
  listeners: Set<() => void>;
  subscribe(fn: () => void): () => void;
  getSnapshot(): LiveState;
}
const hubs = new WeakMap<QueryClient, Hub>();

function hubFor(qc: QueryClient): Hub {
  let hub = hubs.get(qc);
  if (!hub) {
    const h: Hub = {
      refs: 0,
      ctl: null,
      unsub: null,
      state: { status: "reconnecting", lastUpdated: null },
      listeners: new Set(),
      subscribe(fn) {
        h.listeners.add(fn);
        return () => {
          h.listeners.delete(fn);
        };
      },
      getSnapshot: () => h.state,
    };
    hubs.set(qc, h);
    hub = h;
  }
  return hub;
}

function acquire(qc: QueryClient, deps?: LiveDeps): () => void {
  const hub = hubFor(qc);
  const emit = (s: LiveState) => {
    hub.state = s;
    for (const fn of [...hub.listeners]) fn();
  };
  if (hub.refs++ === 0) {
    const ctl = createLiveController(qc, deps);
    hub.ctl = ctl;
    hub.unsub = ctl.subscribe(() => emit(ctl.getState()));
    hub.state = ctl.getState();
    ctl.start();
  }
  let released = false;
  return () => {
    if (released) return;
    released = true;
    if (--hub.refs === 0) {
      hub.unsub?.();
      hub.ctl?.stop();
      hub.ctl = hub.unsub = null;
      emit({ status: "offline", lastUpdated: null });
    }
  };
}

/**
 * Safe to call from any number of components under one QueryClientProvider: they share a
 * single ref-counted controller, hence one socket. The first caller's `deps` win. Connecting
 * waits on the /health fetch, so StrictMode's mount/unmount/mount stops the first controller
 * before it ever opens a socket.
 */
export function useLiveUpdates(deps?: LiveDeps): LiveState {
  const qc = useQueryClient();
  const hub = hubFor(qc);
  useEffect(() => acquire(qc, deps), [qc, deps]);
  return useSyncExternalStore(hub.subscribe, hub.getSnapshot);
}
