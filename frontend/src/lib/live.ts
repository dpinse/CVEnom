import { useQueryClient, type QueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { getApiClient } from "./api";
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
  /** Single-flight token refresh (rejects if the session is gone). */
  refresh?: () => Promise<unknown>;
  getHealth?: (qc: QueryClient) => Promise<Health>;
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

/** Server `what` value -> query-key roots to invalidate. Unknown values are ignored. */
const INVALIDATES = new Map<string, readonly string[]>(Object.entries({
  lanes: ["lanes", "velocity", "cve", "cves"],
  stories: ["loud"],
  geo: ["geo"],
}));

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
  const refresh = deps.refresh ?? (() => getApiClient().refresh());
  const getHealth =
    deps.getHealth ??
    ((c: QueryClient) => c.fetchQuery({ queryKey: qk.health(), queryFn: fetchHealth, staleTime: Infinity }));
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
  let publicRead = false;
  let wasAuthed = false;
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
  function scheduleBackoff() {
    const delay = random() * Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2 ** attempt);
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
    try {
      health = await getHealth(qc);
    } catch {
      if (stopped || myGen !== gen) return;
      connecting = false;
      scheduleBackoff();
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
      if (token) ws.send(JSON.stringify({ type: "auth", token }));
      else if (!publicRead) {
        ws.close(1000);
        return;
      }
      setState({ status: "live" });
      // Anything pushed while we were away was missed: refresh everything once.
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
      setState({ lastUpdated: now() });
      if (Array.isArray(m.what)) queueInvalidation(m.what.filter((w): w is string => typeof w === "string"));
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
      if (code === 4401) void recoverFrom4401();
      else if (code === 4429 || code === 4403) scheduleReconnect(THROTTLE_MIN_MS + random() * THROTTLE_JITTER_MS);
      else scheduleBackoff();
    };
  }

  async function recoverFrom4401() {
    const myGen = gen;
    setState({ status: "reconnecting" });
    try {
      await refresh(); // exactly one attempt per 4401
    } catch {
      if (stopped || myGen !== gen || socket || connecting || reconnectTimer !== undefined) return;
      // The failed refresh cleared the session. Public servers still serve anonymous clients.
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
        if (token) socket.send(JSON.stringify({ type: "auth", token }));
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

/**
 * Mount ONCE at the app root (inside QueryClientProvider). Each effect run owns its own
 * controller; connecting waits on the /health fetch, so StrictMode's mount/unmount/mount
 * stops the first controller before it ever opens a socket.
 */
export function useLiveUpdates(deps?: LiveDeps): LiveState {
  const qc = useQueryClient();
  const [state, setState] = useState<LiveState>({ status: "reconnecting", lastUpdated: null });
  const [stableDeps] = useState(deps);
  useEffect(() => {
    const ctl = createLiveController(qc, stableDeps);
    const unsub = ctl.subscribe(() => setState(ctl.getState()));
    ctl.start();
    return () => {
      unsub();
      ctl.stop();
    };
  }, [qc, stableDeps]);
  return state;
}
