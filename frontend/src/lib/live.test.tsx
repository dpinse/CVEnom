import { QueryClientProvider, QueryObserver, type QueryClient } from "@tanstack/react-query";
import { act, render } from "@testing-library/react";
import { StrictMode } from "react";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { AuthError, RateLimited } from "./api";
import {
  createLiveController,
  liveUrl,
  useLiveUpdates,
  type LiveController,
  type LiveDeps,
  type LiveState,
  type SocketLike,
} from "./live";
import { createQueryClient, qk } from "./queries";

class MockWS implements SocketLike {
  static instances: MockWS[] = [];
  onopen: SocketLike["onopen"] = null;
  onmessage: SocketLike["onmessage"] = null;
  onclose: SocketLike["onclose"] = null;
  onerror: SocketLike["onerror"] = null;
  sent: string[] = [];
  closeCode: number | undefined;
  constructor(public url: string) {
    MockWS.instances.push(this);
  }
  send(d: string) {
    this.sent.push(d);
  }
  close(code?: number) {
    this.closeCode = code;
  }
  open() {
    this.onopen?.({});
  }
  msg(m: unknown) {
    this.onmessage?.({ data: typeof m === "string" ? m : JSON.stringify(m) });
  }
  drop(code: number) {
    this.onclose?.({ code });
  }
}
const last = () => MockWS.instances[MockWS.instances.length - 1];

function makeAuth(initial: string | null) {
  let token = initial;
  const subs = new Set<() => void>();
  return {
    getToken: () => token,
    subscribe(fn: () => void) {
      subs.add(fn);
      return () => subs.delete(fn);
    },
    set(t: string | null) {
      token = t;
      for (const f of [...subs]) f();
    },
  };
}

interface Rig {
  qc: QueryClient;
  auth: ReturnType<typeof makeAuth>;
  refresh: ReturnType<typeof vi.fn>;
  ctl: LiveController;
  deps: LiveDeps;
  counts: Record<string, number>;
  rnd: { v: number };
}

const flush = () => vi.advanceTimersByTimeAsync(0);

function setup(o: { publicRead?: boolean; token?: string | null; refresh?: () => Promise<unknown> } = {}): Rig {
  const qc = createQueryClient();
  const auth = makeAuth(o.token === undefined ? "tok-1" : o.token);
  const refresh = vi.fn(o.refresh ?? (() => Promise.resolve("tok-2")));
  const rnd = { v: 0.999 };
  const deps: LiveDeps = {
    wsFactory: (u) => new MockWS(u),
    auth,
    refresh,
    getHealth: () => Promise.resolve({ status: "ok", public_read: o.publicRead ?? false }),
    random: () => rnd.v,
    url: "ws://app.test/api/ws/live",
  };
  const counts: Record<string, number> = {};
  const keys: Record<string, readonly unknown[]> = {
    lanes: qk.lanes(),
    velocity: qk.velocity(30),
    geo: qk.geo(24),
    loud: qk.loud(50),
    cve: qk.cve("CVE-2025-1"),
    cves: qk.cves({ q: "x" }),
  };
  for (const [name, queryKey] of Object.entries(keys)) {
    counts[name] = 0;
    // an active observer keeps the query live so an invalidation refetches it
    new QueryObserver(qc, {
      queryKey,
      queryFn: () => Promise.resolve(++counts[name]),
      staleTime: 30_000,
    }).subscribe(() => undefined);
  }
  const ctl = createLiveController(qc, deps);
  return { qc, auth, refresh, ctl, deps, counts, rnd };
}

async function started(o: Parameters<typeof setup>[0] = {}) {
  const r = setup(o);
  r.ctl.start();
  await flush();
  return r;
}
async function live(o: Parameters<typeof setup>[0] = {}) {
  const r = await started(o);
  last().open();
  await flush();
  // initial fetches of the observers
  return r;
}

beforeEach(() => {
  vi.useFakeTimers();
  MockWS.instances = [];
});
afterEach(() => {
  vi.useRealTimers();
});

describe("url and auth", () => {
  test("wss for https pages, ws otherwise, no query string", () => {
    expect(liveUrl({ protocol: "https:", host: "cvenom.example" })).toBe("wss://cvenom.example/api/ws/live");
    expect(liveUrl({ protocol: "http:", host: "localhost:5173" })).toBe("ws://localhost:5173/api/ws/live");
    expect(liveUrl()).toMatch(/^ws:\/\/[^?]+\/api\/ws\/live$/);
  });

  test("private + authed: URL has no token and the first message is the auth message", async () => {
    const r = await started({ publicRead: false, token: "secret-access" });
    expect(MockWS.instances).toHaveLength(1);
    expect(last().url).not.toContain("secret-access");
    expect(last().url).not.toContain("?");
    expect(r.ctl.getState().status).toBe("reconnecting"); // not live before open
    last().open();
    expect(last().sent).toEqual([JSON.stringify({ type: "auth", token: "secret-access" })]);
    expect(r.ctl.getState().status).toBe("live");
    r.ctl.stop();
  });

  test("private without a token makes no connection; a login connects and authenticates", async () => {
    const r = await started({ publicRead: false, token: null });
    expect(MockWS.instances).toHaveLength(0);
    expect(r.ctl.getState().status).toBe("offline");
    await vi.advanceTimersByTimeAsync(200_000);
    expect(MockWS.instances).toHaveLength(0);
    r.auth.set("fresh");
    await flush();
    expect(MockWS.instances).toHaveLength(1);
    last().open();
    expect(last().sent).toEqual([JSON.stringify({ type: "auth", token: "fresh" })]);
    expect(r.ctl.getState().status).toBe("live");
    r.ctl.stop();
  });

  test("public server: anonymous connect sends nothing; with a token the auth message is still sent", async () => {
    const a = await live({ publicRead: true, token: null });
    expect(last().sent).toEqual([]);
    expect(a.ctl.getState().status).toBe("live");
    a.ctl.stop();
    MockWS.instances = [];
    const b = await live({ publicRead: true, token: "t" });
    expect(last().sent).toEqual([JSON.stringify({ type: "auth", token: "t" })]);
    b.ctl.stop();
  });

  test("logout: private goes offline and closes; public reconnects anonymously", async () => {
    const p = await live({ publicRead: false });
    const s = last();
    p.auth.set(null);
    await flush();
    expect(s.closeCode).toBe(1000);
    expect(p.ctl.getState().status).toBe("offline");
    await vi.advanceTimersByTimeAsync(120_000);
    expect(MockWS.instances).toHaveLength(1);
    p.ctl.stop();

    MockWS.instances = [];
    const q = await live({ publicRead: true });
    q.auth.set(null);
    await flush();
    expect(MockWS.instances).toHaveLength(2);
    last().open();
    expect(last().sent).toEqual([]);
    expect(q.ctl.getState().status).toBe("live");
    q.ctl.stop();
  });
});

describe("messages and invalidation", () => {
  test("updated:[lanes] refetches lanes, velocity, cve, cves but not loud or geo", async () => {
    const r = await live({ publicRead: true });
    const before = { ...r.counts };
    last().msg({ type: "updated", what: ["lanes"] });
    await vi.advanceTimersByTimeAsync(499);
    expect(r.counts).toEqual(before); // debounced
    await vi.advanceTimersByTimeAsync(2);
    for (const k of ["lanes", "velocity", "cve", "cves"]) expect(r.counts[k]).toBe(before[k] + 1);
    for (const k of ["loud", "geo"]) expect(r.counts[k]).toBe(before[k]);
    r.ctl.stop();
  });

  test("stories -> loud only; geo -> geo only", async () => {
    const r = await live({ publicRead: true });
    const before = { ...r.counts };
    last().msg({ type: "updated", what: ["stories"] });
    await vi.advanceTimersByTimeAsync(600);
    expect(r.counts.loud).toBe(before.loud + 1);
    expect(r.counts.lanes).toBe(before.lanes);
    expect(r.counts.geo).toBe(before.geo);
    last().msg({ type: "updated", what: ["geo"] });
    await vi.advanceTimersByTimeAsync(600);
    expect(r.counts.geo).toBe(before.geo + 1);
    expect(r.counts.loud).toBe(before.loud + 1);
    r.ctl.stop();
  });

  test("a burst of 3 updates within 500ms causes a single refetch per query", async () => {
    const r = await live({ publicRead: true });
    const before = { ...r.counts };
    last().msg({ type: "updated", what: ["lanes"] });
    await vi.advanceTimersByTimeAsync(200);
    last().msg({ type: "updated", what: ["lanes", "geo"] });
    await vi.advanceTimersByTimeAsync(200);
    last().msg({ type: "updated", what: ["stories"] });
    await vi.advanceTimersByTimeAsync(1000);
    for (const k of ["lanes", "velocity", "cve", "cves", "geo", "loud"]) expect(r.counts[k]).toBe(before[k] + 1);
    r.ctl.stop();
  });

  test("unknown what values are ignored; known ones in the same message still work", async () => {
    const r = await live({ publicRead: true });
    const before = { ...r.counts };
    last().msg({ type: "updated", what: ["bogus", "__proto__", 7, null] });
    await vi.advanceTimersByTimeAsync(1000);
    expect(r.counts).toEqual(before);
    last().msg({ type: "updated", what: ["bogus", "geo"] });
    await vi.advanceTimersByTimeAsync(1000);
    expect(r.counts.geo).toBe(before.geo + 1);
    expect(r.counts.lanes).toBe(before.lanes);
    r.ctl.stop();
  });

  test("ping and malformed messages are ignored and do not crash", async () => {
    const r = await live({ publicRead: true });
    const before = { ...r.counts };
    for (const m of [{ type: "ping" }, "{not json", "null", "42", '"str"', "[]", { type: "updated" }, { what: ["lanes"] }]) {
      expect(() => last().msg(m)).not.toThrow();
    }
    last().onmessage?.({ data: new ArrayBuffer(4) });
    await vi.advanceTimersByTimeAsync(1000);
    expect(r.counts).toEqual(before);
    expect(r.ctl.getState().status).toBe("live");
    r.ctl.stop();
  });

  test("lastUpdated is the time of the last updated message, not ping", async () => {
    const r = await live({ publicRead: true });
    expect(r.ctl.getState().lastUpdated).toBeNull();
    last().msg({ type: "ping" });
    expect(r.ctl.getState().lastUpdated).toBeNull();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
    last().msg({ type: "updated", what: ["geo"] });
    expect(r.ctl.getState().lastUpdated).toBe(Date.parse("2026-01-01T00:00:00Z"));
    r.ctl.stop();
  });

  test("a query still inside its Retry-After window is not invalidated", async () => {
    const r = await live({ publicRead: true });
    const q = r.qc.getQueryCache().find({ queryKey: qk.lanes() })!;
    q.setState({ ...q.state, status: "error", error: new RateLimited(30), errorUpdatedAt: Date.now() });
    const before = r.counts.lanes;
    last().msg({ type: "updated", what: ["lanes"] });
    await vi.advanceTimersByTimeAsync(1000);
    expect(r.counts.lanes).toBe(before);
    expect(r.counts.velocity).toBeGreaterThan(0);
    r.ctl.stop();
  });

  test("after a reconnect everything is refreshed once to cover missed pushes", async () => {
    const r = await live({ publicRead: true });
    r.rnd.v = 0;
    last().drop(1006);
    await vi.advanceTimersByTimeAsync(10);
    const before = { ...r.counts };
    last().open();
    await vi.advanceTimersByTimeAsync(1000);
    for (const k of Object.keys(before)) expect(r.counts[k]).toBe(before[k] + 1);
    r.ctl.stop();
  });
});

describe("close handling", () => {
  test("4401 does exactly one refresh, then reconnects immediately", async () => {
    const r = await live({ publicRead: false });
    last().drop(4401);
    await flush();
    expect(r.refresh).toHaveBeenCalledTimes(1);
    expect(MockWS.instances).toHaveLength(2);
    expect(r.ctl.getState().status).toBe("reconnecting");
    await vi.advanceTimersByTimeAsync(100_000);
    expect(r.refresh).toHaveBeenCalledTimes(1);
    expect(MockWS.instances).toHaveLength(2);
    last().open();
    expect(r.ctl.getState().status).toBe("live");
    r.ctl.stop();
  });

  test("4401 with a failed refresh goes offline and waits for a login", async () => {
    const r = await live({
      publicRead: false,
      refresh: () => Promise.reject(new AuthError()),
    });
    last().drop(4401);
    await flush();
    expect(r.refresh).toHaveBeenCalledTimes(1);
    expect(r.ctl.getState().status).toBe("offline");
    await vi.advanceTimersByTimeAsync(300_000);
    expect(MockWS.instances).toHaveLength(1);
    expect(r.refresh).toHaveBeenCalledTimes(1);
    r.auth.set(null);
    r.auth.set("new-login");
    await flush();
    expect(MockWS.instances).toHaveLength(2);
    r.ctl.stop();
  });

  test.each([4429, 4403])("%i waits at least 60s (plus jitter) before reconnecting", async (code) => {
    const r = await live({ publicRead: true });
    r.rnd.v = 0; // minimum jitter
    last().drop(code);
    await vi.advanceTimersByTimeAsync(59_999);
    expect(MockWS.instances).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(2);
    expect(MockWS.instances).toHaveLength(2);
    r.rnd.v = 0.999;
    last().open();
    last().drop(code);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(MockWS.instances).toHaveLength(2); // jitter added on top
    await vi.advanceTimersByTimeAsync(15_000);
    expect(MockWS.instances).toHaveLength(3);
    r.ctl.stop();
  });

  test("1011, 1006 and other closes use exponential backoff with full jitter, capped at 60s", async () => {
    const r = await live({ publicRead: true });
    r.rnd.v = 0.5;
    const delays: number[] = [];
    for (let i = 0; i < 9; i++) {
      const n = MockWS.instances.length;
      last().drop(i % 2 ? 1006 : 1011);
      // find the delay by stepping 100ms
      let waited = 0;
      while (MockWS.instances.length === n && waited < 70_000) {
        await vi.advanceTimersByTimeAsync(100);
        waited += 100;
      }
      expect(MockWS.instances).toHaveLength(n + 1);
      delays.push(waited);
    }
    // expected = 0.5 * min(60000, 1000 * 2^attempt), within the 100ms step
    const expected = [500, 1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000];
    delays.forEach((d, i) => {
      expect(d).toBeGreaterThanOrEqual(expected[i]);
      expect(d).toBeLessThanOrEqual(expected[i] + 100);
    });
    r.ctl.stop();
  });

  test("delay is always within [0, min(60s, 1s*2^attempt)] across the range of random()", async () => {
    for (const v of [0, 0.999]) {
      const r = await live({ publicRead: true });
      r.rnd.v = v;
      for (let attempt = 0; attempt < 8; attempt++) {
        const n = MockWS.instances.length;
        last().drop(1006);
        const bound = Math.min(60_000, 1000 * 2 ** attempt);
        await vi.advanceTimersByTimeAsync(bound);
        expect(MockWS.instances).toHaveLength(n + 1);
      }
      r.ctl.stop();
    }
  });

  test("the attempt counter resets after the socket stayed open for 60s, not before", async () => {
    const r = await live({ publicRead: true });
    r.rnd.v = 0.999;
    // two failed attempts that never open: attempt -> 2
    for (let i = 0; i < 2; i++) {
      last().drop(1006);
      await vi.advanceTimersByTimeAsync(60_000);
    }
    // open and stay up only 59s: no reset, next delay is ~0.999 * 4000
    last().open();
    await vi.advanceTimersByTimeAsync(59_000);
    let n = MockWS.instances.length;
    last().drop(1006);
    await vi.advanceTimersByTimeAsync(3000);
    expect(MockWS.instances).toHaveLength(n); // would be <=1000 if it had reset
    await vi.advanceTimersByTimeAsync(1100);
    expect(MockWS.instances).toHaveLength(n + 1);
    // open and stay up 60s: reset, next delay <= 1000
    last().open();
    await vi.advanceTimersByTimeAsync(60_000);
    n = MockWS.instances.length;
    last().drop(1006);
    await vi.advanceTimersByTimeAsync(1000);
    expect(MockWS.instances).toHaveLength(n + 1);
    r.ctl.stop();
  });

  test("a health fetch failure is retried with backoff", async () => {
    const r = setup({ publicRead: true });
    let calls = 0;
    r.deps.getHealth = () => (++calls < 2 ? Promise.reject(new Error("down")) : Promise.resolve({ status: "ok", public_read: true }));
    const ctl = createLiveController(r.qc, r.deps);
    ctl.start();
    await flush();
    expect(MockWS.instances).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1000);
    expect(MockWS.instances).toHaveLength(1);
    ctl.stop();
  });
});

describe("unmount", () => {
  test("stop closes with 1000, clears timers and schedules no reconnect", async () => {
    const r = await live({ publicRead: true });
    const s = last();
    last().msg({ type: "updated", what: ["geo"] }); // pending debounce
    const geo = r.counts.geo;
    r.ctl.stop();
    expect(s.closeCode).toBe(1000);
    s.drop(1006); // a late close event from the dead socket
    await vi.advanceTimersByTimeAsync(300_000);
    expect(MockWS.instances).toHaveLength(1);
    expect(r.counts.geo).toBe(geo); // debounced invalidation was cancelled
    expect(vi.getTimerCount()).toBe(0);
  });

  test("stop while a reconnect is pending cancels it", async () => {
    const r = await live({ publicRead: true });
    last().drop(1006);
    r.ctl.stop();
    await vi.advanceTimersByTimeAsync(300_000);
    expect(MockWS.instances).toHaveLength(1);
  });

  test("stop during a 4401 refresh does not reconnect", async () => {
    let resolve!: () => void;
    const r = await live({ publicRead: false, refresh: () => new Promise<void>((res) => (resolve = res)) });
    last().drop(4401);
    r.ctl.stop();
    resolve();
    await vi.advanceTimersByTimeAsync(100_000);
    expect(MockWS.instances).toHaveLength(1);
  });
});

describe("useLiveUpdates", () => {
  function Probe({ deps, out }: { deps: LiveDeps; out: { current: LiveState | null } }) {
    out.current = useLiveUpdates(deps);
    return null;
  }

  test("StrictMode double mount creates a single socket; status and unmount behave", async () => {
    const r = setup({ publicRead: true });
    const out: { current: LiveState | null } = { current: null };
    const view = render(
      <StrictMode>
        <QueryClientProvider client={r.qc}>
          <Probe deps={r.deps} out={out} />
        </QueryClientProvider>
      </StrictMode>,
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10);
    });
    expect(MockWS.instances).toHaveLength(1);
    expect(out.current?.status).toBe("reconnecting");
    await act(async () => {
      last().open();
    });
    expect(out.current?.status).toBe("live");
    await act(async () => {
      last().msg({ type: "updated", what: ["geo"] });
    });
    expect(out.current?.lastUpdated).not.toBeNull();
    const s = last();
    view.unmount();
    expect(s.closeCode).toBe(1000);
    await vi.advanceTimersByTimeAsync(200_000);
    expect(MockWS.instances).toHaveLength(1);
  });
});
