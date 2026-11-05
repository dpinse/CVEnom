import { HttpResponse, delay, http } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, test, vi } from "vitest";
import { makeHub, makeLocks } from "../test/coord";
import {
  ApiError,
  AuthError,
  NetworkError,
  RateLimited,
  createApiClient,
  type ApiClient,
  type ApiClientOptions,
} from "./api";
import { createTokenStore } from "./tokenStore";

const B = "http://localhost/api";
const server = setupServer();
const made: ApiClient[] = [];
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  for (const c of made) c.dispose();
  made.length = 0;
  localStorage.clear();
  sessionStorage.clear();
});
afterAll(() => server.close());

const fetchFn: typeof fetch = (u, i) => fetch(new URL(String(u), "http://localhost"), i);

function mk(opts: Partial<ApiClientOptions> = {}) {
  const store = createTokenStore();
  const client = createApiClient({ store, fetchFn, locks: null, channel: null, ...opts });
  made.push(client);
  return { store, client };
}

type Caught = Error & { status: number; code: string; retryAfter: number; body: { detail: { msg: string }[] } };
const caught = (p: Promise<unknown>) =>
  p.then(
    () => {
      throw new Error("expected rejection");
    },
    (e: unknown) => e as Caught,
  );

const tokenBody = (t: string) => ({ access_token: t, token_type: "bearer", expires_in: 900 });

/** /cves returns 200 only for the bearer tokens in `good`. Records refresh calls. */
function useServer(good: string[], refreshImpl?: () => Response | Promise<Response>) {
  const state = { refreshCalls: 0, csrf: [] as (string | null)[], seenAuth: [] as (string | null)[] };
  server.use(
    http.get(`${B}/cves`, ({ request }) => {
      const a = request.headers.get("authorization");
      state.seenAuth.push(a);
      return good.some((g) => a === `Bearer ${g}`)
        ? HttpResponse.json({ ok: true })
        : HttpResponse.json({ error: "invalid_token" }, { status: 401 });
    }),
    http.post(`${B}/auth/refresh`, ({ request }) => {
      state.refreshCalls++;
      state.csrf.push(request.headers.get("x-cvenom-csrf"));
      return refreshImpl ? refreshImpl() : HttpResponse.json(tokenBody("new"));
    }),
  );
  return state;
}

describe("api client basics", () => {
  test("sends no Authorization header without a token, Bearer with one", async () => {
    const seen: (string | null)[] = [];
    server.use(
      http.get(`${B}/cves`, ({ request }) => {
        seen.push(request.headers.get("authorization"));
        return HttpResponse.json({ ok: true });
      }),
    );
    const { client } = mk();
    await client.api("/cves");
    client.adopt("t1", 900);
    await client.api("/cves");
    expect(seen).toEqual([null, "Bearer t1"]);
  });

  test("JSON body, content-type and same-origin credentials", async () => {
    let seen: { ct: string | null; body: unknown; cred: string } | null = null;
    server.use(
      http.post(`${B}/auth/invites`, async ({ request }) => {
        seen = { ct: request.headers.get("content-type"), body: await request.json(), cred: request.credentials };
        return HttpResponse.json({ token: "x" }, { status: 201 });
      }),
    );
    const { client } = mk();
    await client.api("/auth/invites", { method: "POST", body: { email: "a@b.co", role: "member" } });
    expect(seen).toEqual({ ct: "application/json", body: { email: "a@b.co", role: "member" }, cred: "same-origin" });
  });

  test("204 returns undefined", async () => {
    server.use(http.post(`${B}/auth/logout`, () => new HttpResponse(null, { status: 204 })));
    const { client } = mk();
    await expect(client.api("/auth/logout", { method: "POST" })).resolves.toBeUndefined();
  });

  test("429 throws RateLimited with Retry-After seconds", async () => {
    server.use(
      http.get(`${B}/cves`, () =>
        HttpResponse.json({ error: "rate_limited" }, { status: 429, headers: { "Retry-After": "7" } }),
      ),
    );
    const { client } = mk();
    const err = await caught(client.api("/cves"));
    expect(err).toBeInstanceOf(RateLimited);
    expect(err.retryAfter).toBe(7);
    expect(err.status).toBe(429);
    expect(err.code).toBe("rate_limited");
  });

  test("other errors throw ApiError(status, code); code defaults to http_<status>", async () => {
    server.use(
      http.get(`${B}/a`, () => HttpResponse.json({ error: "not_found" }, { status: 404 })),
      http.get(`${B}/b`, () => new HttpResponse("<html>bad gateway</html>", { status: 502 })),
      http.get(`${B}/c`, () =>
        HttpResponse.json({ error: "validation_error", detail: [{ loc: ["q"], msg: "m", type: "t" }] }, { status: 422 }),
      ),
    );
    const { client } = mk();
    const a = await caught(client.api("/a"));
    expect(a).toBeInstanceOf(ApiError);
    expect([a.status, a.code]).toEqual([404, "not_found"]);
    const b = await caught(client.api("/b"));
    expect([b.status, b.code]).toEqual([502, "http_502"]);
    const c = await caught(client.api("/c"));
    expect([c.status, c.code]).toEqual([422, "validation_error"]);
    expect(c.body.detail[0].msg).toBe("m");
  });

  test("network failure throws NetworkError", async () => {
    server.use(http.get(`${B}/cves`, () => HttpResponse.error()));
    const { client } = mk();
    await expect(client.api("/cves")).rejects.toBeInstanceOf(NetworkError);
  });
});

describe("401 handling", () => {
  test("401 -> refresh -> retry succeeds; refresh carries CSRF header", async () => {
    const s = useServer(["new"]);
    const { client, store } = mk();
    client.adopt("old", 900);
    await expect(client.api("/cves")).resolves.toEqual({ ok: true });
    expect(s.refreshCalls).toBe(1);
    expect(s.csrf).toEqual(["1"]);
    expect(s.seenAuth).toEqual(["Bearer old", "Bearer new"]);
    expect(store.getToken()).toBe("new");
  });

  test("retries only once: a second 401 after a good refresh surfaces as ApiError", async () => {
    const s = useServer([]);
    const { client } = mk();
    client.adopt("old", 900);
    const err = await caught(client.api("/cves"));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(401);
    expect(s.refreshCalls).toBe(1);
    expect(s.seenAuth).toHaveLength(2);
  });

  test("failed refresh -> AuthError and store cleared", async () => {
    useServer([], () => HttpResponse.json({ error: "invalid_token" }, { status: 401 }));
    const { client, store } = mk();
    client.adopt("old", 900);
    store.setUser({ id: 1, email: "a@b.co", role: "admin" });
    await expect(client.api("/cves")).rejects.toBeInstanceOf(AuthError);
    expect(store.getToken()).toBeNull();
    expect(store.getUser()).toBeNull();
  });

  test("two concurrent 401s -> exactly one refresh call", async () => {
    const s = useServer(["new"], async () => {
      await delay(30);
      return HttpResponse.json(tokenBody("new"));
    });
    const { client } = mk();
    client.adopt("old", 900);
    const [a, b] = await Promise.all([client.api("/cves"), client.api("/cves")]);
    expect(a).toEqual({ ok: true });
    expect(b).toEqual({ ok: true });
    expect(s.refreshCalls).toBe(1);
  });

  test("a late 401 for an already-replaced token retries without a second refresh", async () => {
    const s = useServer(["new"]);
    server.use(
      http.get(`${B}/late`, ({ request }) =>
        request.headers.get("authorization") === "Bearer new"
          ? HttpResponse.json({ ok: 1 })
          : HttpResponse.json({ error: "invalid_token" }, { status: 401 }),
      ),
    );
    // The response to the request sent with "old" arrives after another request already
    // refreshed the token to "new".
    let first = true;
    const store = createTokenStore();
    const client: ApiClient = createApiClient({
      store,
      locks: null,
      channel: null,
      fetchFn: async (u, i) => {
        const res = await fetchFn(u, i);
        if (first) {
          first = false;
          client.adopt("new", 900);
        }
        return res;
      },
    });
    made.push(client);
    client.adopt("old", 900);
    await expect(client.api("/late")).resolves.toEqual({ ok: 1 });
    expect(s.refreshCalls).toBe(0);
  });

  test.each(["/auth/login", "/auth/password", "/auth/refresh", "/auth/invites/accept"])(
    "401 on exempt path %s: no refresh, no logout, plain ApiError",
    async (path) => {
      let refreshCalls = 0;
      server.use(
        http.post(`${B}/auth/refresh`, () => {
          refreshCalls++;
          return HttpResponse.json({ error: "invalid_credentials" }, { status: 401 });
        }),
      );
      if (path !== "/auth/refresh")
        server.use(http.post(`${B}${path}`, () => HttpResponse.json({ error: "invalid_credentials" }, { status: 401 })));
      const { client, store } = mk();
      client.adopt("keep", 900);
      store.setUser({ id: 1, email: "a@b.co", role: "member" });
      const err = await caught(client.api(path, { method: "POST", body: {} }));
      expect(err).toBeInstanceOf(ApiError);
      expect(err).not.toBeInstanceOf(AuthError);
      expect([err.status, err.code]).toEqual([401, "invalid_credentials"]);
      // for /auth/refresh the single call is the request itself, never a follow-up refresh
      expect(refreshCalls).toBe(path === "/auth/refresh" ? 1 : 0);
      expect(store.getToken()).toBe("keep");
      expect(store.getUser()).not.toBeNull();
    },
  );
});

describe("token is memory only", () => {
  test("not in localStorage or sessionStorage after adopt and after refresh", async () => {
    useServer(["secret-new-token"], () => HttpResponse.json(tokenBody("secret-new-token")));
    const { client } = mk();
    client.adopt("secret-old-token", 900);
    const scan = () => {
      for (const st of [localStorage, sessionStorage]) {
        for (let i = 0; i < st.length; i++) {
          const k = st.key(i) as string;
          for (const t of ["secret-old-token", "secret-new-token"]) {
            expect(k).not.toContain(t);
            expect(st.getItem(k) ?? "").not.toContain(t);
          }
        }
      }
    };
    scan();
    await client.api("/cves");
    scan();
  });
});

describe("proactive refresh", () => {
  async function timerRun(opts: { locks: boolean; random?: () => number }, ...advances: number[]) {
    vi.useFakeTimers();
    try {
      const calls: string[] = [];
      const fn: typeof fetch = async (u) => {
        calls.push(String(u));
        return new Response(JSON.stringify(tokenBody("t2")), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      };
      const store = createTokenStore();
      const client = createApiClient({
        store,
        fetchFn: fn,
        locks: opts.locks ? makeLocks() : null,
        channel: null,
        random: opts.random,
      });
      made.push(client);
      client.adopt("t1", 900);
      const counts: number[] = [];
      for (const ms of advances) {
        await vi.advanceTimersByTimeAsync(ms);
        counts.push(calls.length);
      }
      return counts;
    } finally {
      vi.useRealTimers();
    }
  }

  test("with Web Locks the timer fires within [expires-80s, expires-60s] (jitter 0 = earliest)", async () => {
    // jitter 1 -> 820 s; jitter 0 -> 840 s
    expect(await timerRun({ locks: true, random: () => 1 }, 819_000, 2_000)).toEqual([0, 1]);
    expect(await timerRun({ locks: true, random: () => 0 }, 839_000, 2_000)).toEqual([0, 1]);
  });

  test("never fires before 820 s, whatever the jitter", async () => {
    expect(await timerRun({ locks: true }, 819_000)).toEqual([0]);
  });

  test("without navigator.locks there is no proactive timer", async () => {
    expect(await timerRun({ locks: false }, 1_000_000)).toEqual([0]);
  });

  test("without navigator.locks a reactive refresh on 401 still works", async () => {
    const s = useServer(["new"]);
    const { client, store } = mk({ locks: null });
    client.adopt("old", 900);
    await expect(client.api("/cves")).resolves.toEqual({ ok: true });
    expect(s.refreshCalls).toBe(1);
    expect(store.getToken()).toBe("new");
  });

  test("delay is clamped to at least 1 s and at most 2^31-1 ms", async () => {
    expect(await timerRun({ locks: true }, 0)).toEqual([0]); // sanity
    vi.useFakeTimers();
    try {
      const calls: string[] = [];
      const fn: typeof fetch = async (u) => {
        calls.push(String(u));
        return new Response(JSON.stringify(tokenBody("t2")), { status: 200 });
      };
      const store = createTokenStore();
      const client = createApiClient({ store, fetchFn: fn, locks: makeLocks(), channel: null });
      made.push(client);
      client.adopt("t1", 1e12); // would overflow setTimeout (fires immediately) if unclamped
      await vi.advanceTimersByTimeAsync(5_000);
      expect(calls).toHaveLength(0);
      client.adopt("t1", 0.001); // tiny: at least 1 s
      await vi.advanceTimersByTimeAsync(10);
      expect(calls).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("cross-tab (Web Locks + broadcast events)", () => {
  function tabs() {
    const hub = makeHub();
    const locks = makeLocks();
    const mkTab = () => mk({ locks, channel: hub.channel() });
    return { a: mkTab(), b: mkTab(), locks, hub };
  }

  test("a guest tab ignores a peer's refreshed broadcast", async () => {
    const { b, hub } = tabs();
    hub.channel().postMessage({ type: "refreshed", access_token: "peer", expires_in: 900, sub: "1" });
    await new Promise((r) => setTimeout(r, 5));
    expect(b.store.getToken()).toBeNull();
  });

  test("401 on refresh right after a peer's broadcast adopts that token instead of logging out", async () => {
    const s = useServer(["peer"], async () => {
      await delay(80);
      return HttpResponse.json({ error: "invalid_token" }, { status: 401 }); // grace-window loser
    });
    const hub = makeHub();
    const b = mk({ locks: null, channel: hub.channel() });
    b.client.adopt("old", 900);
    const p = b.client.api("/cves");
    await vi.waitFor(() => expect(s.refreshCalls).toBe(1));
    hub.channel().postMessage({ type: "refreshed", access_token: "peer", expires_in: 900, sub: null });
    await expect(p).resolves.toEqual({ ok: true });
    expect(b.store.getToken()).toBe("peer");
  });

  test("401 on refresh with no recent peer broadcast still logs out", async () => {
    useServer([], () => HttpResponse.json({ error: "invalid_token" }, { status: 401 }));
    const { client, store } = mk({ locks: null });
    client.adopt("old", 900);
    await expect(client.api("/cves")).rejects.toBeInstanceOf(AuthError);
    expect(store.getToken()).toBeNull();
  });

  test("a guest request (no token sent) never calls /refresh", async () => {
    const s = useServer([]);
    const { client } = mk();
    const err = await caught(client.api("/cves"));
    expect([err.status, err.code]).toEqual([401, "invalid_token"]);
    expect(s.refreshCalls).toBe(0);
  });

  test("Web Locks: second tab adopts the broadcast token and does not call /refresh", async () => {
    const s = useServer(["new"], async () => {
      await delay(20);
      // a reused refresh cookie would be rejected (the backend revokes the session)
      return s.refreshCalls === 1
        ? HttpResponse.json(tokenBody("new"))
        : HttpResponse.json({ error: "invalid_token" }, { status: 401 });
    });
    const { a, b, locks } = tabs();
    a.client.adopt("old", 900);
    b.client.adopt("old", 900);
    const [ra, rb] = await Promise.all([a.client.api("/cves"), b.client.api("/cves")]);
    expect([ra, rb]).toEqual([{ ok: true }, { ok: true }]);
    expect(s.refreshCalls).toBe(1);
    expect(locks?.calls).toEqual(["cvenom-refresh", "cvenom-refresh"]);
    expect(a.store.getToken()).toBe("new");
    expect(b.store.getToken()).toBe("new");
  });

  test("a tab that never hit a 401 still adopts the broadcast token", async () => {
    const s = useServer(["new"]);
    const { a, b } = tabs();
    a.client.adopt("old", 900);
    b.client.adopt("old", 900);
    await a.client.api("/cves");
    await new Promise((r) => setTimeout(r, 5));
    expect(b.store.getToken()).toBe("new");
    expect(s.refreshCalls).toBe(1);
  });

  test("ignores malformed broadcast messages", async () => {
    const hub = makeHub();
    const { store } = mk({ channel: hub.channel() });
    const other = hub.channel();
    store.setToken("keep");
    other.postMessage({ type: "refreshed", access_token: 5, expires_in: "x" });
    other.postMessage("garbage");
    other.postMessage(null);
    await new Promise((r) => setTimeout(r, 5));
    expect(store.getToken()).toBe("keep");
  });
});
