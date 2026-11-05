import { HttpResponse, delay, http } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, test, vi } from "vitest";
import { makeHub, makeLocks } from "../test/coord";
import { AuthError, createApiClient, type ApiClient } from "./api";
import { createAuth } from "./auth";
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
const me = { id: 7, email: "a@b.co", role: "admin" as const };

function mk() {
  const store = createTokenStore();
  const client = createApiClient({ store, fetchFn, locks: null, channel: null });
  made.push(client);
  return { store, client, auth: createAuth({ client, store }) };
}

function meHandler() {
  return http.get(`${B}/auth/me`, ({ request }) =>
    request.headers.get("authorization")?.startsWith("Bearer ")
      ? HttpResponse.json(me)
      : HttpResponse.json({ error: "invalid_token" }, { status: 401 }),
  );
}

describe("auth store", () => {
  test("login posts credentials then loads /me; token stays out of storage", async () => {
    let body: unknown;
    server.use(
      http.post(`${B}/auth/login`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ access_token: "tok-login-secret", token_type: "bearer", expires_in: 900 });
      }),
      meHandler(),
    );
    const { auth } = mk();
    const fn = vi.fn();
    auth.subscribe(fn);
    await auth.login("a@b.co", "pw");
    expect(body).toEqual({ email: "a@b.co", password: "pw" });
    expect(auth.getToken()).toBe("tok-login-secret");
    expect(auth.getSnapshot().user).toEqual(me);
    expect(fn).toHaveBeenCalled();
    for (const st of [localStorage, sessionStorage])
      for (let i = 0; i < st.length; i++) {
        const k = st.key(i) as string;
        expect(k).not.toContain("tok-login-secret");
        expect(st.getItem(k) ?? "").not.toContain("tok-login-secret");
      }
  });

  test("bad credentials surface as ApiError and leave the user a guest", async () => {
    server.use(http.post(`${B}/auth/login`, () => HttpResponse.json({ error: "invalid_credentials" }, { status: 401 })));
    const { auth } = mk();
    await expect(auth.login("a@b.co", "x")).rejects.toMatchObject({ status: 401, code: "invalid_credentials" });
    expect(auth.getToken()).toBeNull();
    expect(auth.getSnapshot().user).toBeNull();
  });

  test("logout clears memory even if the server call fails; unsubscribe stops notifications", async () => {
    server.use(
      http.post(`${B}/auth/login`, () => HttpResponse.json({ access_token: "t", token_type: "bearer", expires_in: 900 })),
      meHandler(),
      http.post(`${B}/auth/logout`, () => HttpResponse.error()),
    );
    const { auth } = mk();
    await auth.login("a@b.co", "pw");
    const fn = vi.fn();
    const off = auth.subscribe(fn);
    await auth.logout();
    expect(auth.getToken()).toBeNull();
    expect(auth.getSnapshot().user).toBeNull();
    expect(fn).toHaveBeenCalled();
    fn.mockClear();
    off();
    await auth.login("a@b.co", "pw");
    expect(fn).not.toHaveBeenCalled();
  });

  test("bootstrap with a 401 refresh leaves a guest and throws nothing", async () => {
    server.use(http.post(`${B}/auth/refresh`, () => HttpResponse.json({ error: "invalid_token" }, { status: 401 })));
    const { auth } = mk();
    await expect(auth.bootstrap()).resolves.toBeUndefined();
    expect(auth.getToken()).toBeNull();
    expect(auth.getSnapshot()).toMatchObject({ user: null, ready: true });
  });

  test("bootstrap with a network failure also stays a guest", async () => {
    server.use(http.post(`${B}/auth/refresh`, () => HttpResponse.error()));
    const { auth } = mk();
    await expect(auth.bootstrap()).resolves.toBeUndefined();
    expect(auth.getSnapshot()).toMatchObject({ user: null, ready: true });
  });

  test("bootstrap with a valid cookie restores the session", async () => {
    let csrf: string | null = null;
    server.use(
      http.post(`${B}/auth/refresh`, ({ request }) => {
        csrf = request.headers.get("x-cvenom-csrf");
        return HttpResponse.json({ access_token: "boot", token_type: "bearer", expires_in: 900 });
      }),
      meHandler(),
    );
    const { auth } = mk();
    await auth.bootstrap();
    expect(csrf).toBe("1");
    expect(auth.getToken()).toBe("boot");
    expect(auth.getSnapshot()).toMatchObject({ user: me, ready: true });
  });

  test("snapshot is referentially stable between changes", async () => {
    const { auth } = mk();
    expect(auth.getSnapshot()).toBe(auth.getSnapshot());
  });
});

// ---- cross-tab identity ----------------------------------------------------

const b64u = (o: unknown) => btoa(JSON.stringify(o)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
const jwt = (sub: number) => `${b64u({ alg: "none" })}.${b64u({ sub: String(sub) })}.sig`;
const userFor = (n: number) => ({ id: n, email: `u${n}@x.co`, role: "member" as const });

function identityServer(opts: { refreshAs?: () => number; failLogout?: boolean } = {}) {
  const calls = { refresh: 0, logout: 0 };
  server.use(
    http.get(`${B}/auth/me`, ({ request }) => {
      const t = request.headers.get("authorization")?.slice(7) ?? "";
      const sub = Number(JSON.parse(atob(t.split(".")[1] ?? "e30=")).sub);
      return Number.isFinite(sub) ? HttpResponse.json(userFor(sub)) : HttpResponse.json({ error: "x" }, { status: 401 });
    }),
    http.post(`${B}/auth/login`, async ({ request }) => {
      const { email } = (await request.json()) as { email: string };
      const n = Number(/^u(\d+)@/.exec(email)?.[1]);
      return HttpResponse.json({ access_token: jwt(n), token_type: "bearer", expires_in: 900 });
    }),
    http.post(`${B}/auth/refresh`, () => {
      calls.refresh++;
      return HttpResponse.json({ access_token: jwt(opts.refreshAs?.() ?? 1), token_type: "bearer", expires_in: 900 });
    }),
    http.post(`${B}/auth/logout`, () => {
      calls.logout++;
      return opts.failLogout ? HttpResponse.error() : new HttpResponse(null, { status: 204 });
    }),
    http.get(`${B}/cves`, ({ request }) =>
      request.headers.get("authorization") === `Bearer ${jwt(1)}`
        ? HttpResponse.json({ ok: true })
        : HttpResponse.json({ error: "invalid_token" }, { status: 401 }),
    ),
  );
  return calls;
}

function tabs(n = 2, withLocks = true) {
  const hub = makeHub();
  const locks = withLocks ? makeLocks() : null;
  const out = Array.from({ length: n }, () => {
    const store = createTokenStore();
    const client = createApiClient({ store, fetchFn, locks, channel: hub.channel() });
    made.push(client);
    return { store, client, auth: createAuth({ client, store }) };
  });
  return { tabs: out, hub };
}
const tick = () => new Promise((r) => setTimeout(r, 10));

describe("cross-tab identity", () => {
  test("logout in one tab clears the others", async () => {
    identityServer();
    const { tabs: [a, b] } = tabs();
    await a.auth.login("u1@x.co", "pw");
    await b.auth.login("u1@x.co", "pw"); // same user: both signed in
    await tick();
    expect(b.store.getToken()).not.toBeNull();
    await a.auth.logout();
    await tick();
    expect(b.store.getToken()).toBeNull();
    expect(b.auth.getSnapshot().user).toBeNull();
  });

  test("a logout by a different user does not clear this tab", async () => {
    identityServer();
    const { tabs: [a], hub } = tabs();
    await a.auth.login("u1@x.co", "pw");
    hub.channel().postMessage({ type: "logout", sub: "2" });
    await tick();
    expect(a.store.getToken()).not.toBeNull();
  });

  test("a guest tab is not signed in by a peer's refresh", async () => {
    identityServer();
    const { tabs: [b], hub } = tabs();
    expect(b.store.getToken()).toBeNull(); // guest
    hub.channel().postMessage({ type: "refreshed", access_token: jwt(1), expires_in: 900, sub: "1" });
    await tick();
    expect(b.store.getToken()).toBeNull();
    expect(b.auth.getSnapshot()).toMatchObject({ authenticated: false, user: null });
  });

  test("failed server logout followed by a peer broadcast does not sign the tab back in", async () => {
    identityServer({ failLogout: true });
    const { tabs: [a], hub } = tabs();
    await a.auth.login("u1@x.co", "pw");
    await a.auth.logout(); // server call fails, local state still cleared
    expect(a.store.getToken()).toBeNull();
    hub.channel().postMessage({ type: "refreshed", access_token: jwt(1), expires_in: 900, sub: "1" });
    await tick();
    expect(a.store.getToken()).toBeNull();
    expect(a.auth.getSnapshot().user).toBeNull();
  });

  test("a refresh that returns a different user's token updates the displayed user", async () => {
    identityServer({ refreshAs: () => 1 });
    const { tabs: [a] } = tabs();
    await a.auth.login("u2@x.co", "pw"); // shows user 2, token jwt(2): /cves 401s
    expect(a.auth.getSnapshot().user?.id).toBe(2);
    await a.client.api("/cves"); // 401 -> refresh returns user 1's token -> retry ok
    await vi.waitFor(() => expect(a.auth.getSnapshot().user?.id).toBe(1));
  });

  test("a peer's refreshed broadcast for another user reloads /me in a signed-in tab", async () => {
    identityServer();
    const { tabs: [a], hub } = tabs();
    await a.auth.login("u2@x.co", "pw");
    hub.channel().postMessage({ type: "refreshed", access_token: jwt(1), expires_in: 900, sub: "1" });
    await vi.waitFor(() => expect(a.auth.getSnapshot().user?.id).toBe(1));
    expect(a.store.getToken()).toBe(jwt(1));
  });

  test("a login event for a different user adopts the token and reloads /me; same user is ignored", async () => {
    identityServer();
    const { tabs: [a], hub } = tabs();
    await a.auth.login("u2@x.co", "pw");
    const peer = hub.channel();
    peer.postMessage({ type: "login", sub: "2", access_token: jwt(55), expires_in: 900 });
    await tick();
    expect(a.store.getToken()).toBe(jwt(2));
    peer.postMessage({ type: "login", sub: "1", access_token: jwt(1), expires_in: 900 });
    await vi.waitFor(() => expect(a.auth.getSnapshot().user?.id).toBe(1));
    expect(a.store.getToken()).toBe(jwt(1));
  });

  test("login in another tab as a different user switches this tab's identity", async () => {
    identityServer();
    const { tabs: [a, b] } = tabs();
    await a.auth.login("u2@x.co", "pw");
    await b.auth.login("u1@x.co", "pw");
    await vi.waitFor(() => expect(a.auth.getSnapshot().user?.id).toBe(1));
  });

  // Discriminates loadMe's epoch guard: after a logout and a login as the SAME user the token is
  // non-null and carries the same sub, so neither the `!t` nor the sub check can tell the stale /me
  // apart. Only the epoch does.
  test("logout, then login while a stale /me is pending: the stale /me does not overwrite the new session's user", async () => {
    identityServer();
    let meCalls = 0;
    server.use(
      http.get(`${B}/auth/me`, async () => {
        meCalls++;
        if (meCalls > 1) return HttpResponse.json(userFor(1));
        await delay(120);
        return HttpResponse.json({ ...userFor(1), role: "admin" }); // the old session's view of user 1
      }),
    );
    const { tabs: [a], hub } = tabs(1);
    a.client.adopt(jwt(2), 900);
    hub.channel().postMessage({ type: "refreshed", access_token: jwt(1), expires_in: 900, sub: "1" }); // starts the slow /me
    await vi.waitFor(() => expect(meCalls).toBe(1));
    await a.auth.logout();
    await a.auth.login("u1@x.co", "pw"); // its own /me answers at once
    expect(a.auth.getSnapshot().user).toEqual(userFor(1));
    await new Promise((r) => setTimeout(r, 200)); // the stale /me has resolved by now
    expect(meCalls).toBe(2);
    expect(a.store.getToken()).toBe(jwt(1));
    expect(a.auth.getSnapshot().user).toEqual(userFor(1));
  });

  // Discriminates loadMe's `!t` check. In the app the token only empties through client.clear(),
  // which also bumps the epoch, so this guards the store being emptied directly (the test shell's
  // authStore.clear() does that). With a token that has no `sub`, the sub check cannot catch it.
  test("a /me that resolves after the store was emptied directly does not set a user", async () => {
    let meCalls = 0;
    server.use(
      http.get(`${B}/auth/me`, async () => {
        meCalls++;
        await delay(60);
        return HttpResponse.json(userFor(3));
      }),
    );
    const { tabs: [a], hub } = tabs(1);
    a.client.adopt("opaque-1", 900);
    hub.channel().postMessage({ type: "refreshed", access_token: "opaque-2", expires_in: 900, sub: null }); // no user yet: /me
    await vi.waitFor(() => expect(meCalls).toBe(1));
    a.store.clear(); // no client.clear(): the epoch does not move
    await new Promise((r) => setTimeout(r, 120));
    expect(a.store.getToken()).toBeNull();
    expect(a.auth.getSnapshot()).toMatchObject({ authenticated: false, user: null });
  });

  test("if /me fails after login the server session is logged out before local state clears", async () => {
    const calls = { logout: 0 };
    server.use(
      http.post(`${B}/auth/login`, () => HttpResponse.json({ access_token: "t", token_type: "bearer", expires_in: 900 })),
      http.get(`${B}/auth/me`, () => HttpResponse.json({ error: "boom" }, { status: 500 })),
      http.post(`${B}/auth/logout`, () => {
        calls.logout++;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    const { auth, store } = mk();
    await expect(auth.login("a@b.co", "pw")).rejects.toMatchObject({ status: 500 });
    expect(calls.logout).toBe(1);
    expect(store.getToken()).toBeNull();
  });
});

// ---- logout -> login while the old session's refresh is still in flight -------------------------
// The refresh began before the logout, so its result belongs to the old session. The epoch guards in
// doRefresh must drop it whether it is a 200 (a rotated token of the old session) or a 401: the new
// session keeps its token and user, nothing is logged out, and nothing throws unhandled. The caller
// that triggered the old refresh still gets AuthError (the deferred, benign case in the Plan 4 ledger).

describe("logout -> login while the old session's refresh is in flight", () => {
  const late = {
    "200 (a rotated token of the old session)": () =>
      HttpResponse.json({ access_token: jwt(9), token_type: "bearer", expires_in: 900 }),
    "401": () => HttpResponse.json({ error: "invalid_token" }, { status: 401 }),
  };
  for (const [label, reply] of Object.entries(late)) {
    test(`a late ${label} is ignored and does not log out the new session`, async () => {
      identityServer();
      const calls = { refresh: 0 };
      server.use(
        http.post(`${B}/auth/refresh`, async () => {
          calls.refresh++;
          await delay(100);
          return reply();
        }),
      );
      const { auth, store, client } = mk();
      await auth.login("u2@x.co", "pw"); // jwt(2): /cves answers 401, so the next call refreshes
      const old = client.api("/cves").then(
        () => "resolved",
        (e: unknown) => e,
      );
      await vi.waitFor(() => expect(calls.refresh).toBe(1));
      await auth.logout();
      await auth.login("u2@x.co", "pw");
      expect(store.getToken()).toBe(jwt(2));
      expect(await old).toBeInstanceOf(AuthError); // the old session's caller, settled after the late reply
      await tick();
      expect(calls.refresh).toBe(1);
      expect(store.getToken()).toBe(jwt(2));
      expect(auth.getSnapshot()).toMatchObject({ authenticated: true, user: userFor(2) });
    });
  }
});
