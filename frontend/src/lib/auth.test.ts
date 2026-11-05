import { HttpResponse, http } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, test, vi } from "vitest";
import { createApiClient, type ApiClient } from "./api";
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
