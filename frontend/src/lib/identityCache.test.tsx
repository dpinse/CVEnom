import { QueryClientProvider, QueryObserver } from "@tanstack/react-query";
import { act, fireEvent, render, renderHook, screen, waitFor } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, test, vi } from "vitest";
import { AppRoutes } from "../routes";
import { fill, passCode } from "../test/authpages";
import { makeHub } from "../test/coord";
import { server, setupMsw } from "../test/shell";
import { authStore, createApiClient } from "./api";
import { getAuth } from "./auth";
import { bindQueryCacheToAuth, createQueryClient, qk, useCve } from "./queries";
import { createTokenStore } from "./tokenStore";
import type { Me, SessionInfo } from "./types";

vi.mock("./live", () => ({ useLiveUpdates: () => ({ status: "live", lastUpdated: null }) }));

setupMsw();

const A: Me = { id: 11, email: "alice@example.com", role: "member" };
const B: Me = { id: 22, email: "bob@example.com", role: "member" };
const session = (id: string, ip: string): SessionInfo => ({
  id,
  user_agent: "Mozilla/5.0 Firefox/130",
  ip,
  created_at: "2026-11-01T00:00:00Z",
  last_used_at: "2026-11-05T00:00:00Z",
  current: true,
});

let unbind: (() => void) | undefined;
afterEach(() => {
  unbind?.();
  unbind = undefined;
});

describe("I1: the query cache is identity-scoped", () => {
  test("log in as A, load sessions, log out, log in as B: no A rows and the sessions fetch re-runs", async () => {
    const sessionCalls: string[] = [];
    server.use(
      http.get("http://localhost/api/health", () => HttpResponse.json({ status: "ok", public_read: true })),
      http.get("http://localhost/api/lanes", () =>
        HttpResponse.json({ EXPLOITED: [], LIKELY: [], LOUD: [], FRESH: [] }),
      ),
      http.get("http://localhost/api/auth/sessions", ({ request }) => {
        const auth = request.headers.get("Authorization");
        sessionCalls.push(auth ?? "none");
        if (auth === "Bearer tok-A") return HttpResponse.json([session("a1", "198.51.100.1")]);
        if (auth === "Bearer tok-B") return HttpResponse.json([session("b1", "203.0.113.2")]);
        return HttpResponse.json({ error: "unauthorized" }, { status: 401 });
      }),
      // two-step sign-in: the ticket names the user, the session comes from the second factor
      http.post("http://localhost/api/auth/login", async ({ request }) => {
        const { email } = (await request.json()) as { email: string };
        return HttpResponse.json({
          ticket: email === A.email ? "tk-A" : "tk-B",
          enroll_required: false,
          expires_in: 300,
        });
      }),
      http.post("http://localhost/api/auth/mfa/verify", async ({ request }) => {
        const { ticket } = (await request.json()) as { ticket: string };
        return HttpResponse.json({
          access_token: ticket === "tk-A" ? "tok-A" : "tok-B",
          token_type: "bearer",
          expires_in: 900,
        });
      }),
      http.get("http://localhost/api/auth/me", ({ request }) =>
        HttpResponse.json(request.headers.get("Authorization") === "Bearer tok-A" ? A : B),
      ),
      http.post("http://localhost/api/auth/logout", () => new HttpResponse(null, { status: 204 })),
    );
    authStore.setReady(true);
    const qc = createQueryClient();
    unbind = bindQueryCacheToAuth(qc, authStore);
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/login?next=%2Faccount%2Fsessions"]}>
          <AppRoutes />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const signInAs = async (u: Me) => {
      fill("Email", u.email);
      fill("Password", "correct horse battery");
      fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
      await passCode();
    };

    await screen.findByLabelText("Email");
    await signInAs(A);
    expect(await screen.findByText("198.51.100.1")).toBeInTheDocument();
    expect(sessionCalls).toEqual(["Bearer tok-A"]);

    // log out (this tab): RequireUser sends us back to the sign-in page for the same route
    await act(async () => {
      await getAuth().logout();
    });
    await screen.findByLabelText("Email");
    expect(qc.getQueryData(qk.sessions())).toBeUndefined();

    // B signs in in the same tab and lands on the same page
    await signInAs(B);
    expect(await screen.findByText("203.0.113.2")).toBeInTheDocument();
    expect(screen.queryByText("198.51.100.1")).toBeNull();
    expect(sessionCalls.at(-1)).toBe("Bearer tok-B");
    expect(sessionCalls.filter((c) => c === "Bearer tok-B")).toHaveLength(1);
  });

  test("a CVE query issued before auth is ready does not fire; after ready with a user it fetches with auth", async () => {
    const seen: (string | null)[] = [];
    server.use(
      http.get("http://localhost/api/cves/:id", ({ request }) => {
        seen.push(request.headers.get("Authorization"));
        return HttpResponse.json({ cve_id: "CVE-2026-0001" });
      }),
    );
    const qc = createQueryClient();
    unbind = bindQueryCacheToAuth(qc, authStore);
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    );
    const { result } = renderHook(() => useCve("CVE-2026-0001"), { wrapper });
    await new Promise((r) => setTimeout(r, 50));
    expect(seen).toEqual([]);
    expect(result.current.fetchStatus).toBe("idle");

    act(() => {
      authStore.setToken("tok-member");
      authStore.setUser(A);
      authStore.setReady(true);
    });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(seen).toEqual(["Bearer tok-member"]);
  });

  test("a peer-tab logout broadcast clears the cache (health excepted)", async () => {
    const hub = makeHub();
    const storeA = createTokenStore();
    const storeB = createTokenStore();
    const fetchFn = (() => Promise.resolve(new Response(null, { status: 204 }))) as typeof fetch;
    const tabA = createApiClient({ store: storeA, fetchFn, locks: null, channel: hub.channel() });
    const tabB = createApiClient({ store: storeB, fetchFn, locks: null, channel: hub.channel() });
    storeA.setToken("tok-A");
    storeA.setUser(A);
    storeA.setReady(true);
    const qc = createQueryClient();
    unbind = bindQueryCacheToAuth(qc, storeA);
    qc.setQueryData(qk.sessions(), [session("a1", "198.51.100.1")]);
    qc.setQueryData(qk.cve("CVE-2026-0001"), { cve_id: "CVE-2026-0001", stories: [{ source: "ransomware.live" }] });
    qc.setQueryData(qk.health(), { status: "ok", public_read: true });

    tabB.announce({ type: "logout", sub: String(A.id) });
    await waitFor(() => expect(storeA.getSnapshot().authenticated).toBe(false));
    expect(qc.getQueryData(qk.sessions())).toBeUndefined();
    expect(qc.getQueryData(qk.cve("CVE-2026-0001"))).toBeUndefined();
    expect(qc.getQueryData(qk.health())).toEqual({ status: "ok", public_read: true });
    tabA.dispose();
    tabB.dispose();
  });

  test("an active observer from user A loses A's data as soon as the identity switches", async () => {
    const store = createTokenStore();
    store.setToken("tok-A");
    store.setUser(A);
    store.setReady(true);
    const qc = createQueryClient();
    unbind = bindQueryCacheToAuth(qc, store);
    let who = "A";
    const obs = new QueryObserver(qc, { queryKey: qk.sessions(), queryFn: () => Promise.resolve(who) });
    const seen: unknown[] = [];
    const off = obs.subscribe((r) => seen.push(r.data));
    await waitFor(() => expect(obs.getCurrentResult().data).toBe("A"));
    who = "B";
    act(() => {
      store.setToken("tok-B");
      store.setUser(B);
    });
    expect(obs.getCurrentResult().data).not.toBe("A");
    await waitFor(() => expect(obs.getCurrentResult().data).toBe("B"));
    off();
  });

  test("a token rotation for the same user keeps the cache", () => {
    const store = createTokenStore();
    store.setToken("tok-1");
    store.setUser(A);
    store.setReady(true);
    const qc = createQueryClient();
    unbind = bindQueryCacheToAuth(qc, store);
    qc.setQueryData(qk.lanes(), { EXPLOITED: [] });
    store.setToken("tok-2");
    expect(qc.getQueryData(qk.lanes())).toEqual({ EXPLOITED: [] });
  });
});
