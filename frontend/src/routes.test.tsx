import { cleanup, screen, waitFor } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { useLocation } from "react-router-dom";
import { afterEach, describe, expect, test, vi } from "vitest";
import { authStore } from "./lib/api";
import { __resetBootstrapForTests } from "./lib/useAuth";
import { AppRoutes, legacyThreatsSearch } from "./routes";
import { admin, guest, handlers, member, renderAt, server, signIn, setupMsw } from "./test/shell";

vi.mock("./lib/live", () => ({ useLiveUpdates: () => ({ status: "live", lastUpdated: null }) }));

setupMsw();
afterEach(() => {
  cleanup();
  __resetBootstrapForTests();
});

/** Shell tests drive auth via the store; bootstrap is a no-op there because it already settled. */
function Loc() {
  const l = useLocation();
  return <output data-testid="loc">{l.pathname + l.search}</output>;
}
const at = (path: string) =>
  renderAt(
    <>
      <AppRoutes />
      <Loc />
    </>,
    path,
  );

describe("guards", () => {
  test("a member is sent away from /admin/alerts with an Admins only notice", async () => {
    handlers();
    signIn(member);
    at("/admin/alerts");
    // the real dashboard has its own role=status loading regions, so find the notice by its text
    expect(await screen.findByText(/Admins only/)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Alert rules" })).toBeNull();
    expect(screen.getByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
  });
  test("an admin reaches /admin/alerts", async () => {
    handlers();
    signIn(admin);
    at("/admin/alerts");
    expect(await screen.findByRole("heading", { name: "Alert rules" })).toBeInTheDocument();
  });
  test("a guest is redirected from an admin route to /login?next=", async () => {
    handlers();
    guest();
    at("/admin/users");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });
  test("a guest is redirected from /account/sessions to login", async () => {
    handlers();
    guest();
    at("/account/sessions");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Sessions" })).toBeNull();
  });
  test("a signed-in user reaches /account/password", async () => {
    handlers();
    signIn(member);
    at("/account/password");
    expect(await screen.findByRole("heading", { name: "Change password" })).toBeInTheDocument();
  });
  test("a signed-in user reaches /account/two-factor", async () => {
    handlers();
    server.use(
      http.get("http://localhost/api/auth/mfa", () =>
        HttpResponse.json({ enabled: true, enrolled_at: null, recovery_codes_remaining: 10 }),
      ),
    );
    signIn(member);
    at("/account/two-factor");
    expect(await screen.findByRole("heading", { name: "Two-factor authentication" })).toBeInTheDocument();
  });
  test("public server: a guest sees the dashboard and search", async () => {
    handlers({ publicRead: true });
    guest();
    at("/threats");
    expect(await screen.findByRole("heading", { name: "Threats" })).toBeInTheDocument();
  });
  test("/history?kev=true redirects to /threats?status=exploited", async () => {
    handlers({ publicRead: true });
    guest();
    at("/history?kev=true");
    expect(await screen.findByRole("heading", { level: 1, name: "Threats" })).toBeInTheDocument();
    expect(screen.getByTestId("loc")).toHaveTextContent("/threats?status=exploited");
  });
  test("/search?q=x redirects to /threats?q=x", async () => {
    handlers({ publicRead: true });
    guest();
    at("/search?q=x");
    expect(await screen.findByRole("heading", { level: 1, name: "Threats" })).toBeInTheDocument();
    expect(screen.getByTestId("loc")).toHaveTextContent(/^\/threats\?q=x$/);
  });
  test("/history?cve=CVE-2026-1096 keeps the drawer selection", async () => {
    handlers({ publicRead: true });
    guest();
    at("/history?cve=CVE-2026-1096");
    expect(await screen.findByRole("heading", { level: 1, name: "Threats" })).toBeInTheDocument();
    expect(screen.getByTestId("loc")).toHaveTextContent("/threats?cve=CVE-2026-1096");
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
  });
  test("/threats/CVE-2026-0001 loads the threat page; a bad id is the not-found view", async () => {
    handlers({ publicRead: true });
    server.use(
      http.get("http://localhost/api/cves/CVE-2026-0001", () =>
        HttpResponse.json({ error: "not_found" }, { status: 404 }),
      ),
    );
    guest();
    at("/threats/CVE-2026-0001");
    expect(await screen.findByText("We have no record of CVE-2026-0001.")).toBeInTheDocument();
    cleanup();
    at("/threats/nope");
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeInTheDocument();
  });
  test("private server: a guest is redirected from / to /login", async () => {
    handlers({ publicRead: false });
    guest();
    at("/");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Dashboard" })).toBeNull();
  });
  test("private server: a signed-in member still sees the dashboard", async () => {
    handlers({ publicRead: false });
    signIn(member);
    at("/");
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
  });
  test("invite and reset routes render the AcceptInvite page", async () => {
    handlers();
    guest();
    at("/reset#abc");
    expect(await screen.findByRole("heading", { name: "Reset password" })).toBeInTheDocument();
    cleanup();
    at("/invite#abc");
    expect(await screen.findByRole("heading", { name: "Accept invite" })).toBeInTheDocument();
  });
  test("unknown routes show a 404", async () => {
    handlers();
    guest();
    at("/nope/nothing");
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeInTheDocument();
  });
});

describe("bootstrap", () => {
  test("guards wait for bootstrap: no redirect while loading, then the member stays on the page", async () => {
    handlers();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    server.use(
      http.post("http://localhost/api/auth/refresh", async () => {
        await gate;
        return HttpResponse.json({ access_token: "hdr.eyJzdWIiOiIyIn0.sig", token_type: "bearer", expires_in: 900 });
      }),
      http.get("http://localhost/api/auth/me", () => HttpResponse.json(member)),
    );
    at("/account/password");
    expect(await screen.findByText(/loading/i)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Sign in" })).toBeNull();
    expect(authStore.getSnapshot().ready).toBe(false);
    release();
    expect(await screen.findByRole("heading", { name: "Change password" })).toBeInTheDocument();
    await waitFor(() => expect(authStore.getSnapshot().user?.email).toBe("member@example.com"));
  });
});

describe("legacyThreatsSearch", () => {
  test.each([
    ["?kev=true&q=ivanti&page=2", "?q=ivanti&status=exploited"],
    ["?tab=stories", "?tab=news"],
    ["", ""],
    ["?min_cvss=9.5", "?sev=crit"],
    ["?min_cvss=7", "?sev=high%2Ccrit"],
    ["?min_cvss=5&from=2026-01-01&lane=LOUD", ""],
    ["?min_cvss=abc", ""],
    ["?cve=CVE-2026-1096&q=x", "?q=x&cve=CVE-2026-1096"],
    ["?cve=bogus", ""],
    ["?country=DE", "?country=DE"],
    ["?country=Germany", ""],
    ["?story=https%3A%2F%2Fexample.com%2Fa", "?story=https%3A%2F%2Fexample.com%2Fa"],
    ["?story=javascript%3Aalert(1)", ""],
  ])("%s -> %s", (input, out) => {
    expect(legacyThreatsSearch(input)).toBe(out);
  });
});
