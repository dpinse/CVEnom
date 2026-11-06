import { cleanup, screen, waitFor } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { useLocation } from "react-router-dom";
import { afterEach, describe, expect, test, vi } from "vitest";
import { authStore } from "./lib/api";
import { __resetBootstrapForTests } from "./lib/useAuth";
import { AppRoutes } from "./routes";
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
  test("public server: a guest sees the dashboard and search", async () => {
    handlers({ publicRead: true });
    guest();
    at("/history");
    expect(await screen.findByRole("heading", { name: "History" })).toBeInTheDocument();
  });
  test("/search?q=log4j&kev=true redirects to /history?q=log4j&kev=true", async () => {
    handlers({ publicRead: true });
    guest();
    at("/search?q=log4j&kev=true");
    expect(await screen.findByRole("heading", { name: "History" })).toBeInTheDocument();
    expect(screen.getByTestId("loc")).toHaveTextContent("/history?q=log4j&kev=true");
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
