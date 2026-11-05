import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, test } from "vitest";
import { at, fill, loginOk } from "../test/authpages";
import { Where } from "../test/authpages";
import { authStore } from "../lib/api";
import { guest, renderAt, server, setupMsw } from "../test/shell";
import AcceptInvite from "./AcceptInvite";
import Login from "./Login";

setupMsw();
afterEach(cleanup);

const TOKEN = "s3cret-token-value";
const GOOD = "a long enough pass";

function app(path: string) {
  return renderAt(
    <Routes>
      <Route path="/invite/:token" element={<AcceptInvite mode="invite" />} />
      <Route path="/reset/:token" element={<AcceptInvite mode="reset" />} />
      <Route path="/login" element={<><Login /><Where /></>} />
      <Route path="*" element={<Where />} />
    </Routes>,
    path,
  );
}
const submit = () => fireEvent.click(screen.getByRole("button", { name: /create account|set new password/i }));
const accept = (status: number, body: Record<string, unknown>, onBody?: (b: unknown) => void) =>
  server.use(
    http.post("http://localhost/api/auth/invites/accept", async ({ request }) => {
      onBody?.(await request.json());
      return HttpResponse.json(body, { status });
    }),
  );

describe("AcceptInvite form", () => {
  test("new-password autocomplete, labels, show toggle", () => {
    guest();
    app(`/invite/${TOKEN}`);
    const pw = screen.getByLabelText("New password");
    const cf = screen.getByLabelText("Confirm password");
    expect(pw).toHaveAttribute("autocomplete", "new-password");
    expect(cf).toHaveAttribute("autocomplete", "new-password");
    expect(pw).toHaveAttribute("maxlength", "256");
    const toggle = screen.getByRole("button", { name: /show password/i });
    expect(toggle).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-pressed", "true");
    expect(pw).toHaveAttribute("type", "text");
    expect(cf).toHaveAttribute("type", "text");
  });

  test("a short password is blocked on the client (no request)", async () => {
    guest();
    let called = false;
    accept(201, {}, () => (called = true));
    app(`/invite/${TOKEN}`);
    fill("New password", "short");
    fill("Confirm password", "short");
    submit();
    expect(await screen.findByText(/at least 12 characters/)).toBeInTheDocument();
    expect(called).toBe(false);
  });

  test("mismatch and whitespace-only are blocked", async () => {
    guest();
    app(`/invite/${TOKEN}`);
    fill("New password", GOOD);
    fill("Confirm password", GOOD + "x");
    submit();
    expect(await screen.findByText("Passwords do not match")).toBeInTheDocument();
    fill("New password", " ".repeat(14));
    fill("Confirm password", " ".repeat(14));
    submit();
    expect(await screen.findByText(/only whitespace/)).toBeInTheDocument();
  });

  test("invite mode: posts token in body, auto-logs in, goes to / with token stripped from history", async () => {
    guest();
    let sent: unknown;
    accept(201, { id: 5, email: "new@example.com", role: "member" }, (b) => (sent = b));
    let loginBody: unknown;
    loginOk();
    server.use(
      http.post("http://localhost/api/auth/login", async ({ request }) => {
        loginBody = await request.json();
        return HttpResponse.json({ access_token: "tok", token_type: "bearer", expires_in: 900 });
      }),
    );
    app(`/invite/${TOKEN}`);
    fill("New password", GOOD);
    fill("Confirm password", GOOD);
    submit();
    await waitFor(() => expect(at()).toBe("/"));
    expect(sent).toEqual({ token: TOKEN, password: GOOD });
    expect(loginBody).toEqual({ email: "new@example.com", password: GOOD });
    expect(authStore.getSnapshot().user).not.toBeNull();
    expect(at()).not.toContain(TOKEN);
  });

  test("invite mode: failed auto-login goes to /login with a notice", async () => {
    guest();
    accept(201, { id: 5, email: "new@example.com", role: "member" });
    server.use(http.post("http://localhost/api/auth/login", () => HttpResponse.json({ error: "invalid_credentials" }, { status: 401 })));
    app(`/invite/${TOKEN}`);
    fill("New password", GOOD);
    fill("Confirm password", GOOD);
    submit();
    expect(await screen.findByText("Account created — please sign in")).toBeInTheDocument();
    expect(at()).toBe("/login");
  });

  test("reset mode: no auto-login, logs out, goes to /login with a notice", async () => {
    guest();
    accept(201, { id: 2, email: "member@example.com", role: "member" });
    let loggedIn = false;
    let loggedOut = false;
    server.use(
      http.post("http://localhost/api/auth/login", () => {
        loggedIn = true;
        return HttpResponse.json({}, { status: 500 });
      }),
      http.post("http://localhost/api/auth/logout", () => {
        loggedOut = true;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    app(`/reset/${TOKEN}`);
    expect(screen.getByRole("heading", { name: /reset password/i })).toBeInTheDocument();
    fill("New password", GOOD);
    fill("Confirm password", GOOD);
    submit();
    expect(await screen.findByText("Password reset — please sign in")).toBeInTheDocument();
    expect(at()).toBe("/login");
    expect(loggedIn).toBe(false);
    expect(loggedOut).toBe(true);
  });

  test("400 shows the invalid link message", async () => {
    guest();
    accept(400, { error: "invalid_invite" });
    app(`/invite/${TOKEN}`);
    fill("New password", GOOD);
    fill("Confirm password", GOOD);
    submit();
    expect(await screen.findByText("This link is invalid or expired")).toBeInTheDocument();
  });

  test("422 weak_password shows the policy message; 429 the retry time", async () => {
    guest();
    accept(422, { error: "weak_password" });
    app(`/invite/${TOKEN}`);
    fill("New password", GOOD);
    fill("Confirm password", GOOD);
    submit();
    expect(await screen.findByText(/12 to 256 characters/)).toBeInTheDocument();
    server.use(http.post("http://localhost/api/auth/invites/accept", () => HttpResponse.json({}, { status: 429, headers: { "Retry-After": "9" } })));
    submit();
    expect(await screen.findByText("Too many attempts — try again in 9 seconds")).toBeInTheDocument();
  });

  test("the token never reaches web storage, and the page has no external links", async () => {
    guest();
    accept(400, { error: "invalid_invite" });
    const { container } = app(`/invite/${TOKEN}`);
    fill("New password", GOOD);
    fill("Confirm password", GOOD);
    submit();
    await screen.findByText("This link is invalid or expired");
    expect(JSON.stringify({ ...localStorage })).not.toContain(TOKEN);
    expect(JSON.stringify({ ...sessionStorage })).not.toContain(TOKEN);
    expect(container.querySelectorAll("a[href^='http'], img, script, link")).toHaveLength(0);
    expect(document.querySelector('meta[name="referrer"]')).toHaveAttribute("content", "no-referrer");
  });

  test("the referrer meta is removed when leaving the page", () => {
    guest();
    const { unmount } = app(`/invite/${TOKEN}`);
    unmount();
    expect(document.querySelector('meta[name="referrer"]')).toBeNull();
  });
});
