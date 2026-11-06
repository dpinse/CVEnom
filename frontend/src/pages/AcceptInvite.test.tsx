import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { Route, Routes, useLocation, useNavigationType } from "react-router-dom";
import { afterEach, describe, expect, test } from "vitest";
import { at, fill, loginOk } from "../test/authpages";
import { Where } from "../test/authpages";
import { authStore } from "../lib/api";
import { admin, guest, member, renderAt, server, setupMsw, signIn } from "../test/shell";
import AcceptInvite from "./AcceptInvite";
import Login from "./Login";

setupMsw();
afterEach(cleanup);

const TOKEN = "s3cret-token-value";

/** Where the router is, fragment included (the token must not stay in it). */
function HashProbe() {
  const l = useLocation();
  const nav = useNavigationType();
  return <p data-testid="href">{`${nav} ${l.pathname}${l.search}${l.hash}`}</p>;
}
const GOOD = "a long enough pass";

function app(path: string) {
  return renderAt(
    <Routes>
      <Route
        path="/invite"
        element={
          <>
            <AcceptInvite mode="invite" />
            <HashProbe />
          </>
        }
      />
      <Route
        path="/reset"
        element={
          <>
            <AcceptInvite mode="reset" />
            <HashProbe />
          </>
        }
      />
      <Route
        path="/login"
        element={
          <>
            <Login />
            <Where />
          </>
        }
      />
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
    app(`/invite#${TOKEN}`);
    const pw = screen.getByLabelText("New password");
    const cf = screen.getByLabelText("Confirm password");
    expect(pw).toHaveAttribute("autocomplete", "new-password");
    expect(cf).toHaveAttribute("autocomplete", "new-password");
    expect(pw).toHaveAttribute("maxlength", "1024");
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
    app(`/invite#${TOKEN}`);
    fill("New password", "short");
    fill("Confirm password", "short");
    submit();
    expect(await screen.findByText(/at least 12 characters/)).toBeInTheDocument();
    expect(called).toBe(false);
  });

  test("mismatch and whitespace-only are blocked", async () => {
    guest();
    app(`/invite#${TOKEN}`);
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
    app(`/invite#${TOKEN}`);
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
    server.use(
      http.post("http://localhost/api/auth/login", () =>
        HttpResponse.json({ error: "invalid_credentials" }, { status: 401 }),
      ),
    );
    app(`/invite#${TOKEN}`);
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
    app(`/reset#${TOKEN}`);
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
    app(`/invite#${TOKEN}`);
    fill("New password", GOOD);
    fill("Confirm password", GOOD);
    submit();
    expect(await screen.findByText("This link is invalid or expired")).toBeInTheDocument();
  });

  test("422 weak_password shows the policy message; 429 the retry time", async () => {
    guest();
    accept(422, { error: "weak_password" });
    app(`/invite#${TOKEN}`);
    fill("New password", GOOD);
    fill("Confirm password", GOOD);
    submit();
    expect(await screen.findByText(/12 to 256 characters/)).toBeInTheDocument();
    server.use(
      http.post("http://localhost/api/auth/invites/accept", () =>
        HttpResponse.json({}, { status: 429, headers: { "Retry-After": "9" } }),
      ),
    );
    submit();
    expect(await screen.findByText("Too many attempts — try again in 9 seconds")).toBeInTheDocument();
  });

  test("the token never reaches web storage, and the page has no external links", async () => {
    guest();
    accept(400, { error: "invalid_invite" });
    const { container } = app(`/invite#${TOKEN}`);
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
    const { unmount } = app(`/invite#${TOKEN}`);
    unmount();
    expect(document.querySelector('meta[name="referrer"]')).toBeNull();
  });
});

describe("AcceptInvite hardening", () => {
  const logoutCounter = () => {
    let n = 0;
    server.use(
      http.post("http://localhost/api/auth/logout", () => {
        n++;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    return () => n;
  };
  const go = async () => {
    fill("New password", GOOD);
    fill("Confirm password", GOOD);
    submit();
  };

  test("success REPLACES the history entry (invite and reset)", async () => {
    guest();
    accept(201, { id: 5, email: "new@example.com", role: "member" });
    loginOk();
    app(`/invite#${TOKEN}`);
    await go();
    await waitFor(() => expect(at()).toBe("/"));
    expect(screen.getByTestId("navtype")).toHaveTextContent("REPLACE");
    cleanup();
    authStore.clear();
    guest();
    accept(201, { id: 5, email: "new@example.com", role: "member" });
    logoutCounter();
    app(`/reset#${TOKEN}`);
    await go();
    await waitFor(() => expect(at()).toBe("/login"));
    expect(screen.getByTestId("navtype")).toHaveTextContent("REPLACE");
  });

  test("a non-weak_password 422 means the link is invalid", async () => {
    guest();
    accept(422, { error: "validation_error" });
    app(`/invite#${TOKEN}`);
    await go();
    expect(await screen.findByText("This link is invalid or expired")).toBeInTheDocument();
  });

  test("a 300-char password is reported over-256 and never submitted; inputs allow 1024", async () => {
    guest();
    let called = false;
    accept(201, {}, () => (called = true));
    app(`/invite#${TOKEN}`);
    expect(screen.getByLabelText("New password")).toHaveAttribute("maxlength", "1024");
    expect(screen.getByLabelText("Confirm password")).toHaveAttribute("maxlength", "1024");
    const long = "a".repeat(300);
    fill("New password", long);
    fill("Confirm password", long);
    submit();
    expect(await screen.findByText(/at most 256/)).toBeInTheDocument();
    expect(called).toBe(false);
  });

  test("shows the 12-character rule linked with aria-describedby", () => {
    guest();
    app(`/invite#${TOKEN}`);
    const pw = screen.getByLabelText("New password");
    const hint = screen.getByText(/At least 12 characters/);
    expect(pw.getAttribute("aria-describedby")).toBe(hint.id);
  });

  test("reset with no user signed in logs out and goes to /login", async () => {
    guest();
    accept(201, { id: 2, email: "member@example.com", role: "member" });
    const outs = logoutCounter();
    app(`/reset#${TOKEN}`);
    await go();
    await waitFor(() => expect(at()).toBe("/login"));
    expect(outs()).toBe(1);
  });

  test("reset for the same signed-in user (case-insensitive) logs out", async () => {
    signIn(member);
    accept(201, { id: 2, email: "MEMBER@Example.com", role: "member" });
    const outs = logoutCounter();
    app(`/reset#${TOKEN}`);
    await go();
    await waitFor(() => expect(at()).toBe("/login"));
    expect(outs()).toBe(1);
    expect(await screen.findByText("Password reset — please sign in")).toBeInTheDocument();
  });

  test("reset for a DIFFERENT signed-in user does not log them out", async () => {
    signIn(admin);
    accept(201, { id: 2, email: "member@example.com", role: "member" });
    const outs = logoutCounter();
    app(`/reset#${TOKEN}`);
    await go();
    await waitFor(() => expect(at()).toBe("/"));
    expect(outs()).toBe(0);
    expect(authStore.getSnapshot().user).toEqual(admin);
    expect(screen.getByTestId("navtype")).toHaveTextContent("REPLACE");
    expect(screen.getByTestId("state").textContent).toContain("member@example.com");
  });
});

describe("M2: the token travels in the URL fragment", () => {
  test("the page reads the fragment, strips it from history (replace) and posts the token", async () => {
    guest();
    let body: unknown;
    accept(400, { error: "invalid_invite" }, (b) => (body = b));
    app(`/invite#${TOKEN}`);
    await waitFor(() => expect(screen.getByTestId("href")).toHaveTextContent(/^REPLACE \/invite$/));
    fill("New password", GOOD);
    fill("Confirm password", GOOD);
    submit();
    await screen.findByText("This link is invalid or expired");
    expect(body).toEqual({ token: TOKEN, password: GOOD });
  });

  test.each(["/invite", "/invite#", "/reset", "/reset#"])(
    "%s (no token) shows the invalid-link state and never posts",
    async (path) => {
      guest();
      let called = false;
      accept(201, {}, () => (called = true));
      app(path);
      expect(await screen.findByText("This link is invalid or expired")).toBeInTheDocument();
      fill("New password", GOOD);
      fill("Confirm password", GOOD);
      submit();
      await new Promise((r) => setTimeout(r, 20));
      expect(called).toBe(false);
    },
  );

  test("the old /invite/<token> path form is not a route", async () => {
    guest();
    app(`/invite/${TOKEN}`);
    expect(screen.queryByRole("heading", { name: /accept invite/i })).toBeNull();
  });
});
