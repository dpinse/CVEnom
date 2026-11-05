import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { afterEach, describe, expect, test } from "vitest";
import { authStore } from "../lib/api";
import { at, fill, renderRoute } from "../test/authpages";
import { member, server, setupMsw, signIn } from "../test/shell";
import ChangePassword from "./ChangePassword";

setupMsw();
afterEach(cleanup);

const GOOD = "a brand new passphrase";
const open = () => renderRoute("/account/password", <ChangePassword />, "/account/password");
const submit = () => fireEvent.click(screen.getByRole("button", { name: "Change password" }));
const reply = (status: number, body?: Record<string, unknown>, headers?: Record<string, string>, onBody?: (b: unknown) => void) =>
  server.use(
    http.post("http://localhost/api/auth/password", async ({ request }) => {
      onBody?.(await request.json());
      return status === 204 ? new HttpResponse(null, { status }) : HttpResponse.json(body, { status, headers });
    }),
  );
const fillAll = (cur = "old password!!", n = GOOD, c = GOOD) => {
  fill("Current password", cur);
  fill("New password", n);
  fill("Confirm new password", c);
};

describe("ChangePassword", () => {
  test("autocomplete values, copy, and show toggle", () => {
    signIn(member);
    open();
    expect(screen.getByLabelText("Current password")).toHaveAttribute("autocomplete", "current-password");
    expect(screen.getByLabelText("New password")).toHaveAttribute("autocomplete", "new-password");
    expect(screen.getByLabelText("Confirm new password")).toHaveAttribute("autocomplete", "new-password");
    expect(screen.getByText(/Other devices will be signed out/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /show passwords/i })).toHaveAttribute("aria-pressed", "false");
  });

  test("a short new password is blocked on the client", async () => {
    signIn(member);
    let called = false;
    reply(204, undefined, undefined, () => (called = true));
    open();
    fillAll("old password!!", "short", "short");
    submit();
    expect(await screen.findByText(/at least 12 characters/)).toBeInTheDocument();
    expect(called).toBe(false);
  });

  test("401 says the current password is wrong and does NOT log out", async () => {
    signIn(member);
    let logouts = 0;
    let refreshes = 0;
    authStore.setToken("tok");
    server.use(
      http.post("http://localhost/api/auth/logout", () => {
        logouts++;
        return new HttpResponse(null, { status: 204 });
      }),
      http.post("http://localhost/api/auth/refresh", () => {
        refreshes++;
        return HttpResponse.json({}, { status: 401 });
      }),
    );
    reply(401, { error: "invalid_credentials" });
    open();
    fillAll();
    submit();
    expect(await screen.findByText("Current password is incorrect")).toBeInTheDocument();
    expect(authStore.getSnapshot().user).toEqual(member);
    expect(authStore.getToken()).toBe("tok");
    expect(logouts).toBe(0);
    expect(refreshes).toBe(0);
  });

  test("422 shows the policy message; 429 shows the retry time", async () => {
    signIn(member);
    reply(422, { error: "weak_password" });
    open();
    fillAll();
    submit();
    expect(await screen.findByText(/12 to 256 characters/)).toBeInTheDocument();
    reply(429, {}, { "Retry-After": "30" });
    submit();
    expect(await screen.findByText("Too many attempts — try again in 30 seconds")).toBeInTheDocument();
  });

  test("204 shows a success notice, clears the fields, and sends both passwords", async () => {
    signIn(member);
    let sent: unknown;
    reply(204, undefined, undefined, (b) => (sent = b));
    open();
    fillAll();
    submit();
    expect(await screen.findByText(/Password changed/)).toBeInTheDocument();
    expect(sent).toEqual({ current_password: "old password!!", new_password: GOOD });
    await waitFor(() => expect(screen.getByLabelText("Current password")).toHaveValue(""));
    expect(screen.getByLabelText("New password")).toHaveValue("");
    expect(screen.getByLabelText("Confirm new password")).toHaveValue("");
  });
});

describe("ChangePassword hardening", () => {
  const stage = (statuses: Array<{ status: number; body?: Record<string, unknown> }>, onPost?: () => void) => {
    let i = 0;
    server.use(
      http.post("http://localhost/api/auth/password", () => {
        onPost?.();
        const r = statuses[Math.min(i++, statuses.length - 1)];
        return r.status === 204 ? new HttpResponse(null, { status: 204 }) : HttpResponse.json(r.body ?? {}, { status: r.status });
      }),
    );
  };

  test("a non-credentials 401 refreshes once and retries once", async () => {
    signIn(member);
    authStore.setToken("old");
    let posts = 0;
    let refreshes = 0;
    let logouts = 0;
    server.use(
      http.post("http://localhost/api/auth/refresh", () => {
        refreshes++;
        return HttpResponse.json({ access_token: "new", token_type: "bearer", expires_in: 900 });
      }),
      http.post("http://localhost/api/auth/logout", () => {
        logouts++;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    stage([{ status: 401, body: { error: "invalid_token" } }, { status: 204 }], () => posts++);
    open();
    fillAll();
    submit();
    expect(await screen.findByText(/Password changed/)).toBeInTheDocument();
    expect(posts).toBe(2);
    expect(refreshes).toBe(1);
    expect(logouts).toBe(0);
    expect(authStore.getToken()).toBe("new");
  });

  test("if the refresh fails, go to login with an expiry notice (no logout loop)", async () => {
    signIn(member);
    authStore.setToken("old");
    let logouts = 0;
    let posts = 0;
    server.use(
      http.post("http://localhost/api/auth/refresh", () => HttpResponse.json({}, { status: 401 })),
      http.post("http://localhost/api/auth/logout", () => {
        logouts++;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    stage([{ status: 401, body: { error: "invalid_token" } }], () => posts++);
    open();
    fillAll();
    submit();
    await waitFor(() => expect(at()).toBe("/login"));
    expect(screen.getByTestId("state").textContent).toContain("session-expired");
    expect(posts).toBe(1);
    expect(logouts).toBe(0);
  });

  test("only weak_password shows the policy; another 422 is generic", async () => {
    signIn(member);
    stage([{ status: 422, body: { error: "validation_error" } }]);
    open();
    fillAll();
    submit();
    expect(await screen.findByText("Couldn't update password")).toBeInTheDocument();
    expect(screen.queryByText(/12 to 256/)).not.toBeInTheDocument();
  });

  test("a 300-char new password is reported and not submitted; inputs allow 1024", async () => {
    signIn(member);
    let called = false;
    stage([{ status: 204 }], () => (called = true));
    open();
    expect(screen.getByLabelText("New password")).toHaveAttribute("maxlength", "1024");
    expect(screen.getByLabelText("Confirm new password")).toHaveAttribute("maxlength", "1024");
    const long = "a".repeat(300);
    fillAll("old password!!", long, long);
    submit();
    expect(await screen.findByText(/at most 256/)).toBeInTheDocument();
    expect(called).toBe(false);
  });

  test("shows the 12-character rule linked with aria-describedby", () => {
    signIn(member);
    open();
    const hint = screen.getByText(/At least 12 characters/);
    expect(screen.getByLabelText("New password").getAttribute("aria-describedby")).toBe(hint.id);
  });
});
