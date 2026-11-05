import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { afterEach, describe, expect, test, vi } from "vitest";
import { at, fill, loginOk, renderRoute } from "../test/authpages";
import { guest, member, server, setupMsw, signIn } from "../test/shell";
import Login from "./Login";

setupMsw();
afterEach(cleanup);

const open = (url = "/login") => renderRoute("/login", <Login />, url);
const submit = () => fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
const fail = (status: number, body: Record<string, unknown>, headers?: Record<string, string>) =>
  server.use(http.post("http://localhost/api/auth/login", () => HttpResponse.json(body, { status, headers })));

describe("Login form", () => {
  test("labels, types, autocomplete, and length limits", () => {
    guest();
    open();
    const email = screen.getByLabelText("Email");
    const pw = screen.getByLabelText("Password");
    expect(email).toHaveAttribute("type", "email");
    expect(email).toHaveAttribute("autocomplete", "username");
    expect(email).toHaveAttribute("maxlength", "320");
    expect(pw).toHaveAttribute("type", "password");
    expect(pw).toHaveAttribute("autocomplete", "current-password");
    expect(pw).toHaveAttribute("maxlength", "1024");
  });

  test("unknown user and wrong password show the identical message and clear the password", async () => {
    guest();
    open();
    const texts: string[] = [];
    for (const who of ["nobody@example.com", "member@example.com"]) {
      fail(401, { error: "invalid_credentials" });
      fill("Email", who);
      fill("Password", "hunter2hunter2");
      submit();
      await waitFor(() => {
        expect(screen.getByText("Email or password is incorrect")).toBeInTheDocument();
        expect(screen.getByLabelText("Password")).toHaveValue("");
        expect(screen.getByRole("button", { name: "Sign in" })).toBeEnabled();
      });
      const alert = screen.getByText("Email or password is incorrect");
      texts.push(alert.textContent ?? "");
      expect(document.activeElement).toBe(alert.closest("[aria-live]"));
    }
    expect(texts[0]).toBe(texts[1]);
    expect(screen.getByText("Email or password is incorrect").closest("[aria-live]")).toHaveAttribute("aria-live", "assertive");
  });

  test("429 shows the retry time", async () => {
    guest();
    open();
    fail(429, { error: "rate_limited" }, { "Retry-After": "42" });
    fill("Email", "a@example.com");
    fill("Password", "whatever-pass");
    submit();
    expect(await screen.findByText("Too many attempts — try again in 42 seconds")).toBeInTheDocument();
  });

  test("a network error shows a generic retry message", async () => {
    guest();
    open();
    server.use(http.post("http://localhost/api/auth/login", () => HttpResponse.error()));
    fill("Email", "a@example.com");
    fill("Password", "whatever-pass");
    submit();
    expect(await screen.findByText(/could not reach the server.*try again/i)).toBeInTheDocument();
  });

  test("submit is disabled while pending", async () => {
    guest();
    open();
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    server.use(
      http.post("http://localhost/api/auth/login", async () => {
        await gate;
        return HttpResponse.json({ error: "invalid_credentials" }, { status: 401 });
      }),
    );
    fill("Email", "a@example.com");
    fill("Password", "whatever-pass");
    submit();
    await waitFor(() => expect(screen.getByRole("button", { name: /signing in/i })).toBeDisabled());
    release();
    await screen.findByText("Email or password is incorrect");
  });

  test("Enter in the form submits (native form)", async () => {
    guest();
    open();
    loginOk();
    fill("Email", "member@example.com");
    fill("Password", "correct horse battery");
    fireEvent.submit(screen.getByLabelText("Password").closest("form")!);
    await waitFor(() => expect(at()).toBe("/"));
  });

  test("never logs the password", async () => {
    guest();
    const spies = (["log", "error", "warn", "info", "debug"] as const).map((m) => vi.spyOn(console, m));
    open();
    fail(401, { error: "invalid_credentials" });
    fill("Email", "a@example.com");
    fill("Password", "super-secret-pass");
    submit();
    await screen.findByText("Email or password is incorrect");
    for (const s of spies) expect(JSON.stringify(s.mock.calls)).not.toContain("super-secret-pass");
    vi.restoreAllMocks();
  });
});

describe("Login redirects", () => {
  test("success navigates to next", async () => {
    guest();
    open("/login?next=%2Fsearch%3Fq%3Dx");
    loginOk();
    fill("Email", "member@example.com");
    fill("Password", "correct horse battery");
    submit();
    await waitFor(() => expect(at()).toBe("/search?q=x"));
  });

  test("an evil next falls back to /", async () => {
    guest();
    open("/login?next=%2F%2Fevil.com");
    loginOk();
    fill("Email", "member@example.com");
    fill("Password", "correct horse battery");
    submit();
    await waitFor(() => expect(at()).toBe("/"));
  });

  test("already signed in redirects to next, or /", async () => {
    signIn(member);
    open("/login?next=%2Fsearch");
    await waitFor(() => expect(at()).toBe("/search"));
    cleanup();
    open("/login");
    await waitFor(() => expect(at()).toBe("/"));
  });

  test("shows the form (not a redirect) for a guest only after ready", () => {
    open();
    expect(screen.queryByLabelText("Email")).not.toBeInTheDocument();
  });
});
