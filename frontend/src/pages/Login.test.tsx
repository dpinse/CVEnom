import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { afterEach, describe, expect, test, vi } from "vitest";
import { CODES, SECRET, at, fill, loginOk, passCode, renderRoute } from "../test/authpages";
import { authStore } from "../lib/api";
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
      await waitFor(() => expect(document.activeElement).toBe(alert.closest("[aria-live]")));
    }
    expect(texts[0]).toBe(texts[1]);
    expect(screen.getByText("Email or password is incorrect").closest("[aria-live]")).toHaveAttribute(
      "aria-live",
      "assertive",
    );
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
    await passCode();
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
    await passCode();
    await waitFor(() => expect(at()).toBe("/search?q=x"));
  });

  test("an evil next falls back to /", async () => {
    guest();
    open("/login?next=%2F%2Fevil.com");
    loginOk();
    fill("Email", "member@example.com");
    fill("Password", "correct horse battery");
    submit();
    await passCode();
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

const verifyFails = (status = 401, body: Record<string, unknown> = { error: "invalid_mfa" }) =>
  server.use(http.post("http://localhost/api/auth/mfa/verify", () => HttpResponse.json(body, { status })));

async function toCodeStep(enroll = false) {
  guest();
  open();
  loginOk({ enroll });
  fill("Email", "member@example.com");
  fill("Password", "correct horse battery");
  submit();
}

describe("Login second factor", () => {
  test("the password step creates no session: a code step follows, the password is dropped", async () => {
    await toCodeStep();
    const code = await screen.findByLabelText(/authentication code/i, { selector: "input" });
    expect(code).toHaveAttribute("autocomplete", "one-time-code");
    expect(code).toHaveAttribute("maxlength", "64");
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
    expect(screen.getByText(/recovery code/i)).toBeInTheDocument();
    expect(authStore.getToken()).toBeNull();
  });

  test("the ticket and code are posted; success signs in and navigates", async () => {
    let body: unknown;
    await toCodeStep();
    server.use(
      http.post("http://localhost/api/auth/mfa/verify", async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ access_token: "tok", token_type: "bearer", expires_in: 900 });
      }),
    );
    await passCode(" 123456 ");
    await waitFor(() => expect(at()).toBe("/"));
    expect(body).toEqual({ ticket: "tk-1", code: "123456" });
  });

  test("a recovery code is accepted in the same field", async () => {
    let body: unknown;
    await toCodeStep();
    server.use(
      http.post("http://localhost/api/auth/mfa/verify", async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ access_token: "tok", token_type: "bearer", expires_in: 900 });
      }),
    );
    await passCode("abcd-efgh-jkmn-pqrs");
    await waitFor(() => expect(at()).toBe("/"));
    expect(body).toEqual({ ticket: "tk-1", code: "abcd-efgh-jkmn-pqrs" });
  });

  test("a rejected code shows one generic message, clears the field, and keeps the code step", async () => {
    await toCodeStep();
    verifyFails();
    await passCode("000000");
    expect(await screen.findByText(/code was not accepted/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/authentication code/i, { selector: "input" })).toHaveValue("");
    expect(authStore.getToken()).toBeNull();
  });

  test("Start over returns to the password step", async () => {
    await toCodeStep();
    await screen.findByLabelText(/authentication code/i, { selector: "input" });
    fireEvent.click(screen.getByRole("button", { name: "Start over" }));
    expect(await screen.findByLabelText("Password")).toHaveValue("");
  });

  test("429 on the code step shows the retry time", async () => {
    await toCodeStep();
    server.use(
      http.post("http://localhost/api/auth/mfa/verify", () =>
        HttpResponse.json({ error: "rate_limited" }, { status: 429, headers: { "Retry-After": "600" } }),
      ),
    );
    await passCode("000000");
    expect(await screen.findByText(/too many attempts/i)).toBeInTheDocument();
  });

  test("never logs the code or ticket", async () => {
    const spies = (["log", "error", "warn", "info", "debug"] as const).map((m) => vi.spyOn(console, m));
    await toCodeStep();
    verifyFails();
    await passCode("918273");
    await screen.findByText(/code was not accepted/i);
    for (const sp of spies) {
      const calls = JSON.stringify(sp.mock.calls);
      expect(calls).not.toContain("918273");
      expect(calls).not.toContain("tk-1");
    }
    vi.restoreAllMocks();
  });
});

describe("Login enrollment (account without MFA)", () => {
  test("shows a local QR, the secret for manual entry, then the recovery codes once", async () => {
    await toCodeStep(true);
    expect(await screen.findByRole("heading", { name: /set up two-factor/i })).toBeInTheDocument();
    const qr = await screen.findByRole("img", { name: /qr code/i });
    expect(qr.tagName.toLowerCase()).toBe("svg");
    expect(qr.querySelector("path")).not.toBeNull();
    expect(qr.outerHTML).not.toMatch(/https?:|style=/);
    expect(screen.getByText(SECRET.replace(/(.{4})/g, "$1 ").trim())).toBeInTheDocument();
    expect(authStore.getToken()).toBeNull();
    await passCode();
    const panel = await screen.findByRole("region", { name: /recovery codes/i });
    for (const c of CODES) expect(panel).toHaveTextContent(c);
    expect(panel).toHaveTextContent(/won.t be shown again/i);
    // the enrollment secret is gone once enrolled
    expect(screen.queryByText(SECRET.replace(/(.{4})/g, "$1 ").trim())).not.toBeInTheDocument();
    // still on the sign-in page (no redirect away from the one-time codes)
    expect(screen.queryByTestId("at")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    await waitFor(() => expect(at()).toBe("/"));
  });

  test("a wrong first code keeps the enrollment step", async () => {
    await toCodeStep(true);
    await screen.findByRole("img", { name: /qr code/i });
    server.use(
      http.post("http://localhost/api/auth/mfa/enroll/finish", () =>
        HttpResponse.json({ error: "invalid_mfa" }, { status: 401 }),
      ),
    );
    await passCode("000000");
    expect(await screen.findByText(/code was not accepted/i)).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /qr code/i })).toBeInTheDocument();
  });

  test("secret, ticket and recovery codes never reach web storage or the URL", async () => {
    await toCodeStep(true);
    await screen.findByRole("img", { name: /qr code/i });
    await passCode();
    await screen.findByRole("region", { name: /recovery codes/i });
    const needles = [SECRET, "tk-1", ...CODES];
    for (const st of [localStorage, sessionStorage])
      for (let i = 0; i < st.length; i++) {
        const k = st.key(i) as string;
        for (const n of needles) expect(k + (st.getItem(k) ?? "")).not.toContain(n);
      }
    for (const n of needles) expect(window.location.href + document.title).not.toContain(n);
  });
});
