import { QueryClient } from "@tanstack/react-query";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, test, vi } from "vitest";
import { createQueryClient } from "../lib/queries";
import { member, renderAt, server, setupMsw, signIn } from "../test/shell";
import TwoFactor from "./TwoFactor";

setupMsw();
afterEach(cleanup);

const A = "http://localhost/api/auth";
const NEW = Array.from({ length: 10 }, (_, i) => `new${i}-zzzz-yyyy-xxxx`);

function open(qc: QueryClient = createQueryClient()) {
  signIn(member);
  renderAt(
    <Routes>
      <Route path="/account/two-factor" element={<TwoFactor />} />
    </Routes>,
    "/account/two-factor",
    qc,
  );
  return qc;
}
const status = (remaining: number) =>
  server.use(
    http.get(`${A}/mfa`, () =>
      HttpResponse.json({ enabled: true, enrolled_at: "2026-11-01T00:00:00Z", recovery_codes_remaining: remaining }),
    ),
  );
const cacheDump = (qc: QueryClient) =>
  JSON.stringify([
    qc
      .getQueryCache()
      .getAll()
      .map((q) => ({ k: q.queryKey, d: q.state.data })),
    qc
      .getMutationCache()
      .getAll()
      .map((m) => ({ v: m.state.variables, d: m.state.data })),
  ]);
const regenerate = (code: string) => {
  fireEvent.change(screen.getByLabelText(/authentication code/i, { selector: "input" }), { target: { value: code } });
  fireEvent.click(screen.getByRole("button", { name: /new recovery codes/i }));
};

describe("Two-factor account page", () => {
  test("shows the status and the recovery codes remaining", async () => {
    status(7);
    open();
    expect(await screen.findByRole("heading", { name: "Two-factor authentication" })).toBeInTheDocument();
    expect(await screen.findByText(/^On/)).toBeInTheDocument();
    expect(screen.getByText(/7 of 10 recovery codes left/)).toBeInTheDocument();
  });

  test("warns when few recovery codes are left", async () => {
    status(2);
    open();
    expect(await screen.findByText(/running low/i)).toBeInTheDocument();
  });

  test("regenerating needs a current code; new codes appear once and never reach the cache or storage", async () => {
    status(3);
    let body: unknown;
    server.use(
      http.post(`${A}/mfa/recovery-codes`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ recovery_codes: NEW });
      }),
    );
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const qc = open();
    await screen.findByText(/3 of 10/);
    regenerate(" 123456 ");
    const panel = await screen.findByRole("region", { name: /recovery codes/i });
    expect(body).toEqual({ code: "123456" });
    for (const c of NEW) expect(within(panel).getByText(c)).toBeInTheDocument();
    expect(within(panel).getByText(/won.t be shown again/i)).toBeInTheDocument();
    expect(cacheDump(qc)).not.toContain(NEW[0]);
    // the form (and the code typed into it) is gone while the codes are on screen
    expect(screen.queryByLabelText(/authentication code/i, { selector: "input" })).toBeNull();
    fireEvent.click(within(panel).getByRole("button", { name: "Done" }));
    expect(screen.getByLabelText(/authentication code/i, { selector: "input" })).toHaveValue("");
    expect(document.body.innerHTML).not.toContain(NEW[0]);
    expect(cacheDump(qc)).not.toContain(NEW[0]);
    expect(JSON.stringify([localStorage, sessionStorage, location.href])).not.toContain(NEW[0]);
    for (const c of setItem.mock.calls) expect(c.join("|")).not.toContain(NEW[0]);
    setItem.mockRestore();
  });

  test("a wrong code shows a message and no codes", async () => {
    status(10);
    server.use(
      http.post(`${A}/mfa/recovery-codes`, () => HttpResponse.json({ error: "invalid_code" }, { status: 403 })),
    );
    open();
    await screen.findByText(/10 of 10/);
    regenerate("000000");
    expect(await screen.findByText(/code was not accepted/i)).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: /recovery codes/i })).toBeNull();
  });

  test("an empty code is not sent", async () => {
    status(10);
    let called = false;
    server.use(
      http.post(`${A}/mfa/recovery-codes`, () => {
        called = true;
        return HttpResponse.json({ recovery_codes: NEW });
      }),
    );
    open();
    await screen.findByText(/10 of 10/);
    regenerate("   ");
    await waitFor(() => expect(screen.getByText(/enter the 6-digit code/i)).toBeInTheDocument());
    expect(called).toBe(false);
  });
});
