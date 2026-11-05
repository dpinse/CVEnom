import { QueryClient } from "@tanstack/react-query";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { createQueryClient } from "../lib/queries";
import type { UserAdmin } from "../lib/types";
import { admin, renderAt, server, setupMsw, signIn } from "../test/shell";
import AdminUsers from "./AdminUsers";

setupMsw();
afterEach(cleanup);

const A = "http://localhost/api/auth";
const TOKEN = "RSTTOK-0123456789abcdef";
const mk = (o: Partial<UserAdmin>): UserAdmin => ({
  id: 2,
  email: "bob@example.com",
  role: "member",
  is_active: true,
  created_at: "2026-10-01T00:00:00Z",
  active_sessions: 2,
  ...o,
});
let users: UserAdmin[] = [];
let listCalls = 0;
const calls: { method: string; path: string; body?: unknown }[] = [];
async function rec(request: Request) {
  const t = await request.text();
  calls.push({ method: request.method, path: new URL(request.url).pathname, body: t ? JSON.parse(t) : undefined });
}
function mock() {
  calls.length = 0;
  listCalls = 0;
  server.use(
    http.get(`${A}/users`, () => (listCalls++, HttpResponse.json(users))),
    http.get(`${A}/invites`, () => HttpResponse.json([])),
  );
}
function open(qc: QueryClient = createQueryClient()) {
  renderAt(
    <Routes>
      <Route path="/admin/users" element={<AdminUsers />} />
    </Routes>,
    "/admin/users",
    qc,
  );
  return qc;
}
const rowOf = async (email: string) => (await screen.findByText(email)).closest("tr")!;
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

beforeEach(() => {
  signIn(admin);
  users = [
    mk({ id: 1, email: "admin@example.com", role: "admin" }),
    mk({}),
    mk({ id: 3, email: "carol@example.com", role: "admin" }),
    mk({ id: 4, email: "dan@example.com", is_active: false }),
  ];
});

describe("AdminUsers", () => {
  test("lists email, role, active, sessions and created; hostile email is text", async () => {
    users = [mk({ email: "<img src=x onerror=alert(1)>@example.com" })];
    mock();
    open();
    const row = await rowOf("<img src=x onerror=alert(1)>@example.com");
    expect(document.querySelector("img")).toBeNull();
    expect(within(row).getByRole("combobox")).toHaveValue("member");
    expect(within(row).getByRole("switch")).toBeChecked();
    expect(within(row).getByText("2")).toBeInTheDocument();
    expect(within(row).getByText(/month|day/)).toBeInTheDocument();
  });

  test("the current user's own row has its controls disabled", async () => {
    mock();
    open();
    const me = await rowOf("admin@example.com");
    expect(within(me).getByRole("combobox")).toBeDisabled();
    expect(within(me).getByRole("switch")).toBeDisabled();
    expect(within(me).getByRole("button", { name: /Reset password/ })).toBeDisabled();
    expect(within(me).getByRole("button", { name: /Revoke sessions/ })).toBeDisabled();
    const bob = await rowOf("bob@example.com");
    expect(within(bob).getByRole("combobox")).toBeEnabled();
    expect(within(bob).getByRole("switch")).toBeEnabled();
  });

  test("promoting applies immediately; demoting asks in-page first", async () => {
    mock();
    const confirm = vi.spyOn(window, "confirm");
    server.use(
      http.patch(`${A}/users/:id`, async ({ request, params }) => {
        await rec(request);
        const b = calls[calls.length - 1].body as { role: "admin" | "member" };
        users = users.map((u) => (String(u.id) === params.id ? { ...u, role: b.role } : u));
        return HttpResponse.json(users.find((u) => String(u.id) === params.id));
      }),
    );
    open();
    const bob = await rowOf("bob@example.com");
    fireEvent.change(within(bob).getByRole("combobox"), { target: { value: "admin" } });
    await waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0]).toMatchObject({ method: "PATCH", path: "/api/auth/users/2", body: { role: "admin" } });

    const carol = await rowOf("carol@example.com");
    fireEvent.change(within(carol).getByRole("combobox"), { target: { value: "member" } });
    expect(calls).toHaveLength(1);
    expect(within(carol).getByText(/from admin to member/)).toBeInTheDocument();
    fireEvent.click(within(carol).getByRole("button", { name: "Cancel" }));
    expect(calls).toHaveLength(1);
    expect(within(await rowOf("carol@example.com")).getByRole("combobox")).toHaveValue("admin");
    fireEvent.change(within(carol).getByRole("combobox"), { target: { value: "member" } });
    fireEvent.click(within(carol).getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(calls).toHaveLength(2));
    expect(calls[1]).toMatchObject({ path: "/api/auth/users/3", body: { role: "member" } });
    expect(confirm).not.toHaveBeenCalled();
    confirm.mockRestore();
  });

  test("deactivate confirms with 'Signs them out everywhere'; reactivate confirms too; list refetches", async () => {
    mock();
    server.use(
      http.patch(`${A}/users/:id`, async ({ request }) => {
        await rec(request);
        return HttpResponse.json(users[1]);
      }),
    );
    open();
    const bob = await rowOf("bob@example.com");
    fireEvent.click(within(bob).getByRole("switch"));
    expect(within(bob).getByText(/Signs them out everywhere/)).toBeInTheDocument();
    expect(calls).toEqual([]);
    fireEvent.click(within(bob).getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0].body).toEqual({ is_active: false });
    await waitFor(() => expect(listCalls).toBeGreaterThanOrEqual(2));

    const dan = await rowOf("dan@example.com");
    fireEvent.click(within(dan).getByRole("switch"));
    expect(within(dan).getByText(/Reactivate/)).toBeInTheDocument();
    fireEvent.click(within(dan).getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(calls).toHaveLength(2));
    expect(calls[1].body).toEqual({ is_active: true });
  });

  test("revoke sessions confirms in-page then POSTs", async () => {
    mock();
    server.use(
      http.post(`${A}/users/2/sessions/revoke`, async ({ request }) => {
        await rec(request);
        return new HttpResponse(null, { status: 204 });
      }),
    );
    open();
    const bob = await rowOf("bob@example.com");
    fireEvent.click(within(bob).getByRole("button", { name: /Revoke sessions/ }));
    expect(calls).toEqual([]);
    fireEvent.click(within(bob).getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0]).toMatchObject({ method: "POST", path: "/api/auth/users/2/sessions/revoke" });
    await waitFor(() => expect(listCalls).toBeGreaterThanOrEqual(2));
  });

  test.each([
    ["cannot_modify_self", "You can't change your own role or status here"],
    ["last_admin", "At least one active admin is required"],
  ])("a 409 %s shows its message", async (code, message) => {
    mock();
    server.use(http.patch(`${A}/users/:id`, () => HttpResponse.json({ error: code }, { status: 409 })));
    open();
    const bob = await rowOf("bob@example.com");
    fireEvent.click(within(bob).getByRole("switch"));
    fireEvent.click(within(bob).getByRole("button", { name: "Confirm" }));
    expect(await screen.findByText(message)).toBeInTheDocument();
  });

  test("reset password shows the one-time link; a 409 user_inactive shows its message", async () => {
    mock();
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    server.use(
      http.post(`${A}/users/2/reset`, async ({ request }) => {
        await rec(request);
        return HttpResponse.json({ token: TOKEN, expires_at: "2026-11-06T12:00:00Z" }, { status: 201 });
      }),
      http.post(`${A}/users/4/reset`, () => HttpResponse.json({ error: "user_inactive" }, { status: 409 })),
    );
    const qc = open();
    const bob = await rowOf("bob@example.com");
    fireEvent.click(within(bob).getByRole("button", { name: /Reset password/ }));
    expect(calls).toEqual([]);
    expect(within(bob).getByText(/Any earlier unused reset link for this user stops working/)).toBeInTheDocument();
    fireEvent.click(within(bob).getByRole("button", { name: "Confirm" }));
    const panel = await screen.findByRole("region", { name: /Password reset link/ });
    const link = `${location.origin}/reset#${TOKEN}`;
    expect(within(panel).getByDisplayValue(link)).toBeInTheDocument();
    expect(within(panel).queryByDisplayValue(new RegExp(`/reset/${TOKEN}`))).toBeNull();
    expect(within(panel).getByText("This won't be shown again")).toBeInTheDocument();
    expect(within(panel).getByText(/Expires/)).toBeInTheDocument();
    expect(cacheDump(qc)).not.toContain(TOKEN);

    fireEvent.click(within(panel).getByRole("button", { name: "Done" }));
    expect(screen.queryByDisplayValue(link)).toBeNull();
    expect(document.body.innerHTML).not.toContain(TOKEN);
    expect(cacheDump(qc)).not.toContain(TOKEN);
    expect(JSON.stringify([localStorage, sessionStorage, location.href])).not.toContain(TOKEN);
    for (const c of setItem.mock.calls) expect(c.join("|")).not.toContain(TOKEN);
    setItem.mockRestore();

    const dan = await rowOf("dan@example.com");
    const danReset = within(dan).getByRole("button", { name: /Reset password/ });
    expect(danReset).toBeDisabled();
    expect(danReset).toHaveAttribute("title", "Reactivate first");
    // a stale list can still hit the server error
    users = users.map((u) => (u.id === 4 ? { ...u, is_active: true } : u));
    await qc.invalidateQueries();
    const dan2 = await rowOf("dan@example.com");
    fireEvent.click(within(dan2).getByRole("button", { name: /Reset password/ }));
    fireEvent.click(within(dan2).getByRole("button", { name: "Confirm" }));
    expect(await screen.findByText("Reactivate the user before resetting their password")).toBeInTheDocument();
  });
});
