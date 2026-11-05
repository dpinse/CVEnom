import { QueryClient } from "@tanstack/react-query";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { Link, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { createQueryClient } from "../lib/queries";
import { authStore } from "../lib/api";
import { AppRoutes } from "../routes";
import { Where } from "../test/authpages";
import { admin, member, renderAt, server, setupMsw, signIn } from "../test/shell";
import type { InviteOut, UserAdmin } from "../lib/types";
import AdminInvites from "./AdminInvites";

vi.mock("../lib/live", () => ({ useLiveUpdates: () => ({ status: "live", lastUpdated: null }) }));

setupMsw();
afterEach(cleanup);

const TOKEN = "INVTOK-abcdef0123456789";
const A = "http://localhost/api/auth";
const mkInvite = (o: Partial<InviteOut> = {}): InviteOut => ({
  id: 1,
  email: "new@example.com",
  role: "member",
  purpose: "invite",
  expires_at: new Date(Date.now() + 3 * 86400_000).toISOString(),
  created_at: "2026-11-05T00:00:00Z",
  created_by: 1,
  ...o,
});
const adminUser: UserAdmin = { id: 1, email: "admin@example.com", role: "admin", is_active: true, created_at: "2026-10-01T00:00:00Z", active_sessions: 1 };

let invites: InviteOut[] = [];
let usersStatus = 200;
const calls: { method: string; path: string; body?: unknown }[] = [];
async function rec(request: Request) {
  const t = await request.text();
  calls.push({ method: request.method, path: new URL(request.url).pathname, body: t ? JSON.parse(t) : undefined });
}
function mock() {
  calls.length = 0;
  server.use(
    http.get(`${A}/invites`, () => HttpResponse.json(invites)),
    http.get(`${A}/users`, () => (usersStatus === 200 ? HttpResponse.json([adminUser]) : HttpResponse.json({ error: "x" }, { status: usersStatus }))),
  );
}
const cacheDump = (qc: QueryClient) =>
  JSON.stringify([
    qc.getQueryCache().getAll().map((q) => ({ k: q.queryKey, d: q.state.data })),
    qc.getMutationCache().getAll().map((m) => ({ v: m.state.variables, d: m.state.data })),
  ]);
function open(qc: QueryClient = createQueryClient()) {
  renderAt(
    <Routes>
      <Route
        path="/admin/invites"
        element={
          <>
            <AdminInvites />
            <Link to="/elsewhere">leave</Link>
          </>
        }
      />
      <Route path="*" element={<Where />} />
    </Routes>,
    "/admin/invites",
    qc,
  );
  return qc;
}
beforeEach(() => {
  signIn(admin);
  invites = [];
  usersStatus = 200;
});

describe("AdminInvites", () => {
  test("creates an invite, shows the link once with expiry, and discards it after Done", async () => {
    mock();
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    server.use(
      http.post(`${A}/invites`, async ({ request }) => {
        await rec(request);
        invites = [mkInvite()];
        return HttpResponse.json({ token: TOKEN, expires_at: "2026-11-08T12:00:00Z" }, { status: 201 });
      }),
    );
    const qc = open();
    const email = await screen.findByLabelText("Email");
    expect(email).toHaveAttribute("type", "email");
    fireEvent.change(email, { target: { value: "new@example.com" } });
    fireEvent.change(screen.getByLabelText("Role"), { target: { value: "admin" } });
    fireEvent.click(screen.getByRole("button", { name: "Create invite" }));

    const panel = await screen.findByRole("region", { name: /Invite link/ });
    // M2: the token rides in the fragment, which browsers never send to nginx/Cloudflare logs
    const link = `${location.origin}/invite#${TOKEN}`;
    expect(within(panel).getByDisplayValue(link)).toHaveAttribute("readonly");
    expect(within(panel).queryByDisplayValue(new RegExp(`/invite/${TOKEN}`))).toBeNull();
    expect(within(panel).getByText("This won't be shown again")).toBeInTheDocument();
    expect(within(panel).getByText(/Expires/)).toBeInTheDocument();
    expect(calls[0].body).toEqual({ email: "new@example.com", role: "admin" });
    expect(cacheDump(qc)).not.toContain(TOKEN);
    await screen.findByRole("button", { name: /Revoke invite for new@example.com/ });
    expect(cacheDump(qc)).not.toContain(TOKEN);

    fireEvent.click(within(panel).getByRole("button", { name: "Done" }));
    expect(screen.queryByDisplayValue(link)).toBeNull();
    expect(document.body.innerHTML).not.toContain(TOKEN);
    expect(cacheDump(qc)).not.toContain(TOKEN);
    expect(JSON.stringify([localStorage, sessionStorage, location.href])).not.toContain(TOKEN);
    for (const c of setItem.mock.calls) expect(c.join("|")).not.toContain(TOKEN);
    expect(screen.getByLabelText("Email")).toHaveFocus();
    setItem.mockRestore();
  });

  test("the link is discarded when the page unmounts", async () => {
    mock();
    server.use(http.post(`${A}/invites`, () => HttpResponse.json({ token: TOKEN, expires_at: "2026-11-08T12:00:00Z" }, { status: 201 })));
    open();
    fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "a@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Create invite" }));
    await screen.findByRole("region", { name: /Invite link/ });
    fireEvent.click(screen.getByRole("link", { name: "leave" }));
    await screen.findByTestId("at");
    expect(document.body.innerHTML).not.toContain(TOKEN);
  });

  test("an invalid email is blocked on the client", async () => {
    mock();
    open();
    fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "not-an-email" } });
    fireEvent.click(screen.getByRole("button", { name: "Create invite" }));
    expect(await screen.findByText("Enter a valid email address")).toBeInTheDocument();
    expect(calls).toEqual([]);
  });

  test("lists pending invites with created-by from the users list, falls back to the id, and revokes after an in-page confirm", async () => {
    invites = [mkInvite({ id: 1, created_by: 1 }), mkInvite({ id: 2, email: "reset@example.com", purpose: "reset", created_by: 77 })];
    mock();
    const confirm = vi.spyOn(window, "confirm");
    server.use(
      http.delete(`${A}/invites/1`, async ({ request }) => {
        await rec(request);
        invites = invites.filter((i) => i.id !== 1);
        return new HttpResponse(null, { status: 204 });
      }),
    );
    open();
    const row = (await screen.findByText("new@example.com")).closest("tr")!;
    await waitFor(() => expect(within(row).getByText("admin@example.com")).toBeInTheDocument());
    expect(within(row).getByText(/in 3 days/)).toBeInTheDocument();
    const row2 = screen.getByText("reset@example.com").closest("tr")!;
    expect(within(row2).getByText("User #77")).toBeInTheDocument();
    expect(within(row2).getByText("Password reset")).toBeInTheDocument();

    fireEvent.click(within(row).getByRole("button", { name: /Revoke invite/ }));
    expect(calls).toEqual([]);
    fireEvent.click(within(row).getByRole("button", { name: "Confirm revoke" }));
    await waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0].method).toBe("DELETE");
    await waitFor(() => expect(screen.queryByText("new@example.com")).toBeNull());
    expect(confirm).not.toHaveBeenCalled();
    confirm.mockRestore();
  });

  test("created-by shows the id when the users list is unavailable; hostile email is text", async () => {
    invites = [mkInvite({ email: "<b>x</b>@example.com", created_by: 5 })];
    usersStatus = 500;
    mock();
    open();
    expect(await screen.findByText("<b>x</b>@example.com")).toBeInTheDocument();
    expect(await screen.findByText("User #5")).toBeInTheDocument();
    expect(document.querySelector("td b")).toBeNull();
  });
});

describe("admin guard", () => {
  test.each(["/admin/invites", "/admin/users", "/admin/alerts"])("a member never renders %s", async (path) => {
    server.use(
      http.get("http://localhost/api/health", () => HttpResponse.json({ status: "ok", public_read: true })),
      http.get("http://localhost/api/lanes", () => HttpResponse.json({ EXPLOITED: [], LIKELY: [], LOUD: [], FRESH: [] })),
    );
    signIn(member);
    let hit = 0;
    server.use(
      http.get(`${A}/invites`, () => (hit++, HttpResponse.json([]))),
      http.get(`${A}/users`, () => (hit++, HttpResponse.json([]))),
      http.get("http://localhost/api/alerts/rules", () => (hit++, HttpResponse.json([]))),
    );
    renderAt(<AppRoutes />, path);
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
    for (const h of ["Invites", "Users", "Alert rules"]) expect(screen.queryByRole("heading", { name: h })).toBeNull();
    expect(hit).toBe(0);
    expect(authStore.getSnapshot().user?.role).toBe("member");
  });
});
