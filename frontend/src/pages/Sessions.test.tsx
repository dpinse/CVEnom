import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { afterEach, describe, expect, test } from "vitest";
import { authStore } from "../lib/api";
import type { SessionInfo } from "../lib/types";
import { at, renderRoute } from "../test/authpages";
import { member, server, setupMsw, signIn } from "../test/shell";
import Sessions from "./Sessions";

setupMsw();
afterEach(cleanup);

const mk = (o: Partial<SessionInfo>): SessionInfo => ({
  id: "s1",
  user_agent: "Mozilla/5.0 (X11; Linux) Firefox/130",
  ip: "203.0.113.5",
  created_at: "2026-11-01T00:00:00Z",
  last_used_at: new Date(Date.now() - 5 * 60_000).toISOString(),
  current: false,
  ...o,
});
let rows: SessionInfo[] = [];
let listCalls = 0;
const revoked: string[] = [];
function api(revokeStatus = 204) {
  listCalls = 0;
  revoked.length = 0;
  let logouts = 0;
  server.use(
    http.get("http://localhost/api/auth/sessions", () => {
      listCalls++;
      return HttpResponse.json(rows);
    }),
    http.delete("http://localhost/api/auth/sessions/:id", ({ params }) => {
      revoked.push(String(params.id));
      if (revokeStatus === 204) rows = rows.filter((r) => r.id !== params.id);
      return revokeStatus === 204 ? new HttpResponse(null, { status: 204 }) : HttpResponse.json({ error: "not_found" }, { status: revokeStatus });
    }),
    http.post("http://localhost/api/auth/logout", () => {
      logouts++;
      return new HttpResponse(null, { status: 204 });
    }),
  );
  return () => logouts;
}
const open = () => renderRoute("/account/sessions", <Sessions />, "/account/sessions");

describe("Sessions", () => {
  test("lists device, IP, last used, and marks this device", async () => {
    signIn(member);
    rows = [
      mk({ id: "a", current: true }),
      mk({ id: "b", user_agent: null, ip: null }),
      mk({ id: "c", user_agent: "<img src=x onerror=alert(1)>" }),
    ];
    api();
    open();
    expect(await screen.findByText("This device")).toBeInTheDocument();
    expect(screen.getByText("Unknown device")).toBeInTheDocument();
    expect(screen.getAllByText("203.0.113.5").length).toBeGreaterThan(0);
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/5 minutes ago/).length).toBeGreaterThan(0);
    // hostile UA is text, not markup
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });

  test("revoke asks for in-page confirmation, then refetches", async () => {
    signIn(member);
    rows = [mk({ id: "a", current: true }), mk({ id: "b", ip: "198.51.100.7" })];
    api();
    open();
    const row = (await screen.findByText("198.51.100.7")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: /revoke/i }));
    expect(revoked).toEqual([]);
    fireEvent.click(within(row).getByRole("button", { name: /confirm revoke/i }));
    await waitFor(() => expect(revoked).toEqual(["b"]));
    await waitFor(() => expect(screen.queryByText("198.51.100.7")).not.toBeInTheDocument());
    expect(listCalls).toBeGreaterThanOrEqual(2);
  });

  test("cancel leaves the session alone", async () => {
    signIn(member);
    rows = [mk({ id: "b" })];
    api();
    open();
    fireEvent.click(await screen.findByRole("button", { name: /revoke/i }));
    fireEvent.click(screen.getByRole("button", { name: /cancel/i }));
    expect(screen.getByRole("button", { name: /revoke/i })).toBeInTheDocument();
    expect(revoked).toEqual([]);
  });

  test("revoking the CURRENT session logs out and goes to /login", async () => {
    signIn(member);
    authStore.setToken("tok");
    rows = [mk({ id: "a", current: true })];
    const logouts = api();
    open();
    fireEvent.click(await screen.findByRole("button", { name: /revoke/i }));
    fireEvent.click(screen.getByRole("button", { name: /confirm revoke/i }));
    await waitFor(() => expect(at()).toBe("/login"));
    expect(logouts()).toBe(1);
    expect(authStore.getSnapshot().user).toBeNull();
  });

  test("a 404 on revoke means already gone: refetch, no error", async () => {
    signIn(member);
    rows = [mk({ id: "b", ip: "198.51.100.7" })];
    api(404);
    open();
    await screen.findByText("198.51.100.7");
    fireEvent.click(screen.getByRole("button", { name: /revoke/i }));
    fireEvent.click(screen.getByRole("button", { name: /confirm revoke/i }));
    await waitFor(() => expect(listCalls).toBeGreaterThanOrEqual(2));
    expect(screen.queryByText(/could not/i)).not.toBeInTheDocument();
  });
});
