import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import type { LiveState } from "../lib/live";
import { admin, guest, handlers, item, lanes, member, renderAt, signIn, setupMsw } from "../test/shell";
import { CommandBar } from "./CommandBar";

let live: LiveState = { status: "live", lastUpdated: null };
vi.mock("../lib/live", () => ({ useLiveUpdates: () => live }));

setupMsw();
beforeEach(() => {
  live = { status: "live", lastUpdated: null };
  document.documentElement.removeAttribute("data-theme");
});
afterEach(cleanup);

const bar = (path = "/") => renderAt(<CommandBar />, path);
const openMenu = (email: RegExp) => fireEvent.click(screen.getByRole("button", { name: email }));

describe("navigation", () => {
  test("has Dashboard and Threats links in the Main nav", async () => {
    handlers();
    guest();
    bar();
    const nav = within(screen.getByRole("navigation", { name: "Main" }));
    expect(nav.getByRole("link", { name: "Threats" }).getAttribute("href")).toBe("/threats");
    expect(nav.getByRole("link", { name: "Dashboard" }).getAttribute("href")).toBe("/?range=7d");
    await screen.findByRole("img", { name: /Situation/ });
  });
  test("on /threats the Threats link is current and the range control is hidden", async () => {
    handlers();
    guest();
    bar("/threats?lane=fresh");
    expect(screen.getByRole("link", { name: "Threats" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Dashboard" })).not.toHaveAttribute("aria-current");
    expect(screen.queryByRole("group", { name: "Time range" })).toBeNull();
    await screen.findByRole("img", { name: /Situation/ });
  });
  test("the range control shows on the Dashboard only", async () => {
    handlers();
    guest();
    bar("/");
    expect(screen.getByRole("group", { name: "Time range" })).toBeInTheDocument();
    cleanup();
    bar("/admin/users");
    expect(screen.queryByRole("group", { name: "Time range" })).toBeNull();
    await screen.findByRole("img", { name: /Situation/ });
  });
});

describe("Situation readout", () => {
  test("shows the server's level, lit bars and reason", async () => {
    handlers({ situation: { level: "High", lit: 3, reason: "7 KEV additions this week, 2.3x the 90-day norm" } });
    guest();
    bar();
    expect(
      await screen.findByRole("img", { name: "Situation: High. 7 KEV additions this week, 2.3x the 90-day norm" }),
    ).toBeInTheDocument();
    expect(document.querySelectorAll(".sgauge i.lit")).toHaveLength(3);
    expect(document.querySelectorAll(".sgauge i")).toHaveLength(4);
    expect(document.querySelector(".situation")).toHaveAttribute("data-level", "High");
    expect(document.querySelector(".situation")).toHaveAttribute(
      "title",
      "High: 7 KEV additions this week, 2.3x the 90-day norm",
    );
    expect(document.querySelector(".sreason")).toHaveTextContent("7 KEV additions this week");
  });
  test("a server Calm shows one dim bar even when the Exploited lane is full", async () => {
    // the old client rule said Severe for a KEV today; the server's relative level is what shows
    const added = new Date().toISOString().slice(0, 10);
    handlers({ lanes: lanes([1, 2, 3, 4, 5, 6, 7].map((n) => item({ cve_id: `CVE-2020-${n}`, kev_added: added }))) });
    guest();
    bar();
    expect(await screen.findByRole("img", { name: /^Situation: Calm\./ })).toBeInTheDocument();
    expect(document.querySelectorAll(".sgauge i.lit")).toHaveLength(1);
  });
  test("shows Unavailable with no bars lit when the summary fails", async () => {
    handlers({ situation: null });
    guest();
    bar();
    expect(await screen.findByRole("img", { name: "Situation: Unavailable" })).toBeInTheDocument();
    expect(document.querySelectorAll(".sgauge i.lit")).toHaveLength(0);
    expect(document.querySelector(".sreason")).toBeNull();
  });
});

describe("live status", () => {
  test("announces status as visually hidden text and shows updated time", () => {
    handlers();
    guest();
    live = { status: "reconnecting", lastUpdated: new Date(2026, 10, 5, 9, 7).getTime() };
    bar();
    expect(screen.getByText(/reconnecting/i)).toHaveClass("sr-only");
    expect(screen.getByText(/updated 09:07/)).toBeInTheDocument();
    expect(document.querySelector(".dot")).toHaveAttribute("data-status", "reconnecting");
  });
});

describe("theme toggle", () => {
  test("flips data-theme and persists", () => {
    handlers();
    guest();
    bar();
    const btn = screen.getByRole("button", { name: /theme/i });
    const before = btn.getAttribute("aria-pressed");
    expect(before).toMatch(/true|false/);
    fireEvent.click(btn);
    const first = document.documentElement.getAttribute("data-theme");
    expect(["light", "dark"]).toContain(first);
    expect(localStorage.getItem("cvenom-theme")).toBe(first);
    fireEvent.click(btn);
    const second = document.documentElement.getAttribute("data-theme");
    expect(second).not.toBe(first);
    expect(btn.getAttribute("aria-pressed")).toBe(before);
  });
  test("initial value comes from storage", () => {
    localStorage.setItem("cvenom-theme", "light");
    handlers();
    guest();
    bar();
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    expect(screen.getByRole("button", { name: /theme/i })).toHaveAttribute("aria-pressed", "false");
  });
  test("works when localStorage throws", () => {
    const get = vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    const set = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    handlers();
    guest();
    bar();
    fireEvent.click(screen.getByRole("button", { name: /theme/i }));
    expect(["light", "dark"]).toContain(document.documentElement.getAttribute("data-theme"));
    get.mockRestore();
    set.mockRestore();
  });
});

describe("user menu", () => {
  test("guest sees Sign in", () => {
    handlers();
    guest();
    bar();
    expect(screen.getByRole("link", { name: "Sign in" })).toBeInTheDocument();
  });
  test("member sees email, account links and logout, no admin links", () => {
    handlers();
    signIn(member);
    bar();
    openMenu(/member@example\.com/);
    expect(screen.getByRole("link", { name: "Sessions" })).toHaveAttribute("href", "/account/sessions");
    expect(screen.getByRole("link", { name: "Change password" })).toHaveAttribute("href", "/account/password");
    expect(screen.getByRole("link", { name: "Two-factor" })).toHaveAttribute("href", "/account/two-factor");
    expect(screen.getByRole("button", { name: "Log out" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Alerts" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Invites" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Users" })).toBeNull();
  });
  test("admin sees admin links", () => {
    handlers();
    signIn(admin);
    bar();
    openMenu(/admin@example\.com/);
    expect(screen.getByRole("link", { name: "Alerts" })).toHaveAttribute("href", "/admin/alerts");
    expect(screen.getByRole("link", { name: "Invites" })).toHaveAttribute("href", "/admin/invites");
    expect(screen.getByRole("link", { name: "Users" })).toHaveAttribute("href", "/admin/users");
  });
  test("Esc closes the menu and returns focus to the trigger", () => {
    handlers();
    signIn(member);
    bar();
    const trigger = screen.getByRole("button", { name: /member@example\.com/ });
    fireEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    screen.getByRole("link", { name: "Sessions" }).focus();
    fireEvent.keyDown(document.activeElement ?? document.body, { key: "Escape" });
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("link", { name: "Sessions" })).toBeNull();
    expect(trigger).toHaveFocus();
  });
  test("an email with entities is rendered through Text", () => {
    handlers();
    signIn({ id: 3, email: "a&amp;b@example.com", role: "member" });
    bar();
    expect(screen.getByRole("button", { name: /a&b@example\.com/ })).toBeInTheDocument();
  });
  test("logout calls the API and clears the session", async () => {
    handlers();
    signIn(member);
    bar();
    openMenu(/member@example\.com/);
    fireEvent.click(screen.getByRole("button", { name: "Log out" }));
    await waitFor(() => expect(screen.getByRole("link", { name: "Sign in" })).toBeInTheDocument());
  });
});

describe("user area before bootstrap", () => {
  test("renders no Sign in link until ready, then shows it for a guest", () => {
    handlers();
    bar();
    expect(screen.queryByRole("link", { name: "Sign in" })).not.toBeInTheDocument();
    cleanup();
    guest();
    bar();
    expect(screen.getByRole("link", { name: "Sign in" })).toBeInTheDocument();
  });
  test("on /login the Sign in link does not nest next", () => {
    handlers();
    guest();
    bar("/login?next=%2Fsearch");
    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/login");
  });
});

describe("Sign in link never carries a secret route", () => {
  test.each(["/invite#s3cret-token", "/reset#s3cret-token", "/invite", "/reset"])(
    "%s links to a bare /login",
    (path) => {
      handlers();
      guest();
      bar(path);
      expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/login");
    },
  );
});
