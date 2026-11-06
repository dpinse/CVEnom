import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
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

describe("Situation readout", () => {
  test("renders the level and an accessible gauge label from the Exploited lane", async () => {
    handlers({ lanes: lanes([1, 2, 3, 4].map((n) => item({ cve_id: `CVE-2020-${n}`, kev_added: "2020-01-01" }))) });
    guest();
    bar();
    expect(await screen.findByRole("img", { name: "Situation: High" })).toBeInTheDocument();
    expect(document.querySelectorAll(".sgauge i.lit")).toHaveLength(3);
    expect(document.querySelectorAll(".sgauge i")).toHaveLength(4);
  });
  test("Calm with an empty lane shows one dim bar", async () => {
    handlers();
    guest();
    bar();
    expect(await screen.findByRole("img", { name: "Situation: Calm" })).toBeInTheDocument();
    expect(document.querySelectorAll(".sgauge i.lit")).toHaveLength(1);
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
