import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Page, Route } from "@playwright/test";
import { CVE_ID, expect, loaded, test } from "./harness";

/**
 * Signed in (M5): the startup refresh succeeds and /auth/me is a member. Guards I1: data fetched
 * as the member (here a ransomware.live story, signed-in only) must be gone after logout.
 * These routes are registered after the harness's, so Playwright consults them first.
 */
const TOKEN = "e2e-access-token";
const MEMBER = { id: 7, email: "member@example.test", role: "member" };
const VICTIM = "Victim Corp listed by e2e-group";

const CVE_FIXTURE = JSON.parse(readFileSync(join(import.meta.dirname, "fixtures", `cve-${CVE_ID}.json`), "utf8"));
const SIGNED_IN_CVE = {
  ...CVE_FIXTURE,
  stories: [
    ...CVE_FIXTURE.stories,
    {
      title: VICTIM,
      url: "https://www.ransomware.live/e2e",
      source: "ransomware.live",
      published: "2026-11-05T09:00:00Z",
    },
  ],
};

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
const authed = (route: Route) => route.request().headers()["authorization"] === `Bearer ${TOKEN}`;

async function signedInApi(page: Page) {
  const calls = { refresh: 0, logout: 0, cveAnon: 0, cveAuthed: 0 };
  await page.route("**/api/auth/refresh", (route) => {
    calls.refresh++;
    return json(route, { access_token: TOKEN, token_type: "bearer", expires_in: 900 });
  });
  await page.route("**/api/auth/me", (route) =>
    authed(route) ? json(route, MEMBER) : json(route, { error: "unauthorized" }, 401),
  );
  await page.route("**/api/auth/logout", (route) => {
    calls.logout++;
    return route.fulfill({ status: 204 });
  });
  await page.route(`**/api/cves/${CVE_ID}?*`, (route) => {
    if (authed(route)) {
      calls.cveAuthed++;
      return json(route, SIGNED_IN_CVE);
    }
    calls.cveAnon++;
    return json(route, CVE_FIXTURE);
  });
  return calls;
}

test("signed in: member-only data shows in the CVE drawer and is gone after logout", async ({ page }) => {
  const calls = await signedInApi(page);
  await loaded(page);

  // signed-in-only chrome: the account menu instead of "Sign in"
  const account = page.getByRole("button", { name: new RegExp(MEMBER.email) });
  await expect(account).toBeVisible();
  await expect(page.getByRole("link", { name: "Sign in" })).toHaveCount(0);
  expect(calls.refresh).toBe(1);

  // the CVE drawer carries the signed-in-only ransomware.live story, with its credit
  const row = page.locator('.lane[data-k="exploited"] [data-testid="lane-row"]').first();
  await row.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText(VICTIM)).toBeVisible();
  await expect(dialog.getByTestId("ransomware-credit")).toHaveText("Ransomware data: ransomware.live");
  expect(calls.cveAuthed).toBe(1);
  expect(calls.cveAnon).toBe(0);
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);

  // log out
  await account.click();
  await page.getByRole("button", { name: "Log out" }).click();
  await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible();
  expect(calls.logout).toBe(1);

  // the same CVE again, now as a guest: refetched anonymously, the member's data is gone
  await row.click();
  await expect(dialog.getByText("Gateway flaw hits thousands")).toBeVisible();
  await expect(dialog.getByText(VICTIM)).toHaveCount(0);
  await expect(dialog.getByTestId("ransomware-credit")).toHaveCount(0);
  expect(calls.cveAnon).toBe(1);
  await expect(page.getByText(MEMBER.email)).toHaveCount(0);
});
