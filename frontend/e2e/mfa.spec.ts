import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";
import { MFA, expect, mockTwoStepSignIn, passwordStep, test } from "./harness";

/**
 * Mandatory MFA through the real sign-in form (production build, mocked API). Guards that the
 * ticket, enrollment secret and recovery codes stay out of URLs, web storage and request URLs,
 * and that no session exists before the second factor.
 */

const SECRETS = [MFA.ticket, MFA.secret, ...MFA.recoveryCodes];

async function assertNoSecretsLeaked(page: Page, log: { url: string }[], extraUrls: string[]) {
  const stored = await page.evaluate(() =>
    JSON.stringify([{ ...localStorage }, { ...sessionStorage }, document.cookie]),
  );
  for (const s of SECRETS) {
    expect(stored, "web storage / cookies").not.toContain(s);
    expect(page.url()).not.toContain(s);
    for (const u of [...log.map((l) => l.url), ...extraUrls]) expect(u).not.toContain(s);
  }
}

function collectUrls(page: Page) {
  const urls: string[] = [];
  page.on("request", (r) => urls.push(r.url()));
  return urls;
}

test("sign-in with a TOTP code: password step, then code step, then signed in", async ({ page }) => {
  const urls = collectUrls(page);
  const log = await mockTwoStepSignIn(page);
  await passwordStep(page);

  // step two: no session yet, the password field is gone
  const code = page.getByLabel("Authentication code");
  await expect(code).toBeVisible();
  await expect(page.getByLabel("Password")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible(); // still a guest
  expect(log.map((l) => l.path)).toEqual(["/api/auth/login"]);

  await code.fill(MFA.code);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("button", { name: new RegExp(MFA.member.email) })).toBeVisible();
  await expect(page).toHaveURL(/\/$/);
  const verify = log.find((l) => l.path === "/api/auth/mfa/verify");
  expect(verify?.body).toEqual({ ticket: MFA.ticket, code: MFA.code });
  await assertNoSecretsLeaked(page, log, urls);
});

test("an account without MFA enrolls at sign-in: local QR, manual key, one-time recovery codes", async ({ page }) => {
  const urls = collectUrls(page);
  const log = await mockTwoStepSignIn(page, { enroll: true });
  await passwordStep(page);

  await expect(page.getByRole("heading", { name: "Set up two-factor authentication" })).toBeVisible();
  const qr = page.getByRole("img", { name: "QR code for your authenticator app" });
  await expect(qr).toBeVisible();
  const svg = await qr.evaluate((el) => el.outerHTML);
  expect(svg).not.toMatch(/style=|<image|href=|https?:/);
  await expect(page.getByText(MFA.secret.replace(/(.{4})/g, "$1 ").trim())).toBeVisible();
  await expect(page.locator('meta[name="referrer"][content="no-referrer"]')).toHaveCount(1);
  await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible(); // no session before the code

  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  const bad = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(bad.map((v) => ({ id: v.id, nodes: v.nodes.map((n) => n.target.join(" ")) }))).toEqual([]);

  await page.getByLabel("Authentication code").fill(MFA.code);
  await page.getByRole("button", { name: "Verify" }).click();

  const panel = page.getByRole("region", { name: "Recovery codes" });
  await expect(panel).toBeVisible();
  for (const c of MFA.recoveryCodes) await expect(panel.getByText(c)).toBeVisible();
  await expect(panel.getByText("This won't be shown again")).toBeVisible();
  // the enrollment secret left the page once confirmed
  await expect(page.getByText(MFA.secret.replace(/(.{4})/g, "$1 ").trim())).toHaveCount(0);
  await assertNoSecretsLeaked(page, log, urls);

  await panel.getByRole("button", { name: "Done" }).click();
  await expect(page.getByRole("button", { name: new RegExp(MFA.member.email) })).toBeVisible();
  await expect(page.getByText(MFA.recoveryCodes[0])).toHaveCount(0);
  expect(log.map((l) => l.path)).toEqual([
    "/api/auth/login",
    "/api/auth/mfa/enroll/start",
    "/api/auth/mfa/enroll/finish",
  ]);
});

test("a rejected code keeps the code step with one generic message; Start over goes back", async ({ page }) => {
  await mockTwoStepSignIn(page);
  await page.route("**/api/auth/mfa/verify", (route) =>
    route.fulfill({ status: 401, contentType: "application/json", body: '{"error":"invalid_mfa"}' }),
  );
  // the browser logs the mocked 401 itself; the harness allows exactly that line
  await passwordStep(page);
  await page.getByLabel("Authentication code").fill("000000");
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByText(/That code was not accepted/)).toBeVisible();
  await expect(page.getByLabel("Authentication code")).toHaveValue("");
  await page.getByRole("button", { name: "Start over" }).click();
  await expect(page.getByLabel("Password")).toHaveValue("");
});
