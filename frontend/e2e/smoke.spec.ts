import AxeBuilder from "@axe-core/playwright";
import { canvasCentreStdDev, CVE_ID, expect, loaded, STDDEV_MIN, test } from "./harness";

const LANES = ["Exploited now", "Likely next", "Loud now", "Fresh criticals"];

test("dashboard renders the four lanes with fixture rows", async ({ page }) => {
  await loaded(page);
  for (const name of LANES) await expect(page.getByRole("heading", { level: 2, name })).toBeVisible();
  await expect(page.locator(".lane")).toHaveCount(4);
  for (const k of ["exploited", "likely", "loud", "fresh"]) {
    await expect(page.locator(`.lane[data-k="${k}"] [data-testid="lane-row"]`)).toHaveCount(2);
  }
});

test("globe canvas exists and WebGL actually drew (centre pixels are not uniform)", async ({ page }) => {
  await loaded(page);
  await expect(page.locator(".globe-map canvas").first()).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText("Couldn't load the map")).toHaveCount(0);
  await expect
    .poll(() => canvasCentreStdDev(page), { timeout: 20_000, message: "canvas centre luminance stddev" })
    .toBeGreaterThan(STDDEV_MIN);
});

test("clicking a row opens the drawer; Esc closes it and focus returns to the row", async ({ page }) => {
  await loaded(page);
  const row = page.locator('.lane[data-k="exploited"] [data-testid="lane-row"]').first();
  await row.click();
  await expect(page).toHaveURL(new RegExp(`[?&]cve=${CVE_ID}`));
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText("Acme Gateway 4.2")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(page).not.toHaveURL(/cve=/);
  await expect(row).toBeFocused();
});

test("no horizontal scroll at a 400px viewport", async ({ page }) => {
  await page.setViewportSize({ width: 400, height: 800 });
  await loaded(page);
  await expect(page.locator(".globe-map canvas").first()).toBeVisible({ timeout: 20_000 });
  const widths = await page.evaluate(() => ({
    doc: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
    cols: getComputedStyle(document.querySelector(".lanes")!).gridTemplateColumns.split(" ").length,
  }));
  expect(widths.doc).toBeLessThanOrEqual(400);
  expect(widths.body).toBeLessThanOrEqual(400);
  expect(widths.cols).toBe(1);
});

test("the theme toggle flips data-theme and the globe keeps drawing without errors", async ({ page }) => {
  await loaded(page);
  await expect(page.locator(".globe-map canvas").first()).toBeVisible({ timeout: 20_000 });
  const before = (await page.locator("html").getAttribute("data-theme")) ?? "";
  await page.getByRole("button", { name: "Dark theme" }).click();
  await expect(page.locator("html")).not.toHaveAttribute("data-theme", before);
  await expect.poll(() => canvasCentreStdDev(page), { timeout: 20_000 }).toBeGreaterThan(STDDEV_MIN);
});

test("axe: no serious or critical violations on the dashboard", async ({ page }) => {
  await loaded(page);
  await expect(page.locator(".globe-map canvas").first()).toBeVisible({ timeout: 20_000 });
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"])
    .analyze();
  const bad = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(bad.map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.map((n) => n.target.join(" ")) }))).toEqual([]);
});

// Stored-XSS contract: summaries/titles arrive HTML-escaped from the API and may contain markup. They must render as
// literal text; no element may be created from them, on the dashboard or in the drawer.
const XSS_IMG = "<img src=x onerror=alert(1)>";
const XSS_SCRIPT = "<script>alert(2)</script>"; // the fixture holds &lt;script&gt;alert(2)&lt;/script&gt;, decoded once

test("XSS fixtures render as literal text on the dashboard and in the CVE and story drawers", async ({ page }) => {
  const dialogs: string[] = [];
  page.on("dialog", (d) => {
    dialogs.push(d.message());
    void d.dismiss();
  });
  await loaded(page);
  const lanes = page.locator(".lanes");
  await expect(lanes).toContainText(XSS_IMG);
  await expect(lanes).toContainText(XSS_SCRIPT);
  await expect(lanes.locator("img, script, [onerror]")).toHaveCount(0);

  // the story title in the Loud lane
  const storyRow = page.getByTestId("story-row").filter({ hasText: XSS_IMG });
  await expect(storyRow).toHaveCount(1);
  await storyRow.getByRole("button").first().click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText(XSS_IMG);
  await expect(dialog.locator("img, script, [onerror]")).toHaveCount(0);
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);

  // the CVE summary and a linked story title in the CVE drawer
  await page.locator('.lane[data-k="exploited"] [data-testid="lane-row"]').first().click();
  await expect(dialog).toContainText("Acme Gateway 4.2");
  await expect(dialog).toContainText(XSS_IMG);
  await expect(dialog).toContainText(XSS_SCRIPT);
  await expect(dialog.locator("img, script, [onerror]")).toHaveCount(0);
  expect(await page.locator("body script, #root img, #root [onerror]").count()).toBe(0);
  expect(dialogs).toEqual([]);
});

test("the live socket is only ever same-origin /api/ws/live with no query string or token", async ({ page }) => {
  await loaded(page);
  await expect.poll(() => page.evaluate(() => (window as unknown as { __wsAttempts: string[] }).__wsAttempts.length)).toBeGreaterThan(0);
  const attempts = await page.evaluate(() => (window as unknown as { __wsAttempts: string[] }).__wsAttempts);
  const pageOrigin = new URL(page.url()).origin;
  for (const raw of attempts) {
    const u = new URL(raw);
    expect(u.origin).toBe(pageOrigin.replace(/^http/, "ws"));
    expect(u.pathname).toBe("/api/ws/live");
    expect(u.search).toBe("");
    expect(u.hash).toBe("");
    expect(u.username + u.password).toBe("");
  }
});

test("400px: the drawer fits the viewport (no horizontal scroll, dialog <= 400px wide)", async ({ page }) => {
  await page.setViewportSize({ width: 400, height: 800 });
  await loaded(page);
  await page.locator('.lane[data-k="exploited"] [data-testid="lane-row"]').first().click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText("Acme Gateway 4.2")).toBeVisible();
  const m = await page.evaluate(() => ({
    doc: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
    dialog: document.querySelector('[role="dialog"]')!.getBoundingClientRect().width,
  }));
  expect(m.doc).toBeLessThanOrEqual(400);
  expect(m.body).toBeLessThanOrEqual(400);
  expect(m.dialog).toBeLessThanOrEqual(400);
});

test("/search?q=x redirects to /history?q=x and the History nav link is visible", async ({ page }) => {
  await page.goto("/search?q=x");
  await expect(page).toHaveURL(/\/history\?q=x$/);
  await expect(page.getByRole("heading", { level: 1, name: "History" })).toBeVisible();
  await expect(page.getByRole("link", { name: "History" })).toBeVisible();
  await expect(page.getByTestId("search-row")).toHaveCount(1);
  await page.getByRole("tab", { name: "Stories" }).click();
  await expect(page).toHaveURL(/\/history\?tab=stories$/);
  await expect(page.getByTestId("history-story")).toHaveCount(1);
});
