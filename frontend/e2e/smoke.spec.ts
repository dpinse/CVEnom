import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";
import { CVE_ID, expect, test } from "./harness";

const LANES = ["Exploited now", "Likely next", "Loud now", "Fresh criticals"];

async function loaded(page: Page) {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 2, name: "Exploited now" })).toBeVisible();
  await expect(page.locator('.lane[data-k="exploited"] [data-testid="lane-row"]').first()).toBeVisible();
}

/** Standard deviation of luminance over a centre crop of the globe canvas, measured from a real screenshot. */
async function canvasCentreStdDev(page: Page): Promise<number> {
  const box = await page.locator(".globe-map canvas").first().boundingBox();
  if (!box) return 0;
  const size = 120;
  const clip = {
    x: box.x + box.width / 2 - size / 2,
    y: box.y + box.height / 2 - size / 2,
    width: size,
    height: size,
  };
  const png = (await page.screenshot({ clip })).toString("base64");
  return page.evaluate(async (b64) => {
    const img = new Image();
    img.src = `data:image/png;base64,${b64}`;
    await img.decode();
    const c = document.createElement("canvas");
    c.width = img.width;
    c.height = img.height;
    const ctx = c.getContext("2d")!;
    ctx.drawImage(img, 0, 0);
    const { data } = ctx.getImageData(0, 0, c.width, c.height);
    const lum: number[] = [];
    for (let i = 0; i < data.length; i += 4) lum.push(0.2126 * data[i] + 0.7152 * data[i + 1] + 0.0722 * data[i + 2]);
    const mean = lum.reduce((a, b) => a + b, 0) / lum.length;
    return Math.sqrt(lum.reduce((a, b) => a + (b - mean) ** 2, 0) / lum.length);
  }, png);
}

const STDDEV_MIN = 4;

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
