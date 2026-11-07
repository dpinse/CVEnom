import AxeBuilder from "@axe-core/playwright";
import { canvasCentreStdDev, CVE_ID, expect, loaded, STDDEV_MIN, test } from "./harness";

const LANES = ["Exploited now", "Likely next", "Loud now", "Fresh criticals"];

test("dashboard renders the four lanes with fixture rows", async ({ page, guards }) => {
  await loaded(page);
  expect(guards.apiRequests.some((r) => r.startsWith("/api/lanes") && r.includes("limit=10"))).toBe(true);
  await expect(page.locator('.lane[data-k="exploited"] .lane-foot a')).toHaveAttribute("href", /&sort=priority$/);
  for (const name of LANES) await expect(page.getByRole("heading", { level: 2, name })).toBeVisible();
  await expect(page.locator(".lane")).toHaveCount(4);
  for (const k of ["exploited", "likely", "loud", "fresh"]) {
    await expect(page.locator(`.lane[data-k="${k}"] [data-testid="lane-row"]`)).toHaveCount(2);
  }
});

test("dashboard shows the summary line, the map panel, compact lanes that scroll inside themselves and the volume chart", async ({
  page,
}) => {
  await loaded(page);
  await expect(page.getByRole("heading", { level: 1, name: "Last 7 days" })).toBeVisible();
  await expect(page.locator(".today")).toBeVisible();
  await expect(page.getByRole("region", { name: "Threat geography" })).toBeVisible();
  for (const k of ["exploited", "likely", "loud", "fresh"]) {
    // the list is capped at ~5 rows of height and scrolls inside the lane; the page never grows with it
    const m = await page.locator(`.lane[data-k="${k}"] .lane-items`).evaluate((el) => ({
      overflowY: getComputedStyle(el).overflowY,
      height: el.clientHeight,
      rowH: el.querySelector<HTMLElement>(".row")?.getBoundingClientRect().height ?? 0,
    }));
    expect(m.overflowY).toBe("auto");
    expect(m.height).toBeLessThanOrEqual(5 * 52);
    expect(m.rowH, "compact two-line row").toBeLessThanOrEqual(56);
  }
  await expect(page.getByRole("heading", { level: 2, name: /New CVEs per/ })).toBeVisible();
  await expect(page.getByRole("img", { name: /New CVEs per .*, stacked by severity/ })).toBeVisible();
});

test("the 24h range sets ?range=24h and the lanes request carries range=24h", async ({ page, guards }) => {
  await loaded(page);
  await page.getByRole("button", { name: "24h" }).click();
  await expect(page).toHaveURL(/[?&]range=24h/);
  await expect
    .poll(() => guards.apiRequests.some((r) => r.startsWith("/api/lanes") && r.includes("range=24h")))
    .toBe(true);
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
  await expect
    .poll(() => page.evaluate(() => (window as unknown as { __wsAttempts: string[] }).__wsAttempts.length))
    .toBeGreaterThan(0);
  const attempts = await page.evaluate(() => (window as unknown as { __wsAttempts: string[] }).__wsAttempts);
  const pageOrigin = new URL(page.url()).origin;
  for (const raw of attempts) {
    const u = new URL(raw);
    expect(u.origin).toBe(pageOrigin.replace(/^http/g, "ws"));
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

test("/search?q=x redirects to /threats?q=x and the Threats nav link is current", async ({ page }) => {
  await page.goto("/search?q=x");
  await expect(page).toHaveURL(/\/threats\?q=x$/);
  await expect(page.getByRole("heading", { level: 1, name: "Threats" })).toBeVisible();
  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByRole("link", { name: "Threats" })).toHaveAttribute("aria-current", "page");
  await expect(page.getByRole("group", { name: "Time range" })).toHaveCount(0);
  await expect(page.getByTestId("search-row")).toHaveCount(1);
  await page.getByRole("tab", { name: "News" }).click();
  await expect(page).toHaveURL(/\/threats\?tab=news$/);
  await expect(page.getByTestId("news-story")).toHaveCount(1);
});

test("the range control shows on the Dashboard only and writes ?range=", async ({ page }) => {
  await loaded(page);
  await page.getByRole("button", { name: "14d" }).click();
  await expect(page).toHaveURL(/[?&]range=14d/);
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Threats" }).click();
  await expect(page.getByRole("group", { name: "Time range" })).toHaveCount(0);
});

test.describe("country side panel", () => {
  const sideList = (page: import("@playwright/test").Page) => page.getByRole("list", { name: "Top countries" });

  test("Tab to Germany in the side list, Enter shows its panel; All countries returns to the list", async ({
    page,
  }) => {
    await loaded(page);
    await expect(page.locator(".globe-map canvas").first()).toBeVisible({ timeout: 20_000 });
    const buttons = sideList(page).getByRole("button");
    await expect(buttons.first()).toContainText("United States"); // the fixture's busiest country
    // Tabbing on from the map canvas passes the legend's attribution link, then enters the side list.
    await page.locator(".globe-map canvas").first().focus();
    await page.keyboard.press("Tab");
    await expect(page.locator(".map-legend .geo-attrib")).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(buttons.first()).toBeFocused();
    const de = buttons.filter({ hasText: "Germany" });
    for (let n = 0; n < 6 && !(await de.evaluate((el) => el === document.activeElement)); n++) {
      await page.keyboard.press("Tab");
    }
    await expect(de).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/[?&]country=DE/);
    const side = page.getByRole("complementary", { name: "Country detail" });
    await expect(side.getByRole("heading", { name: "Germany" })).toBeVisible();
    await expect(side.getByText("exploit scanning")).toBeVisible();
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await side.getByRole("button", { name: "All countries" }).click();
    await expect(page).not.toHaveURL(/country=/);
    await expect(sideList(page)).toBeVisible();
  });

  test("the map defaults to flat, switches to the globe, and the choice survives a reload", async ({ page }) => {
    await loaded(page);
    const group = page.getByRole("group", { name: "Map projection" });
    await expect(group.getByRole("button", { name: "Flat" })).toHaveAttribute("aria-pressed", "true");
    await group.getByRole("button", { name: "Globe" }).click();
    await expect(group.getByRole("button", { name: "Globe" })).toHaveAttribute("aria-pressed", "true");
    await page.reload();
    await expect(
      page.getByRole("group", { name: "Map projection" }).getByRole("button", { name: "Globe" }),
    ).toHaveAttribute("aria-pressed", "true");
    await expect(page.locator(".globe-map canvas").first()).toBeVisible({ timeout: 20_000 });
  });

  test("the legend and the DB-IP credit show", async ({ page }) => {
    await loaded(page);
    await expect(page.locator(".map-legend")).toContainText(/more alerts · 5 countries · 7 days/);
    await expect(page.locator(".map-legend").getByRole("link", { name: "IP geolocation by DB-IP.com" })).toBeVisible();
    // The side panel carries its own credit (stacked layouts can scroll the legend away).
    await expect(
      page
        .getByRole("complementary", { name: "Country detail" })
        .getByRole("link", { name: "IP geolocation by DB-IP.com" }),
    ).toBeVisible();
  });

  test("no horizontal overflow at 400px with a country selected", async ({ page }) => {
    await page.setViewportSize({ width: 400, height: 800 });
    await page.goto("/?country=DE");
    const side = page.getByRole("complementary", { name: "Country detail" });
    await expect(side.getByRole("heading", { name: "Germany" })).toBeVisible();
    await expect(side.getByText("exploit scanning")).toBeVisible();
    const m = await page.evaluate(() => {
      const el = document.querySelector<HTMLElement>(".side")!;
      return { side: [el.scrollWidth, el.clientWidth], doc: [document.documentElement.scrollWidth, innerWidth] };
    });
    expect(m.side[0]).toBeLessThanOrEqual(m.side[1]);
    expect(m.doc[0]).toBeLessThanOrEqual(m.doc[1]);
  });

  test("CVE -> country chip lands on the dashboard side panel; Back returns to the CVE dialog, Forward to the country", async ({
    page,
  }) => {
    await loaded(page);
    await page.locator('.lane[data-k="exploited"] [data-testid="lane-row"]').first().click();
    await expect(page).toHaveURL(new RegExp(`[?&]cve=${CVE_ID}`));
    const dialog = page.getByRole("dialog");
    await expect(dialog).toHaveCount(1);
    await dialog.getByRole("link", { name: "United States" }).click();
    await expect(page).toHaveURL(/[?&]country=US/);
    await expect(dialog).toHaveCount(0);
    const side = page.getByRole("complementary", { name: "Country detail" });
    await expect(side.getByRole("heading", { name: "United States" })).toBeVisible();
    await page.goBack();
    await expect(page).toHaveURL(new RegExp(`[?&]cve=${CVE_ID}`));
    await expect(dialog).toHaveCount(1);
    await expect(dialog.getByText("Acme Gateway 4.2")).toBeVisible();
    await expect.poll(() => page.evaluate(() => !!document.activeElement?.closest('[role="dialog"]'))).toBe(true);
    await page.goForward();
    await expect(page).toHaveURL(/[?&]country=US/);
    await expect(dialog).toHaveCount(0);
    await expect(side.getByRole("heading", { name: "United States" })).toBeVisible();
  });

  test("opening a CVE from the country panel keeps ?country= and closing returns to the panel (R7)", async ({
    page,
  }) => {
    await page.goto("/?country=DE");
    const side = page.getByRole("complementary", { name: "Country detail" });
    await side.getByRole("button", { name: new RegExp(CVE_ID) }).click();
    await expect(page).toHaveURL(new RegExp(`country=DE.*cve=${CVE_ID}|cve=${CVE_ID}.*country=DE`));
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByText("Acme Gateway 4.2")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    await expect(page).toHaveURL(/[?&]country=DE/);
    await expect(side.getByRole("heading", { name: "Germany" })).toBeVisible();
  });
});
