import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Page } from "@playwright/test";
import { canvasCentreStdDev, CVE_ID, expect, loaded, STDDEV_MIN, test } from "./harness";

/**
 * The production dist/ served by e2e/csp-server.mjs with exactly the response headers parsed from nginx.conf.
 * Any CSP violation (inline script/style, blob: worker, off-origin request, ws/wss) fails the test.
 */
test.use({ baseURL: "http://127.0.0.1:4174" });

const CONF = readFileSync(join(import.meta.dirname, "../nginx.conf"), "utf8");
const CSP = /add_header Content-Security-Policy "([^"]+)" always;/.exec(CONF)![1];

type Violation = { directive: string; blocked: string; sample: string };
type Win = Window & { __cspViolations: Violation[]; __RealWebSocket: typeof WebSocket };

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    const w = window as unknown as Win;
    w.__cspViolations = [];
    document.addEventListener("securitypolicyviolation", (e) => {
      w.__cspViolations.push({ directive: e.violatedDirective, blocked: e.blockedURI, sample: e.sample });
    });
  });
});

const violations = (page: Page) => page.evaluate(() => (window as unknown as Win).__cspViolations);

test("the server really applies the nginx.conf headers", async ({ request }) => {
  const res = await request.get("/");
  const h = res.headers();
  expect(h["content-security-policy"]).toBe(CSP);
  expect(h["x-content-type-options"]).toBe("nosniff");
  expect(h["x-frame-options"]).toBe("DENY");
  expect(h["referrer-policy"]).toBe("no-referrer");
  expect(h["strict-transport-security"]).toBe("max-age=63072000; includeSubDomains");
  expect(h["cross-origin-opener-policy"]).toBe("same-origin");
  expect(h["cross-origin-resource-policy"]).toBe("same-origin");
  expect(h["permissions-policy"]).toContain("camera=()");
  expect(h["cache-control"]).toBe("no-store");
  expect(CSP).not.toMatch(/unsafe-inline|unsafe-eval|blob:/);
});

test("dashboard under the production CSP: zero violations, the globe draws, no console errors", async ({ page, guards }) => {
  await loaded(page);
  await expect(page.locator(".globe-map canvas").first()).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText("Couldn't load the map")).toHaveCount(0);
  await expect.poll(() => canvasCentreStdDev(page), { timeout: 20_000 }).toBeGreaterThan(STDDEV_MIN);
  expect(await violations(page)).toEqual([]);
  expect(guards.consoleErrors).toEqual([]);
});

test("theme toggle and the drawer under the production CSP: still zero violations", async ({ page, guards }) => {
  await loaded(page);
  await expect(page.locator(".globe-map canvas").first()).toBeVisible({ timeout: 20_000 });
  const before = (await page.locator("html").getAttribute("data-theme")) ?? "";
  await page.getByRole("button", { name: "Dark theme" }).click();
  await expect(page.locator("html")).not.toHaveAttribute("data-theme", before);
  await page.locator('.lane[data-k="exploited"] [data-testid="lane-row"]').first().click();
  await expect(page).toHaveURL(new RegExp(`[?&]cve=${CVE_ID}`));
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("Acme Gateway 4.2")).toBeVisible();
  await expect.poll(() => canvasCentreStdDev(page), { timeout: 20_000 }).toBeGreaterThan(STDDEV_MIN);
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  expect(await violations(page)).toEqual([]);
  expect(guards.consoleErrors).toEqual([]);
});

test("connect-src 'self' permits a same-origin WebSocket (no ws:/wss: needed)", async ({ page }) => {
  await loaded(page);
  const result = await page.evaluate(
    () =>
      new Promise<string>((resolve) => {
        const w = window as unknown as Win;
        const ws = new w.__RealWebSocket(`ws://${location.host}/api/ws/live`);
        ws.onopen = () => resolve("open");
        ws.onerror = () => resolve("error");
        setTimeout(() => resolve("timeout"), 5000);
      }),
  );
  expect(result).toBe("open");
  expect(await violations(page)).toEqual([]);
});

test("positive controls: the violation collector sees off-origin fetches and WebSockets", async ({ page, guards }) => {
  await loaded(page);
  await page.evaluate(() => {
    const w = window as unknown as Win;
    void fetch("https://evil.example/x").catch(() => {});
    try {
      new w.__RealWebSocket("wss://evil.example/ws").onerror = () => {};
    } catch {
      /* a synchronous block is fine too */
    }
  });
  await expect.poll(async () => (await violations(page)).map((v) => v.directive).sort()).toEqual(["connect-src", "connect-src"]);
  // The blocked attempts also log console errors / show up as requests; they are the expected outcome here.
  guards.consoleErrors.length = 0;
  guards.offOrigin.length = 0;
});
