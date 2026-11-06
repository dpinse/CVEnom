import { readFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { join } from "node:path";
import type { APIResponse, Page } from "@playwright/test";
import { canvasCentreStdDev, CVE_ID, expect, loaded, STDDEV_MIN, test } from "./harness";
import { cspFor } from "./nginxHeaders.ts";

/**
 * The production dist/ served by e2e/csp-server.mjs with exactly the response headers parsed from nginx.conf.
 * Any CSP violation (inline script/style, blob: worker, off-origin request, ws/wss) fails the test.
 */
test.use({ baseURL: "http://127.0.0.1:4174" });

const CONF = readFileSync(join(import.meta.dirname, "../nginx.conf"), "utf8");
/** The SPA policy and the /api/ policy, both read from nginx.conf's `map $uri $csp`. */
const CSP = cspFor(CONF, "/");
const API_CSP = cspFor(CONF, "/api/");

/** Every Content-Security-Policy header line on a response (a duplicate would be two entries). */
const cspHeaders = (res: APIResponse) =>
  res
    .headersArray()
    .filter((h) => h.name.toLowerCase() === "content-security-policy")
    .map((h) => h.value);

/** Raw WebSocket handshake against the CSP server; resolves with the 101 response's raw headers. */
function wsHandshakeHeaders(): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      host: "127.0.0.1",
      port: 4174,
      path: "/api/ws/live",
      headers: {
        Connection: "Upgrade",
        Upgrade: "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
      },
    });
    req.on("upgrade", (res, socket) => {
      socket.destroy();
      resolve(res.rawHeaders);
    });
    req.on("response", (res) => reject(new Error(`no upgrade: HTTP ${res.statusCode}`)));
    req.on("error", reject);
    req.end();
  });
}

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

test("per-URI CSP: the SPA shell, its fallback and /assets/* get the SPA policy, exactly once", async ({ request }) => {
  const shell = await request.get("/");
  expect(cspHeaders(shell)).toEqual([CSP]);
  expect(cspHeaders(await request.get("/some/spa/route"))).toEqual([CSP]);
  const asset = /<script[^>]+src="(\/assets\/[^"]+\.js)"/.exec(await shell.text())?.[1];
  expect(asset).toBeTruthy();
  const res = await request.get(asset!);
  expect(res.status()).toBe(200);
  expect(cspHeaders(res)).toEqual([CSP]);
  expect(cspHeaders(await request.get("/assets/missing-0000.js"))).toEqual([CSP]); // the 404 too
  expect(CSP).toContain("script-src 'self'");
});

test("per-URI CSP: /api/ responses (here nginx's own 502) get the api's strict policy, exactly once", async ({
  request,
}) => {
  expect(API_CSP).not.toBe(CSP);
  expect(API_CSP).toMatch(/^default-src 'none';/);
  expect(API_CSP).toContain("frame-ancestors 'none'");
  const res = await request.get("/api/health");
  expect(res.status()).toBe(502);
  expect(cspHeaders(res)).toEqual([API_CSP]);
  expect(res.headers()["x-content-type-options"]).toBe("nosniff");
  expect(res.headers()["cache-control"]).toBeUndefined(); // the api's own Cache-Control passes through
  // A path outside /api/ that merely contains it keeps the SPA policy.
  expect(cspHeaders(await request.get("/apix/health"))).toEqual([CSP]);
});

test("per-URI CSP: the /api/ws/live WebSocket handshake gets the api's strict policy, exactly once", async () => {
  const raw = await wsHandshakeHeaders();
  const csp = raw.filter((_, i) => i % 2 === 1 && raw[i - 1].toLowerCase() === "content-security-policy");
  expect(csp).toEqual([API_CSP]);
  expect(API_CSP).not.toBe(CSP);
});

test("dashboard under the production CSP: zero violations, the globe draws, no console errors", async ({
  page,
  guards,
}) => {
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
  await expect
    .poll(async () => (await violations(page)).map((v) => v.directive).sort())
    .toEqual(["connect-src", "connect-src"]);
  // The blocked attempts also log console errors / show up as requests; they are the expected outcome here.
  guards.consoleErrors.length = 0;
  guards.offOrigin.length = 0;
});
