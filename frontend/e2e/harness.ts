import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test as base, expect, type Page, type Route } from "@playwright/test";

const FIXTURES = join(import.meta.dirname, "fixtures");
const fixture = (name: string): string => readFileSync(join(FIXTURES, `${name}.json`), "utf8");

export const CVE_ID = "CVE-2026-1001";

/** Replaces window.WebSocket with a socket that never connects, so no real WS is ever attempted. */
const FAKE_WS = `
  window.__wsAttempts = [];
  window.__RealWebSocket = window.WebSocket;
  class FakeWebSocket extends EventTarget {
    constructor(url) {
      super();
      this.url = String(url);
      this.readyState = 0;
      this.onopen = this.onmessage = this.onclose = this.onerror = null;
      window.__wsAttempts.push(this.url);
    }
    send() {}
    close() { this.readyState = 3; }
  }
  FakeWebSocket.CONNECTING = 0; FakeWebSocket.OPEN = 1; FakeWebSocket.CLOSING = 2; FakeWebSocket.CLOSED = 3;
  window.WebSocket = FakeWebSocket;
`;

function json(body: string, status = 200) {
  return { status, contentType: "application/json", body };
}

/** GET /api/story?url=: the loud-feed stories (no details) plus the ransomware.live fixture; anything else is the backend's 404. */
function storyByUrl(url: string | null) {
  const loud = JSON.parse(fixture("loud")) as { url: string }[];
  const found = [...loud.map((s) => ({ ...s, details: {} })), JSON.parse(fixture("story")) as { url: string }].find(
    (s) => s.url === url,
  );
  return found ? json(JSON.stringify(found)) : json('{"error":"not_found"}', 404);
}

async function mockApi(page: Page, unexpected: string[]) {
  await page.route("**/api/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/health") return route.fulfill(json(fixture("health")));
    if (path === "/api/lanes") return route.fulfill(json(fixture("lanes")));
    if (path === "/api/summary") return route.fulfill(json(fixture("summary")));
    if (path === "/api/volume") return route.fulfill(json(fixture("volume")));
    if (path === "/api/geo") return route.fulfill(json(fixture("geo")));
    const geoCc = /^\/api\/geo\/([A-Z]{2})$/.exec(path)?.[1]; // anonymous: events is null
    if (geoCc) return route.fulfill(json(JSON.stringify({ ...JSON.parse(fixture("geo-DE")), country_code: geoCc })));
    if (path === "/api/stories/loud") return route.fulfill(json(fixture("loud")));
    if (path === "/api/cves") return route.fulfill(json(fixture("cves")));
    if (path === "/api/stories") return route.fulfill(json(fixture("stories")));
    if (path === "/api/story") return route.fulfill(storyByUrl(new URL(route.request().url()).searchParams.get("url")));
    if (path === `/api/cves/${CVE_ID}`) return route.fulfill(json(fixture(`cve-${CVE_ID}`)));
    if (path === "/api/auth/refresh") return route.fulfill(json('{"error":"unauthorized"}', 401)); // stays a guest
    unexpected.push(`${route.request().method()} ${path}`);
    return route.fulfill(json('{"error":"not_found"}', 404));
  });
}

interface Guards {
  consoleErrors: string[];
  offOrigin: string[];
  unexpectedApi: string[];
  /** Every /api request's path + query, in order (the request log specs assert against). */
  apiRequests: string[];
}

/**
 * Every test gets: the mocked API, a stubbed WebSocket, and collectors for page errors, console errors
 * and off-origin requests, all asserted empty after the test body.
 */
export const test = base.extend<{ guards: Guards }>({
  guards: [
    async ({ page, baseURL }, use) => {
      const origin = new URL(baseURL ?? "http://localhost:4173").origin;
      const guards: Guards = { consoleErrors: [], offOrigin: [], unexpectedApi: [], apiRequests: [] };
      page.on("pageerror", (e) => guards.consoleErrors.push(`pageerror: ${e.message}`));
      page.on("console", (m) => {
        if (m.type() !== "error") return;
        // The browser logs the guest's mocked 401 from /api/auth/refresh as a console error by itself; it is the
        // only expected one (the app handles it and stays a guest).
        if (m.location().url.endsWith("/api/auth/refresh") && /401/.test(m.text())) return;
        // Likewise the browser's own line for a mocked 401 from the MFA code step (mfa.spec's rejected-code test).
        if (m.location().url.endsWith("/api/auth/mfa/verify") && /401/.test(m.text())) return;
        guards.consoleErrors.push(`console.error: ${m.text()}`);
      });
      page.on("request", (r) => {
        const u = r.url();
        const parsed = new URL(u.startsWith("http") ? u : "http://x/");
        if (parsed.pathname.startsWith("/api/") && !u.startsWith("ws"))
          guards.apiRequests.push(parsed.pathname + parsed.search);
        // Not network requests to a third party, so they are not "off-origin":
        //  - data:  inline images/fonts the app or MapLibre embeds (no network);
        //  - blob:  same-origin object URLs the page itself minted (e.g. MapLibre's canvas/worker plumbing);
        //  - about: about:blank frames/documents.
        // Anything else must be exactly the page origin. A real remote request still fails the test.
        if (u.startsWith("data:") || u.startsWith("blob:") || u.startsWith("about:")) return;
        if (new URL(u).origin !== origin) guards.offOrigin.push(u);
      });
      await page.addInitScript(FAKE_WS);
      await mockApi(page, guards.unexpectedApi);
      await use(guards);
      expect(guards.consoleErrors, "console errors / page errors").toEqual([]);
      expect(guards.offOrigin, "off-origin requests").toEqual([]);
      expect(guards.unexpectedApi, "unmocked API calls").toEqual([]);
    },
    { auto: true },
  ],
});

/** Two-step sign-in fixtures (password -> MFA ticket -> TOTP code or enrollment). Never real secrets. */
export const MFA = {
  member: { id: 7, email: "member@example.test", role: "member" },
  password: "e2e correct horse battery",
  ticket: "e2e-mfa-ticket-0123456789",
  token: "e2e-access-token",
  secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
  code: "123456",
  recoveryCodes: Array.from({ length: 10 }, (_, i) => `e2e${i}-rcvr-code-abcd`),
};

/**
 * Mock the two-step sign-in. `enroll` makes the account one that has not set up MFA yet. Returns the
 * request log (method, path and JSON body) so specs can assert what was sent where. These routes are
 * registered after the harness's catch-all, so Playwright consults them first.
 */
export async function mockTwoStepSignIn(page: Page, opts: { enroll?: boolean } = {}) {
  const log: { method: string; path: string; url: string; body: unknown }[] = [];
  const record = (route: Route) => {
    const r = route.request();
    log.push({ method: r.method(), path: new URL(r.url()).pathname, url: r.url(), body: r.postDataJSON() });
  };
  const token = { access_token: MFA.token, token_type: "bearer", expires_in: 900 };
  await page.route("**/api/auth/login", (route) => {
    record(route);
    return route.fulfill(json(JSON.stringify({ ticket: MFA.ticket, enroll_required: !!opts.enroll, expires_in: 300 })));
  });
  await page.route("**/api/auth/mfa/verify", (route) => {
    record(route);
    return route.fulfill(json(JSON.stringify(token)));
  });
  await page.route("**/api/auth/mfa/enroll/start", (route) => {
    record(route);
    const uri = `otpauth://totp/CVEnom:member%40example.test?secret=${MFA.secret}&issuer=CVEnom&algorithm=SHA1&digits=6&period=30`;
    return route.fulfill(json(JSON.stringify({ secret: MFA.secret, otpauth_uri: uri })));
  });
  await page.route("**/api/auth/mfa/enroll/finish", (route) => {
    record(route);
    return route.fulfill(json(JSON.stringify({ ...token, recovery_codes: MFA.recoveryCodes })));
  });
  await page.route("**/api/auth/me", (route) =>
    route.request().headers()["authorization"] === `Bearer ${MFA.token}`
      ? route.fulfill(json(JSON.stringify(MFA.member)))
      : route.fulfill(json('{"error":"unauthorized"}', 401)),
  );
  return log;
}

/** Fill and submit the password step. */
export async function passwordStep(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(MFA.member.email);
  await page.getByLabel("Password").fill(MFA.password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

export async function loaded(page: Page) {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 2, name: "Exploited now" })).toBeVisible();
  await expect(page.locator('.lane[data-k="exploited"] [data-testid="lane-row"]').first()).toBeVisible();
}

/** A globe canvas smaller than this is a collapsed/failed map, not a render. */
export const MIN_CANVAS = 200;

/** Standard deviation of luminance over a centre crop of the globe canvas, measured from a real screenshot. 0 for a missing or collapsed canvas. */
export async function canvasCentreStdDev(page: Page): Promise<number> {
  const canvas = page.locator(".globe-map canvas").first();
  await canvas.scrollIntoViewIfNeeded(); // a taller page above the lanes can leave the globe scrolled out of the clip
  const box = await canvas.boundingBox();
  if (!box || box.width < MIN_CANVAS || box.height < MIN_CANVAS) return 0;
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

export const STDDEV_MIN = 4;

export { expect };
