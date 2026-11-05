import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test as base, expect, type Page } from "@playwright/test";

const FIXTURES = join(import.meta.dirname, "fixtures");
const fixture = (name: string): string => readFileSync(join(FIXTURES, `${name}.json`), "utf8");

export const CVE_ID = "CVE-2026-1001";
const ORIGIN = "http://localhost:4173";

/** Replaces window.WebSocket with a socket that never connects, so no real WS is ever attempted. */
const FAKE_WS = `
  window.__wsAttempts = [];
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

async function mockApi(page: Page, unexpected: string[]) {
  await page.route("**/api/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/health") return route.fulfill(json(fixture("health")));
    if (path === "/api/lanes") return route.fulfill(json(fixture("lanes")));
    if (path === "/api/velocity") return route.fulfill(json(fixture("velocity")));
    if (path === "/api/geo") return route.fulfill(json(fixture("geo")));
    if (path === "/api/stories/loud") return route.fulfill(json(fixture("loud")));
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
}

/**
 * Every test gets: the mocked API, a stubbed WebSocket, and collectors for page errors, console errors
 * and off-origin requests, all asserted empty after the test body.
 */
export const test = base.extend<{ guards: Guards }>({
  guards: [
    async ({ page }, use) => {
      const guards: Guards = { consoleErrors: [], offOrigin: [], unexpectedApi: [] };
      page.on("pageerror", (e) => guards.consoleErrors.push(`pageerror: ${e.message}`));
      page.on("console", (m) => {
        if (m.type() !== "error") return;
        // The browser logs the guest's mocked 401 from /api/auth/refresh as a console error by itself; it is the
        // only expected one (the app handles it and stays a guest).
        if (m.location().url.endsWith("/api/auth/refresh") && /401/.test(m.text())) return;
        guards.consoleErrors.push(`console.error: ${m.text()}`);
      });
      page.on("request", (r) => {
        const u = r.url();
        if (u.startsWith("data:") || u.startsWith("blob:") || u.startsWith("about:")) return;
        if (new URL(u).origin !== ORIGIN) guards.offOrigin.push(u);
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

export { expect };
