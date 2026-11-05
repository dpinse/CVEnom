import { defineConfig, devices } from "@playwright/test";

/** Smoke tests run against the production build served by `vite preview`; the API and WebSocket are mocked in the specs. */
export default defineConfig({
  testDir: "./e2e",
  testMatch: /.*\.spec\.ts/,
  fullyParallel: true,
  // software WebGL is CPU-heavy: keep the pool small so pixel/canvas assertions are not starved
  workers: 2,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: "http://localhost:4173",
    trace: "retain-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
  ],
  webServer: [
    {
      command: "npm run build && npm run preview -- --port 4173 --strictPort",
      url: "http://localhost:4173",
      reuseExistingServer: false,
      timeout: 180_000,
    },
    {
      // csp.spec.ts: the same dist/ with the headers parsed from nginx.conf. Started after the build above.
      command: "node e2e/csp-server.mjs",
      url: "http://127.0.0.1:4174/healthz",
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
});
