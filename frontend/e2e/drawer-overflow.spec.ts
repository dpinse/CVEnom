import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Page } from "@playwright/test";
import { CVE_ID, expect, test } from "./harness";

/**
 * Long unbroken strings (a minified blob, a tracking URL, a vector) must wrap inside the drawer: neither the dialog, its body
 * nor the document may scroll horizontally. Routes registered here win over the harness's.
 */
const BLOB = "A".repeat(600);
const LONG_REF = `https://refs.example/${"b".repeat(280)}`;
const LONG_VECTOR = `CVSS:3.1/${"AV:N/".repeat(60)}`;
const LONG_TITLE = `T${"x".repeat(300)}`;
const STORY_URL = "https://news.example/overflow";

const SIZES = [
  { width: 1280, height: 800 },
  { width: 400, height: 800 },
];

for (const size of SIZES) {
  test.describe(`${size.width}px`, () => {
    test.use({ viewport: size });

    async function expectNoOverflow(page: Page) {
      const m = await page.evaluate(() => {
        const dlg = document.querySelector<HTMLElement>('[role="dialog"]')!;
        const body = document.querySelector<HTMLElement>(".dbody")!;
        // an element that sticks out of the dialog is clipped by overflow-x:hidden; report it by name
        const dlgRight = dlg.getBoundingClientRect().right;
        const out = Array.from(dlg.querySelectorAll<HTMLElement>("*"))
          .filter((el) => el.getBoundingClientRect().right > dlgRight + 1)
          .map((el) => `${el.tagName.toLowerCase()}.${el.className}`);
        return {
          dlg: [dlg.scrollWidth, dlg.clientWidth],
          body: [body.scrollWidth, body.clientWidth],
          doc: [document.documentElement.scrollWidth, innerWidth],
          out: out.slice(0, 8),
        };
      });
      expect(m.out, "elements sticking out of the dialog").toEqual([]);
      expect(m.dlg[0], "dialog scrollWidth").toBeLessThanOrEqual(m.dlg[1]);
      expect(m.body[0], ".dbody scrollWidth").toBeLessThanOrEqual(m.body[1]);
      expect(m.doc[0], "document scrollWidth").toBeLessThanOrEqual(m.doc[1]);
    }

    test("CVE drawer with long unbroken summary, reference and vector", async ({ page }) => {
      const base = JSON.parse(readFileSync(join(import.meta.dirname, "fixtures", `cve-${CVE_ID}.json`), "utf8"));
      await page.route(`**/api/cves/${CVE_ID}`, (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            ...base,
            summary: BLOB,
            cvss_vector: LONG_VECTOR,
            kev_name: LONG_TITLE,
            kev_action: BLOB,
            cwes: ["CWE-79"],
            references: [{ url: LONG_REF, tags: ["Vendor Advisory", "x".repeat(200)] }],
          }),
        }),
      );
      await page.goto(`/?cve=${CVE_ID}`);
      await expect(page.getByRole("dialog")).toBeVisible();
      await expect(page.getByRole("dialog")).toContainText("AAAAAAAAAA");
      await expectNoOverflow(page);
    });

    test("story drawer with long unbroken title and summary", async ({ page }) => {
      await page.route("**/api/story*", (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            title: LONG_TITLE,
            summary: BLOB,
            url: STORY_URL,
            source: "Example News",
            published: "2026-11-05T09:00:00Z",
            cve_ids: [CVE_ID],
            details: {},
          }),
        }),
      );
      await page.goto(`/?story=${encodeURIComponent(STORY_URL)}`);
      await expect(page.getByRole("dialog")).toBeVisible();
      await expect(page.getByRole("dialog")).toContainText("xxxxxxxxxx");
      await expectNoOverflow(page);
    });
  });
}
