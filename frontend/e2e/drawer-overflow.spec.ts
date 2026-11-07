import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Page } from "@playwright/test";
import { CVE_ID, expect, test } from "./harness";

/**
 * Long unbroken strings (a minified blob, a tracking URL, a vector) must wrap inside the drawer: neither the dialog, its body
 * nor the document may scroll horizontally. Routes registered here win over the harness's.
 */
const BLOB = "A".repeat(600);
const LONG_URL = `https://tracker.example/${"u".repeat(300)}`;
const LONG_REF = `https://refs.example/${"b".repeat(280)}`;
const LONG_VECTOR = `CVSS:3.1/${"AV:N/".repeat(60)}`;
const LONG_TITLE = `T${"x".repeat(300)}`;
const STORY_URL = "https://news.example/overflow";

const SIZES = [
  { width: 1280, height: 800 },
  { width: 400, height: 800 },
  { width: 320, height: 500 },
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
      await page.route(`**/api/cves/${CVE_ID}?*`, (route) =>
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

    test("CVE drawer with a very long summary scrolls inside the drawer and is not cut off", async ({ page }) => {
      const base = JSON.parse(readFileSync(join(import.meta.dirname, "fixtures", `cve-${CVE_ID}.json`), "utf8"));
      const sentences = Array.from(
        { length: 40 },
        (_, i) => `Sentence ${i + 1} describes the flaw in ordinary words and keeps going for a while.`,
      );
      const summary = `${sentences.join(" ")} See ${LONG_URL} for details. ENDOFSUMMARY`;
      await page.route(`**/api/cves/${CVE_ID}?*`, (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            ...base,
            summary,
            affected: Array.from({ length: 50 }, (_, i) => `Vendor-Product-${i}-${"p".repeat(200)}`),
            references: Array.from({ length: 20 }, (_, i) => ({
              url: `https://refs.example/${i}/${"c".repeat(120)}`,
              tags: ["Patch"],
            })),
          }),
        }),
      );
      await page.goto(`/?cve=${CVE_ID}`);
      const dialog = page.getByRole("dialog");
      await expect(dialog).toBeVisible();
      await expect(dialog).toContainText("Sentence 40");
      // measure only once the open (slide-in) animation has finished
      await dialog.evaluate((el) => Promise.all(el.getAnimations({ subtree: true }).map((an) => an.finished)));
      await expectNoOverflow(page);
      const m = await page.evaluate(() => {
        const dlg = document.querySelector<HTMLElement>('[role="dialog"]')!;
        const body = document.querySelector<HTMLElement>(".dbody")!;
        const scrollable = body.scrollHeight > body.clientHeight;
        body.scrollTop = body.scrollHeight;
        const last = body.lastElementChild!.getBoundingClientRect();
        const sum = Array.from(body.querySelectorAll<HTMLElement>(".sum")).find((e) =>
          e.textContent?.includes("ENDOFSUMMARY"),
        );
        sum?.scrollIntoView();
        const s = sum?.getBoundingClientRect();
        return {
          scrollable,
          lastBottom: last.bottom,
          dlgBottom: dlg.getBoundingClientRect().bottom,
          dlgRight: dlg.getBoundingClientRect().right,
          dlgLeft: dlg.getBoundingClientRect().left,
          sumInView: !!s && s.bottom <= innerHeight + 1 && s.top >= 0,
          innerWidth,
          innerHeight,
        };
      });
      expect(m.scrollable, ".dbody scrolls vertically").toBe(true);
      expect(m.dlgRight, "dialog right edge").toBeLessThanOrEqual(m.innerWidth);
      expect(m.dlgLeft, "dialog left edge").toBeGreaterThanOrEqual(0);
      expect(m.dlgBottom, "dialog bottom edge").toBeLessThanOrEqual(m.innerHeight);
      expect(m.sumInView, "full summary reachable by scrolling .dbody").toBe(true);
      // scroll to the very bottom: the last section must end inside the viewport
      const bottom = await page.evaluate(() => {
        const body = document.querySelector<HTMLElement>(".dbody")!;
        body.scrollTop = body.scrollHeight;
        return body.lastElementChild!.getBoundingClientRect().bottom <= innerHeight + 1;
      });
      expect(bottom, "last section not cut off").toBe(true);
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
