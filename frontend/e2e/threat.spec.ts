import { readFileSync } from "node:fs";
import { join } from "node:path";
import { CVE_ID, expect, test } from "./harness";

const base = () => JSON.parse(readFileSync(join(import.meta.dirname, "fixtures", `cve-${CVE_ID}.json`), "utf8"));

test("threat page shows the timeline, evidence ladder and affected versions", async ({ page }) => {
  await page.goto(`/threats/${CVE_ID}`);
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Acme Gateway");
  await expect(page.getByRole("heading", { name: "Timeline" })).toBeVisible();
  await expect(page.locator(".tl li").first()).toContainText("CVE ID reserved");
  await expect(page.locator(".tl li", { hasText: "Published" })).toContainText("t = 0");
  await expect(page.locator(".ladder li")).toHaveCount(5);
  await expect(page.getByRole("table")).toContainText("from 4.0 before 4.2.1");
  await expect(page.getByRole("heading", { name: "Where it's seen" })).toBeVisible();
  // the CWE name map is a lazy chunk, fetched from the page's own origin
  await expect(page.getByText("Improper Authentication")).toBeVisible();
});

test("a malformed id shows the not-found page", async ({ page }) => {
  await page.goto("/threats/not-a-cve");
  await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible();
});

const BLOB = "A".repeat(600);
const LONG_URL = `https://tracker.example/${"u".repeat(300)}`;
const LONG_REF = `https://refs.example/${"b".repeat(280)}`;

for (const size of [
  { width: 1280, height: 800 },
  { width: 400, height: 800 },
  { width: 320, height: 600 },
]) {
  test.describe(`${size.width}px`, () => {
    test.use({ viewport: size });

    test("threat page has no horizontal overflow with a very long description and unbroken URL", async ({ page }) => {
      await page.route(`**/api/cves/${CVE_ID}?*`, (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            ...base(),
            summary: `${"A long sentence that keeps going. ".repeat(40)}See ${LONG_URL} and ${BLOB} ENDOFDESC`,
            kev_action: BLOB,
            cvss_vector: `CVSS:3.1/${"AV:N/".repeat(60)}`,
            references: [{ url: LONG_REF, tags: ["x".repeat(200)] }],
            affected_versions: [
              {
                product: `Product-${"p".repeat(200)}`,
                vendor: null,
                ecosystem: null,
                introduced: "1".repeat(100),
                fixed: "2".repeat(100),
                last_affected: null,
                source: "OSV",
              },
            ],
            stories: [
              {
                title: `T${"x".repeat(300)}`,
                url: "https://news.example/long",
                source: "Example News",
                published: "2026-11-05T08:00:00Z",
              },
            ],
          }),
        }),
      );
      await page.goto(`/threats/${CVE_ID}`);
      await expect(page.locator(".prose")).toContainText("ENDOFDESC");
      const m = await page.evaluate(() => {
        const root = document.querySelector<HTMLElement>(".threat")!;
        const right = root.getBoundingClientRect().right;
        // the versions table may scroll inside its own wrapper; everything else must stay inside the page
        const out = Array.from(root.querySelectorAll<HTMLElement>("*"))
          .filter((el) => !el.closest(".tbl-wrap") && el.getBoundingClientRect().right > right + 1)
          .map((el) => `${el.tagName.toLowerCase()}.${el.className}`);
        return { doc: [document.documentElement.scrollWidth, innerWidth], out: out.slice(0, 8) };
      });
      expect(m.out, "elements sticking out of the page").toEqual([]);
      expect(m.doc[0], "document scrollWidth").toBeLessThanOrEqual(m.doc[1]);
    });
  });
}
