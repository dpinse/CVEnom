import AxeBuilder from "@axe-core/playwright";
import { CVE_ID, expect, test } from "./harness";

const serious = async (page: import("@playwright/test").Page) => {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"])
    .analyze();
  return results.violations
    .filter((v) => v.impact === "serious" || v.impact === "critical")
    .map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.map((n) => n.target.join(" ")) }));
};

test("Threats filters live in the URL; severity chips are colour-coded toggles", async ({ page, guards }) => {
  await page.goto("/threats");
  await expect(page.getByRole("heading", { level: 1, name: "Threats" })).toBeVisible();
  await expect(page.getByRole("group", { name: "Time range" })).toHaveCount(0);
  await expect(page.getByTestId("search-row")).toHaveCount(1);

  const sev = page.getByRole("group", { name: "Severity" });
  await expect(sev.getByRole("button")).toHaveText(["Low", "Medium", "High", "Critical"]);
  await sev.getByRole("button", { name: "Critical" }).click();
  await sev.getByRole("button", { name: "High" }).click();
  await expect(page).toHaveURL(/[?&]sev=high%2Ccrit/);
  await expect(sev.getByRole("button", { name: "High" })).toHaveAttribute("aria-pressed", "true");

  await page.getByLabel("Added").selectOption("month");
  await page.getByRole("button", { name: "Exploited" }).click();
  await expect(page).toHaveURL(/added=month/);
  await expect(page).toHaveURL(/status=exploited/);
  await page.getByLabel("Sort").selectOption("priority");
  await expect(page).toHaveURL(/sort=priority/);
  await expect
    .poll(() => guards.apiRequests.some((r) => r.startsWith("/api/cves?") && r.includes("sort=priority")))
    .toBe(true);
  await page.getByLabel("Sort").selectOption("due");
  await expect(page.getByText("Soonest CISA deadline first")).toBeVisible();
  // The URL state reaches the API as the matching query.
  await expect
    .poll(() =>
      guards.apiRequests.some(
        (r) =>
          r.startsWith("/api/cves?") &&
          r.includes("status=exploited") &&
          r.includes("added=month") &&
          r.includes("sev=high%2Ccrit"),
      ),
    )
    .toBe(true);
});

test("a dashboard deep link shows why the list is narrowed and lets the user remove it", async ({ page }) => {
  await page.goto("/threats?status=critical&exclude_kev=1&added=14d");
  await expect(page.getByLabel("Added")).toHaveValue("14d");
  await page.getByRole("button", { name: "Remove filter: Not in KEV" }).click();
  await expect(page).not.toHaveURL(/exclude_kev/);
});

test("a CVE row opens its threat page", async ({ page }) => {
  await page.goto("/threats");
  await page.getByTestId("search-row").getByText("Acme Gateway 4.2 remote code execution").click();
  await expect(page).toHaveURL(/\/threats\/CVE-2026-1001$/);
});

test("the page does not scroll sideways at 400px; the table scrolls inside its wrapper", async ({ page }) => {
  await page.setViewportSize({ width: 400, height: 800 });
  await page.goto("/threats?sev=crit,high&status=likely&poc=1");
  await expect(page.getByTestId("search-row")).toHaveCount(1);
  const m = await page.evaluate(() => ({
    doc: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
  }));
  expect(m.doc).toBeLessThanOrEqual(400);
  expect(m.body).toBeLessThanOrEqual(400);
});

test("axe: no serious or critical violations on /threats", async ({ page }) => {
  await page.goto("/threats");
  await expect(page.getByTestId("search-row")).toHaveCount(1);
  expect(await serious(page)).toEqual([]);
});

test("axe: no serious or critical violations on the threat page", async ({ page }) => {
  await page.goto(`/threats/${CVE_ID}`);
  await expect(page.getByRole("heading", { name: "Timeline" })).toBeVisible();
  await expect(page.getByText("Improper Authentication")).toBeVisible();
  expect(await serious(page)).toEqual([]);
});

test("the threat page shows the H1 and the status line", async ({ page }) => {
  await page.goto(`/threats/${CVE_ID}`);
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Acme Gateway auth bypass");
  await expect(page.getByTestId("status-line")).toContainText("Data as of");
});

test("/threats/not-a-cve shows not-found and never requests /api/cves/", async ({ page, guards }) => {
  await page.goto("/threats/not-a-cve");
  await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible();
  expect(guards.apiRequests.filter((r) => r.startsWith("/api/cves/"))).toEqual([]);
});

test("/history?kev=true lands on /threats?status=exploited", async ({ page }) => {
  await page.goto("/history?kev=true");
  await expect(page).toHaveURL(/\/threats\?status=exploited$/);
  await expect(page.getByRole("button", { name: "Exploited" })).toHaveAttribute("aria-pressed", "true");
});

test("the News tab shows the stories table and asks for news only", async ({ page, guards }) => {
  await page.goto("/threats?tab=news");
  await expect(page.getByRole("tab", { name: "News" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByTestId("news-story")).toHaveCount(1);
  await expect(page.getByTestId("ransomware-credit")).toHaveCount(0);
  await expect
    .poll(() => guards.apiRequests.some((r) => r.startsWith("/api/stories?") && r.includes("kind=news")))
    .toBe(true);
});

test("the Ransomware tab is reachable and asks guests to sign in", async ({ page, guards }) => {
  await page.goto("/threats?tab=news");
  await page.getByRole("tab", { name: "Ransomware" }).click();
  await expect(page).toHaveURL(/tab=ransomware/);
  await expect(page.getByRole("tab", { name: "Ransomware" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByTestId("ransomware-signin")).toBeVisible();
  await expect(page.getByTestId("news-story")).toHaveCount(0);
  expect(guards.apiRequests.some((r) => r.includes("kind=ransomware"))).toBe(false);
});
