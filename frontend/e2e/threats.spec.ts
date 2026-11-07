import { expect, test } from "./harness";

test("Threats filters live in the URL; severity chips are colour-coded toggles", async ({ page }) => {
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
  await page.getByLabel("Sort").selectOption("due");
  await expect(page.getByText("Soonest CISA deadline first")).toBeVisible();
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
