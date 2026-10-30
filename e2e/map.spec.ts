import { expect, test } from "@playwright/test";
import { errorBox, mapRepo, tile, tiles, watchProblems } from "./helpers";

test("paste a repo URL, read the verdict, and drill down to the failing step", async ({ page }) => {
  const problems = watchProblems(page);
  await mapRepo(page, "acme/shop");

  // L0: the whole system in a handful of blocks, with a verdict anyone can read
  await expect(page.getByText("NO-GO").first()).toBeVisible();
  await expect(tile(page, "CI/CD pipelines")).toContainText("CI is failing");
  expect(await tiles(page).count()).toBeGreaterThanOrEqual(4);

  // L1: open the failing block from its drawer
  await tile(page, "CI/CD pipelines").click();
  await expect(page.locator("aside")).toContainText("Failing");
  await page.getByRole("button", { name: /Open \d+ inner parts/ }).click();
  await expect(tile(page, "Latest run failed")).toBeVisible();
  await expect(page.getByRole("navigation").getByText("CI/CD pipelines")).toBeVisible(); // the breadcrumb

  // L2: double-clicking the workflow opens its jobs; the failing job names the failing step
  await tile(page, "Latest run failed").dblclick();
  const failing = tile(page, "Run unit tests");
  await expect(failing).toBeVisible();
  await expect(failing).toContainText("failed");
  await expect(tile(page, "lint")).not.toContainText("failed");
  await failing.click();
  await expect(page.locator("aside")).toContainText("Run unit tests");

  // the drill-down is a URL, so it can be shared
  expect(page.url()).toContain("z=");
  expect(problems).toEqual([]);
});

test("an unknown repository gives a clear message, not a blank page", async ({ page }) => {
  await page.goto("/scan");
  await page.getByLabel("GitHub repository").fill("acme/does-not-exist");
  await page.getByRole("button", { name: "Map it" }).click();
  await expect(errorBox(page)).toContainText(/private|name is wrong|sign in/i);
  await expect(tiles(page)).toHaveCount(0);
});

test("a malformed repository is refused before anything is fetched", async ({ page }) => {
  await page.goto("/scan");
  await page.getByLabel("GitHub repository").fill("not a repo!!");
  await page.getByRole("button", { name: "Map it" }).click();
  await expect(errorBox(page)).toContainText(/owner\/repo/);
});

test("the Ask-AI box says plainly when AI is off, rather than failing silently", async ({ page }) => {
  await mapRepo(page, "acme/shop");
  await tile(page, "CI/CD pipelines").click();
  await page.getByLabel("Ask AI about this node").fill("what should I check first?");
  await page.getByRole("button", { name: "Ask", exact: true }).click();
  await expect(page.locator("aside").getByRole("alert")).toContainText(/AI|off|Set/i);
});
