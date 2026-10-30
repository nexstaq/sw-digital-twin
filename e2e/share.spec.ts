import { expect, test } from "@playwright/test";
import { anonymous, errorBox, mapRepo, signIn, tile, tiles, watchProblems } from "./helpers";

test("share a private map by link, open it without signing in, then revoke it", async ({ page, context }) => {
  await signIn(page);
  await mapRepo(page, "acme/vault");

  await page.getByRole("button", { name: "Share" }).click();
  await page.getByLabel("Link label").fill("for the board");
  await page.getByRole("button", { name: "New link" }).click();
  const link = (await page.locator("button", { hasText: /\/s\/acme\/vault\// }).innerText()).trim();
  expect(link).toMatch(/\/s\/acme\/vault\/[\w-]{32}$/);
  const secret = link.split("/").pop()!;
  await expect(page.getByText("for the board")).toBeVisible();

  // a stranger with the link: sees the map, read-only, with no way to edit or share
  const stranger = await anonymous(context);
  const view = await stranger.newPage();
  const problems = watchProblems(view);
  await view.goto(link);
  await expect(view.getByText("Read-only · acme/vault")).toBeVisible();
  await expect(tiles(view).first()).toBeVisible();
  await expect(view.getByRole("button", { name: "Share" })).toHaveCount(0);
  await tile(view, "acme-shop").click();
  await expect(view.locator("aside")).toBeVisible();
  await expect(view.getByText("Correct this")).toHaveCount(0);
  expect(problems).toEqual([]);

  // the badge opens with the secret and only with the secret
  const withToken = await (await stranger.request.get(`/api/badge/acme/vault?t=${secret}`)).text();
  expect(withToken).not.toContain("unavailable");
  expect(await (await stranger.request.get("/api/badge/acme/vault")).text()).toContain("unavailable");
  expect(await (await stranger.request.get(`/api/badge/acme/vault?t=${"x".repeat(32)}`)).text()).toContain("unavailable");
  expect((await stranger.request.get(`/api/shared/acme/vault/${"x".repeat(32)}`)).status()).toBe(404);

  // revoke: the open page loses the map on its next refresh, and the link is dead for new visitors
  await page.getByRole("button", { name: /Revoke for the board/ }).click();
  await expect(page.getByText("for the board")).toHaveCount(0);
  expect((await stranger.request.get(`/api/shared/acme/vault/${secret}`)).status()).toBe(404);
  expect(await (await stranger.request.get(`/api/badge/acme/vault?t=${secret}`)).text()).toContain("unavailable");
  await view.reload();
  await expect(errorBox(view)).toContainText(/doesn't work|revoked/);
  await expect(tiles(view)).toHaveCount(0);
  await stranger.close();
});

test("a team member can correct a node, and the correction survives a re-scan and can be undone", async ({ page }) => {
  await signIn(page);
  await mapRepo(page, "acme/vault");

  await tile(page, "acme-shop").click();
  await page.getByRole("button", { name: "Rename or re-describe" }).click();
  await page.getByLabel("Name").fill("Billing Core");
  await page.getByLabel("Description").fill("Takes the money.");
  await page.getByRole("button", { name: "Save for the team" }).click();
  await expect(tile(page, "Billing Core")).toBeVisible();
  await expect(tile(page, "acme-shop")).toHaveCount(0);

  await page.reload(); // a fresh scan of the repo: the correction is applied again
  await expect(tile(page, "Billing Core")).toBeVisible({ timeout: 30_000 });

  await tile(page, "Billing Core").click();
  await page.getByRole("button", { name: "Undo my edits" }).click();
  await expect(tile(page, "acme-shop")).toBeVisible();
});

test("hiding a false part removes it from the map, and it can be restored from the hidden list", async ({ page }) => {
  await signIn(page);
  await mapRepo(page, "acme/vault");
  const before = await tiles(page).count();

  await tile(page, "Data & messaging").click();
  await page.getByRole("button", { name: /Not a real part, hide it/ }).click();
  await expect(tiles(page)).toHaveCount(before - 1);
  await expect(tile(page, "Data & messaging")).toHaveCount(0);

  await page.getByRole("button", { name: /1 hidden/ }).click();
  await page.getByRole("button", { name: "Show", exact: true }).click();
  await expect(tiles(page)).toHaveCount(before);
  await expect(tile(page, "Data & messaging")).toBeVisible();
});

test("without write access there is no way to edit or share", async ({ page }) => {
  await mapRepo(page, "acme/shop"); // public repo, signed out
  await expect(page.getByRole("button", { name: "Share" })).toHaveCount(0);
  await tile(page, "CI/CD pipelines").click();
  await expect(page.locator("aside")).toBeVisible();
  await expect(page.getByText("Correct this")).toHaveCount(0);
});
