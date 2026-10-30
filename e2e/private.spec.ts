import { expect, test } from "@playwright/test";
import { errorBox, mapRepo, signIn, tile, tiles } from "./helpers";

test("a private repo is closed to anonymous visitors in every door", async ({ page, request }) => {
  await page.goto("/scan");
  await page.getByLabel("GitHub repository").fill("acme/vault");
  await page.getByRole("button", { name: "Map it" }).click();
  await expect(errorBox(page)).toContainText(/private|sign in/i);
  await expect(errorBox(page).getByRole("link", { name: "Sign in with GitHub" })).toBeVisible();
  await expect(tiles(page)).toHaveCount(0);

  // the same answer from the data endpoints, and nothing leaks through the badge
  expect((await request.get("/api/snapshots?repo=acme/vault")).status()).toBe(401);
  expect((await request.get("/api/health/stream?repo=acme/vault")).status()).toBe(401);
  expect((await request.get("/api/mappings?repo=acme/vault")).status()).toBe(401);
  const badge = await (await request.get("/api/badge/acme/vault")).text();
  expect(badge).toContain("unavailable");
});

test("signing in lists your repos, opens the private one, and signing out closes it again", async ({ page }) => {
  await page.goto("/repos");
  await expect(page.getByRole("link", { name: /Sign in with GitHub/ }).first()).toBeVisible();

  await signIn(page);
  await expect(page.getByRole("button", { name: /acme\/shop/ })).toBeVisible();
  const vault = page.getByRole("button", { name: /acme\/vault/ });
  await expect(vault).toContainText("Private");

  await vault.click();
  await expect(tiles(page).first()).toBeVisible({ timeout: 30_000 });
  await expect(tile(page, "CI/CD pipelines").or(tile(page, "acme-shop")).first()).toBeVisible();

  await page.getByRole("button", { name: "Signed in as alice" }).click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
  await expect(page.getByRole("link", { name: /Sign in/ }).first()).toBeVisible();
  await page.goto("/scan?repo=acme/vault");
  await expect(errorBox(page)).toContainText(/private|sign in/i);
});

test("the session cookie is httpOnly and the token never reaches the page", async ({ page, context }) => {
  await signIn(page);
  const cookie = (await context.cookies()).find((c) => c.name === "twin_session")!;
  expect(cookie.httpOnly).toBe(true);
  expect(cookie.sameSite).toBe("Lax");
  const me = await page.evaluate(async () => (await fetch("/api/auth/me")).text());
  expect(me).not.toContain("tok-alice");
  expect(await page.evaluate(() => document.cookie)).not.toContain("twin_session");
  await mapRepo(page, "acme/vault");
  expect(await page.content()).not.toContain("tok-alice");
});
