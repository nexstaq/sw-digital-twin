import { createServer } from "node:http";
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

test("the status card embed: frameable, honest about private repos, and the only page that is", async ({ page, context }) => {
  await signIn(page);
  await mapRepo(page, "acme/shop");
  await mapRepo(page, "acme/vault");
  await page.getByRole("button", { name: "Share" }).click();
  await page.getByRole("button", { name: "New link" }).click();
  const link = (await page.locator("button", { hasText: /\/s\/acme\/vault\// }).innerText()).trim();
  const secret = link.split("/").pop()!;
  // the panel offers a ready-to-paste iframe
  await expect(page.getByRole("button", { name: /Copy status card/ })).toBeVisible();

  const stranger = await anonymous(context);
  const get = (url: string) => stranger.request.get(url);

  // public repo: no token needed; any site may frame it; it carries no script
  const pub = await get("/embed/acme/shop");
  expect(pub.status()).toBe(200);
  expect(pub.headers()["content-security-policy"]).toContain("frame-ancestors *");
  expect(pub.headers()["x-frame-options"]).toBeUndefined();
  const body = await pub.text();
  expect(body).toMatch(/GO|HOLD|NO DATA/);
  expect(body).not.toMatch(/<script/i);

  // private repo: the same "unavailable" with no token or a wrong one, the real card with the secret
  expect(await (await get("/embed/acme/vault")).text()).toContain("Unavailable");
  expect(await (await get(`/embed/acme/vault?t=${"x".repeat(32)}`)).text()).toContain("Unavailable");
  const priv = await get(`/embed/acme/vault?t=${secret}`);
  expect(await priv.text()).toContain("acme/vault");
  expect(priv.headers()["cache-control"]).toContain("private");

  // it renders inside a real iframe on another origin (a real server on another port: a different origin), and the rest of the app refuses to
  const site = createServer((_, res) => { res.setHeader("content-type", "text/html"); res.end(`<iframe id="card" src="http://localhost:3300/embed/acme/shop" width="560" height="260"></iframe><iframe id="app" src="http://localhost:3300/repos" width="300" height="200"></iframe>`); });
  await new Promise<void>((ok) => site.listen(3399, "127.0.0.1", ok));
  try {
    const host = await stranger.newPage();
    await host.goto("http://localhost:3399/");
    await expect(host.frameLocator("#card").getByRole("region", { name: /Launch status for acme\/shop/ })).toBeVisible();
    await expect(host.frameLocator("#card").getByRole("link", { name: "Open the full map" })).toBeVisible();
    // the app itself refuses to be framed: that frame never shows the app
    await host.waitForTimeout(1500);
    await expect(host.frameLocator("#app").getByRole("heading").first()).toHaveCount(0);
  } finally { site.close(); }

  // revoked: the card stops showing the map
  await page.getByRole("button", { name: /Revoke/ }).first().click();
  await expect(async () => expect(await (await get(`/embed/acme/vault?t=${secret}`)).text()).toContain("Unavailable")).toPass();
  await stranger.close();
});
