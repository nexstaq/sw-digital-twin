import { expect, test } from "@playwright/test";
import { anonymous, mapRepo, signIn } from "./helpers";

test.describe("who can see what", () => {
  test("only maintainers can open or change the settings", async ({ request }) => {
    expect((await request.get("/api/settings/access?repo=acme/shop")).status()).toBe(401);
    expect((await request.put("/api/settings/access", { data: { repo: "acme/shop", view: "health", model: "maintainers" } })).status()).toBe(401);
  });

  test("limit live health to maintainers: the public loses it, a maintainer keeps it, and it can be undone", async ({ page, context }) => {
    await signIn(page);
    await mapRepo(page, "acme/shop");
    const stranger = await anonymous(context);
    const open = async () => (await stranger.request.get("/api/verdict?repo=acme/shop")).status();
    expect(await open()).toBe(200); // a public repo's verdict is open by default

    try {
      await page.getByRole("link", { name: "Access" }).click();
      await expect(page.getByRole("heading", { name: "Who can see what" })).toBeVisible();

      // Security is fixed: a lock, no choice, and the reason
      const sec = page.locator("[data-view=security]");
      await expect(sec.getByRole("combobox")).toHaveCount(0);
      await expect(sec).toContainText(/Fixed: .*sensitive/);

      await page.getByLabel("Who can open Live health").selectOption("maintainers");
      await expect(page.locator("[data-view=health]").getByRole("status")).toContainText("Saved");

      // the public (and the badge, the status card and the stream) are now shut out of that view only
      expect(await open()).toBe(401);
      expect((await stranger.request.get("/api/health/stream?repo=acme/shop", { timeout: 8000 })).status()).toBe(401);
      expect(await (await stranger.request.get("/api/badge/acme/shop")).text()).toContain("unavailable");
      expect(await (await stranger.request.get("/embed/acme/shop")).text()).toContain("Unavailable");
      expect((await stranger.request.get("/api/snapshots?repo=acme/shop")).status()).toBe(200); // the map was not limited
      // ...but a guessed share secret does not get around it
      expect(await (await stranger.request.get(`/api/badge/acme/shop?t=${"x".repeat(32)}`)).text()).toContain("unavailable");
      // the maintainer still has it
      expect((await page.request.get("/api/verdict?repo=acme/shop")).status()).toBe(200);

      // the server refuses to open Security up, whatever the page does
      const bad = await page.request.put("/api/settings/access", { data: { repo: "acme/shop", view: "security", model: "github" } });
      expect(bad.status()).toBe(400);
      expect((await bad.json()).error).toMatch(/sensitive/);

      // the setting is stored: it survives a reload
      await page.reload();
      await expect(page.getByLabel("Who can open Live health")).toHaveValue("maintainers");
    } finally {
      await page.request.put("/api/settings/access", { data: { repo: "acme/shop", view: "health", model: "github" } });
    }
    expect(await open()).toBe(200); // back to the default
    expect(await (await stranger.request.get("/embed/acme/shop")).text()).not.toContain("Unavailable");
    await stranger.close();
  });

  test("limit the map to maintainers: the saved map is closed to the public", async ({ page, context }) => {
    await signIn(page);
    await mapRepo(page, "acme/shop");
    const stranger = await anonymous(context);
    try {
      expect((await page.request.put("/api/settings/access", { data: { repo: "acme/shop", view: "map", model: "maintainers" } })).status()).toBe(200);
      expect((await stranger.request.get("/api/snapshots?repo=acme/shop")).status()).toBe(401);
      expect((await stranger.request.get("/api/scan?repo=acme/shop")).status()).toBe(401);
      expect((await page.request.get("/api/snapshots?repo=acme/shop")).status()).toBe(200);
    } finally {
      await page.request.put("/api/settings/access", { data: { repo: "acme/shop", view: "map", model: "github" } });
    }
    expect((await stranger.request.get("/api/snapshots?repo=acme/shop")).status()).toBe(200);
    await stranger.close();
  });
});
