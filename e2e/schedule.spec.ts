import { expect, test } from "@playwright/test";
import { mapRepo, signIn } from "./helpers";

const CRON = { authorization: "Bearer e2e-cron-secret" };

test.describe("scheduled scans", () => {
  test("only maintainers can set a schedule, and the cron endpoint needs its secret", async ({ request }) => {
    expect((await request.put("/api/security/schedule", { data: { repo: "acme/vault", cadence: "daily" } })).status()).toBe(401);
    expect((await request.get("/api/security/schedule?repo=acme/vault")).status()).toBe(401);
    expect((await request.get("/api/cron/rescan")).status()).toBe(401);
    expect((await request.get("/api/cron/rescan", { headers: { authorization: "Bearer wrong" } })).status()).toBe(401);
  });

  test("turn it on, let the cron job run it, and see the result; then turn it off", async ({ page }) => {
    await signIn(page);
    await mapRepo(page, "acme/shop");
    await page.goto("/security?repo=acme/shop");
    const posture = page.getByLabel("Security posture");
    await posture.getByRole("button", { name: /Run security scan|Scan again/ }).click();
    await expect(posture.getByRole("button", { name: "Scan again" })).toBeEnabled({ timeout: 30_000 });
    await page.getByLabel("Sources and integrations").getByText("Sources and live testing").click();

    const box = page.getByLabel("Scheduled scans");
    await expect(box).toBeVisible();
    await box.getByLabel("Scan schedule").selectOption("daily");
    await expect(box.getByText(/It has not run yet/)).toBeVisible();

    // what Vercel Cron does once a day. It has no signed-in user, so it reads a public repo with no token (a private one needs the GitHub App installed)
    const res = await page.request.get("/api/cron/rescan", { headers: CRON });
    expect(res.status()).toBe(200);
    const report = await res.json();
    expect(report.ran).toEqual([expect.objectContaining({ repo: "acme/shop", ok: true })]);

    // not due again straight away
    expect((await (await page.request.get("/api/cron/rescan", { headers: CRON })).json()).ran).toEqual([]);

    await page.reload();
    await page.getByLabel("Sources and integrations").getByText("Sources and live testing").click();
    await expect(page.getByLabel("Scheduled scans").getByText(/Last run .*: ok/)).toBeVisible();

    await page.getByLabel("Scheduled scans").getByLabel("Scan schedule").selectOption("off");
    await expect(page.getByLabel("Scheduled scans").getByLabel("Scan schedule")).toHaveValue("off");
    expect((await (await page.request.get("/api/cron/rescan", { headers: CRON })).json()).due).toBe(0);
  });
});
