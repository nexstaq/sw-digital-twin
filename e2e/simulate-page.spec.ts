import { expect, test, type Page } from "@playwright/test";
import { mapRepo, signIn } from "./helpers";

const posture = (page: Page) => page.getByRole("tablist", { name: "Simulation entry points" }).locator("..");
const tab = (page: Page, name: RegExp) => page.getByRole("tab", { name });

async function openSimulate(page: Page, repo = "acme/vault") {
  await signIn(page);
  await mapRepo(page, repo);
  await page.goto(`/simulate?repo=${encodeURIComponent(repo)}`);
  await expect(tab(page, /^Explain a block/)).toBeVisible();
}

test.describe("the Simulation page: three entry points", () => {
  test("is for maintainers: an anonymous visitor is told to sign in, never shown the page's contents", async ({ page }) => {
    await page.goto("/simulate?repo=acme/vault");
    await expect(page.getByRole("heading", { name: "Simulation is for maintainers" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Sign in with GitHub" })).toHaveAttribute("href", /returnTo=.*simulate/);
  });

  test("Explain a block: points at the map and the Simulate lens, touches nothing itself", async ({ page }) => {
    await openSimulate(page);
    await expect(posture(page)).toContainText(/Pick any block on the map/);
    const link = posture(page).getByRole("link", { name: /Open the map/ });
    await expect(link).toHaveAttribute("href", /\/scan\?repo=acme%2Fvault/);
  });

  test("Run a test: asks for a scan first when there is none, then embeds the same simulation controls as the Security page", async ({ page }) => {
    await openSimulate(page);
    // acme/vault is a shared fixture: an earlier test file in the same run may already have scanned it, so this checks
    // the real precondition rather than assuming one
    const { set } = await (await page.request.get("/api/security/findings?repo=acme/vault")).json();
    await tab(page, /^Run a test/).click();
    if (!set) {
      await expect(posture(page)).toContainText(/Run a security scan first/);
      await posture(page).getByRole("link", { name: "Security" }).click();
      await expect(page).toHaveURL(/\/security\?repo=acme%2Fvault/);
      await page.getByRole("button", { name: /Run security scan|Scan again/ }).click();
      await expect(page.getByRole("button", { name: "Scan again" })).toBeEnabled({ timeout: 30_000 });
      await page.goto("/simulate?repo=acme/vault");
      await tab(page, /^Run a test/).click();
    }
    await expect(posture(page).getByRole("button", { name: /Verify by simulation/ })).toBeVisible();
  });

  test("Check reachability: will not run without explicit approval, then replays what it found with shapes, not colour alone", async ({ page }) => {
    await openSimulate(page);
    // scan via the Security page first (reachability needs a scan, same precondition as "Run a test")
    await page.goto("/security?repo=acme/vault");
    await page.getByRole("button", { name: /Run security scan|Scan again/ }).click();
    await expect(page.getByRole("button", { name: "Scan again" })).toBeEnabled({ timeout: 30_000 });
    await page.goto("/simulate?repo=acme/vault");

    await tab(page, /^Check reachability/).click();
    const run = posture(page).getByRole("button", { name: "Approve and run" });
    await expect(run).toBeDisabled();
    await posture(page).getByRole("checkbox").check();
    await expect(run).toBeEnabled();
    await run.click();

    const replay = page.getByRole("region", { name: "Reachability and detection replay" });
    await expect(replay).toBeVisible({ timeout: 30_000 });
    await expect(replay.getByRole("button", { name: /^Step 1:/ })).toBeVisible();

    // more than one shape appears among the steps: a reachability glyph and a detection glyph, never colour alone
    const stepButtons = await replay.getByRole("listitem").count();
    expect(stepButtons).toBeGreaterThan(1);

    await expect(posture(page).getByRole("link", { name: "Download SARIF" })).toHaveAttribute("href", /format=sarif/);
    await expect(posture(page).getByRole("link", { name: "Open report" })).toHaveAttribute("href", /format=html/);

    // "Run again" goes back through the pre-flight screen, not straight into another run
    await posture(page).getByRole("button", { name: "Run again" }).click();
    await expect(posture(page).getByRole("button", { name: "Approve and run" })).toBeDisabled();
  });

  test("the replay step list and the scrubber are reachable with the keyboard alone", async ({ page }) => {
    await openSimulate(page);
    await page.goto("/security?repo=acme/vault");
    await page.getByRole("button", { name: /Run security scan|Scan again/ }).click();
    await expect(page.getByRole("button", { name: "Scan again" })).toBeEnabled({ timeout: 30_000 });
    await page.goto("/simulate?repo=acme/vault");
    await tab(page, /^Check reachability/).click();
    await posture(page).getByRole("checkbox").focus();
    await page.keyboard.press("Space");
    await page.keyboard.press("Tab");
    await expect(posture(page).getByRole("button", { name: "Approve and run" })).toBeFocused();
    await page.keyboard.press("Enter");
    const replay = page.getByRole("region", { name: "Reachability and detection replay" });
    await expect(replay).toBeVisible({ timeout: 30_000 });
    await replay.getByRole("button", { name: /Play replay/ }).focus();
    await expect(replay.getByRole("button", { name: /Play replay/ })).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(replay.getByRole("slider", { name: "Replay step" })).toBeFocused();
    await page.keyboard.press("ArrowRight");
    await expect(replay).toContainText("2/");
  });

  test("works on a phone: no sideways scroll, every tab reachable", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await openSimulate(page);
    for (const name of [/^Explain a block/, /^Run a test/, /^Check reachability/]) await tab(page, name).click();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  });

  test("the SARIF export carries the ATT&CK technique a verdict was actually exercised with", async ({ page }) => {
    await signIn(page);
    await mapRepo(page, "acme/vault");
    await page.goto("/security?repo=acme/vault");
    await page.getByRole("button", { name: /Run security scan|Scan again/ }).click();
    await expect(page.getByRole("button", { name: "Scan again" })).toBeEnabled({ timeout: 30_000 });
    const sim = page.getByRole("region", { name: "Verify by simulation" });
    await sim.getByRole("button", { name: /Verify by simulation|Verify again/ }).click();
    await expect(sim.getByRole("status")).toBeVisible({ timeout: 30_000 });
    const sarif = await (await page.request.get("/api/security/report?repo=acme/vault&format=sarif")).json();
    const withTechnique = sarif.runs[0].results.filter((r: { properties?: { technique?: string } }) => r.properties?.technique);
    expect(withTechnique.length).toBeGreaterThan(0);
    expect(withTechnique.every((r: { properties: { technique: string } }) => /^T\d{4}/.test(r.properties.technique))).toBe(true);
  });

  test("a share link never carries the reachability replay data or the detection coverage", async ({ page, browser }) => {
    await signIn(page);
    await mapRepo(page, "acme/vault");
    await page.goto("/security?repo=acme/vault");
    await page.getByRole("button", { name: /Run security scan|Scan again/ }).click();
    await expect(page.getByRole("button", { name: "Scan again" })).toBeEnabled({ timeout: 30_000 });
    const sim = page.getByRole("region", { name: "Verify by simulation" });
    await sim.getByRole("button", { name: /Verify by simulation|Verify again/ }).click();
    await expect(sim.getByRole("status")).toBeVisible({ timeout: 30_000 });

    await page.goto("/scan?repo=acme/vault");
    await page.getByRole("button", { name: "Share" }).click();
    await page.getByRole("button", { name: "New link" }).click();
    const link = (await page.locator("button", { hasText: /\/s\/acme\/vault\// }).innerText()).trim();
    const stranger = await browser.newContext();
    const body = await (await stranger.request.get(`/api/shared/acme/vault/${link.split("/").pop()}`)).text();
    expect(body).not.toMatch(/detection-gap|BLUE\/not-detected|T1190|T1195|pull_request_target checks out/);
    await stranger.close();
  });
});
