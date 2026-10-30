import { expect, test, type Page } from "@playwright/test";
import { errorBox, mapRepo, signIn, tile, watchProblems } from "./helpers";

// The same key the mock assembles at run time. Written in pieces so it never appears as one string in the repo.
const AWS = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE";

const panel = (page: Page) => page.getByRole("dialog", { name: /^Finding:/ });
const posture = (page: Page) => page.getByLabel("Security posture");

async function scanVault(page: Page) {
  await signIn(page);
  await mapRepo(page, "acme/vault"); // the security view colours the saved map
  await page.goto("/security?repo=acme/vault");
  // the server keeps the last scan, so on a later visit the button says "Scan again"; either way, scan fresh
  await posture(page).getByRole("button", { name: /Run security scan|Scan again/ }).click();
  await expect(posture(page).getByRole("img", { name: /Security grade/ })).toBeVisible({ timeout: 30_000 });
}

test.describe("security analysis", () => {
  test("findings are for maintainers: every door refuses anonymous callers, even for a public repo", async ({ page, request }) => {
    for (const [method, url] of [["POST", "/api/security/scan?repo=acme/shop"], ["GET", "/api/security/findings?repo=acme/shop"], ["GET", "/api/security/snippet?repo=acme/shop&path=Dockerfile&line=1"]] as const) {
      expect((await request.fetch(url, { method })).status(), `${method} ${url}`).toBe(401);
    }
    await page.goto("/security?repo=acme/shop");
    await expect(page.getByRole("heading", { name: /for maintainers/ })).toBeVisible();
    await expect(page.getByRole("link", { name: "Sign in with GitHub" })).toBeVisible();
  });

  test("scan, read the posture, and see the map recolour by risk", async ({ page }) => {
    const problems = watchProblems(page);
    await scanVault(page);

    await expect(posture(page)).toContainText(/2 critical issues to fix first/);
    await expect(page.getByLabel("Security grade F").or(page.getByLabel("Security grade D")).first()).toBeVisible();
    await expect(page.getByText(/Scanned commit/)).toBeVisible();

    // the same map, now coloured by security: the pipeline block holds a critical finding
    await expect(tile(page, "CI/CD pipelines").getByRole("img", { name: "High risk" })).toBeVisible();
    await expect(tile(page, "CI/CD pipelines")).toContainText(/untrusted pull-request code|critical/i);
    // health-only chrome is gone in this view
    await expect(page.getByRole("button", { name: "Replay incident" })).toHaveCount(0);
    expect(problems).toEqual([]);
  });

  test("deep dive on a leaked key: exact file and line, the reason, and no secret value anywhere", async ({ page }) => {
    await scanVault(page);
    await posture(page).getByRole("button", { name: /AWS access key ID committed in config\.ts/ }).click();
    const d = panel(page);
    await expect(d).toBeVisible();
    await expect(d.getByText("Critical").first()).toBeVisible();
    await expect(d.getByRole("link", { name: /src\/config\.ts:2/ })).toHaveAttribute("href", /github\.com\/acme\/vault\/blob\/[0-9a-f]{40}\/src\/config\.ts#L2/);
    await expect(d.getByText("Why it matters")).toBeVisible();
    await expect(d).toContainText("revoke or rotate");
    await expect(d).toContainText("CWE-798");
    // the excerpt comes from GitHub at view time, with the secret redacted
    await expect(d.getByText("redacted").first()).toBeVisible();
    await expect(d.getByText("awsKey").first()).toBeVisible();
    expect(await page.content()).not.toContain(AWS);
    await expect(d).toContainText("never stored");
    // jumping to the map selects the part that holds it
    await d.getByRole("button", { name: "Show on map" }).click();
    await expect(page.locator("aside[aria-label$='details']")).toBeVisible();
  });

  test("a vulnerable dependency: CVE, severity, the version that fixes it, and whether your code imports it", async ({ page }) => {
    await scanVault(page);
    await posture(page).getByRole("button", { name: /^Dependencies/ }).click(); // filters the map and the list
    await posture(page).getByRole("button", { name: /lodash@4\.17\.15 has 2 known vulnerabilities/ }).click();
    const d = panel(page);
    await expect(d.getByText("Known vulnerabilities in lodash@4.17.15")).toBeVisible();
    await expect(d.getByRole("link", { name: "CVE-2020-8203" })).toHaveAttribute("href", /github\.com\/advisories/);
    await expect(d).toContainText("CVSS 7.4");
    await expect(d).toContainText("fixed in 4.17.19");
    await expect(d).toContainText("Upgrade lodash to 4.17.21 or later"); // the version that fixes BOTH advisories
    await expect(d).toContainText("Imported by your code in src/server.ts");
    await expect(d.getByRole("link", { name: /package\.json:\d+/ })).toBeVisible(); // pinned to where it is declared
    await expect(d.getByText("CWE-1321")).toBeVisible();
  });

  test("a risky pipeline: the dangerous line is highlighted, with a safe rewrite", async ({ page }) => {
    await scanVault(page);
    await posture(page).getByRole("button", { name: /pull_request_target checks out untrusted/ }).click();
    const d = panel(page);
    await expect(d.getByRole("link", { name: /\.github\/workflows\/pr\.yml:\d+/ })).toBeVisible();
    await expect(d.locator("pre")).toContainText("github.event.pull_request.head.sha");
    await expect(d).toContainText("pull_request");
    await expect(d.getByText("CWE-94")).toBeVisible();
    await d.getByRole("button", { name: "Close finding" }).click();
    await expect(d).toHaveCount(0);
  });

  test("drilling from a block lists what is wrong inside it, worst first", async ({ page }) => {
    await scanVault(page);
    await tile(page, "CI/CD pipelines").click();
    const section = page.getByLabel("Security findings");
    await expect(section).toContainText(/Security findings · \d+/);
    const rows = section.getByRole("button");
    await expect(rows.first()).toContainText("Critical");
    await rows.first().click();
    await expect(panel(page)).toBeVisible();
  });

  test("the scan is stored, so reloading shows it without scanning again", async ({ page }) => {
    await scanVault(page);
    await page.reload();
    await expect(posture(page).getByRole("img", { name: /Security grade/ })).toBeVisible({ timeout: 20_000 });
    await expect(posture(page).getByRole("button", { name: "Scan again" })).toBeVisible();
  });

  test("the code-excerpt endpoint is not a file browser", async ({ page }) => {
    await scanVault(page);
    const get = (q: string) => page.request.get(`/api/security/snippet?repo=acme/vault&${q}`);
    expect((await get("path=src/server.ts&line=1")).status()).toBe(404); // a real file, but no finding points at it
    expect((await get("path=../../etc/passwd&line=1")).status()).toBe(400);
    expect((await get("path=/etc/passwd&line=1")).status()).toBe(400);
    expect((await get("path=Dockerfile&line=0")).status()).toBe(400);
    expect((await get("path=Dockerfile&line=99999")).status()).toBe(404);
    const ok = await get("path=Dockerfile&line=1");
    expect(ok.status()).toBe(200);
    expect(await ok.text()).toContain("FROM node");
  });

  test("a share link and the badge never expose findings", async ({ page, browser }) => {
    await scanVault(page);
    await page.goto("/scan?repo=acme/vault");
    await page.getByRole("button", { name: "Share" }).click();
    await page.getByRole("button", { name: "New link" }).click();
    const link = (await page.locator("button", { hasText: /\/s\/acme\/vault\// }).innerText()).trim();
    const stranger = await browser.newContext();
    const view = await stranger.newPage();
    await view.goto(link);
    await expect(view.getByText("Read-only · acme/vault")).toBeVisible();
    await expect(view.getByRole("link", { name: "Security" })).toHaveCount(0);
    const api = await stranger.request.get("/api/security/findings?repo=acme/vault");
    expect(api.status()).toBe(401);
    expect(await (await stranger.request.get(`/api/shared/acme/vault/${link.split("/").pop()}`)).text()).not.toMatch(/AWS access key|lodash@|pull_request_target checks out/);
    await stranger.close();
  });

  test("the health map offers the security view to maintainers only", async ({ page }) => {
    await mapRepo(page, "acme/shop"); // signed out
    await expect(page.getByRole("link", { name: "Security" })).toHaveCount(0);
    await signIn(page);
    await mapRepo(page, "acme/vault");
    await expect(page.getByRole("link", { name: "Security" })).toBeVisible();
    await expect(errorBox(page)).toHaveCount(0);
  });
});
