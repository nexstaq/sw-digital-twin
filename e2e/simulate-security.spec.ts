import { expect, test, type Page } from "@playwright/test";
import { mapRepo, signIn, watchProblems } from "./helpers";

const panel = (page: Page) => page.getByRole("dialog", { name: /^Finding:/ });
const posture = (page: Page) => page.getByLabel("Security posture");
const gradeLabel = (page: Page) => posture(page).getByRole("img", { name: /Security grade/ }).getAttribute("aria-label");

async function scanVault(page: Page) {
  await signIn(page);
  await mapRepo(page, "acme/vault");
  await page.goto("/security?repo=acme/vault");
  await posture(page).getByRole("button", { name: /Run security scan|Scan again/ }).click();
  await expect(posture(page).getByRole("button", { name: "Scan again" })).toBeEnabled({ timeout: 30_000 });
  await expect(posture(page).getByRole("img", { name: /Security grade/ })).toBeVisible();
}

async function verify(page: Page, o: { source: boolean }) {
  const sim = posture(page).getByRole("region", { name: "Verify by simulation" });
  const box = sim.getByRole("checkbox", { name: /Let it read the few lines/ });
  if (o.source) await box.check(); else await box.uncheck();
  await sim.getByRole("button", { name: /Verify by simulation|Verify again/ }).click();
  await expect(sim.getByRole("status")).toBeVisible({ timeout: 30_000 });
  return sim;
}

/** show only code findings, so every one of them is in the "fix first" list */
async function codeOnly(page: Page) {
  await posture(page).getByRole("button", { name: /^Code \d/ }).click();
}

test.describe("verify by simulation", () => {
  test("every door refuses anonymous callers", async ({ request }) => {
    for (const [method, url] of [["POST", "/api/security/simulate?repo=acme/shop"], ["DELETE", "/api/security/simulate?repo=acme/shop"], ["GET", "/api/security/simulate/patch?repo=acme/shop&finding=x"]] as const) {
      expect((await request.fetch(url, { method })).status(), `${method} ${url}`).toBe(401);
    }
  });

  test("confirms the seeded SQL injection and path traversal, and downgrades the one that only looks like SQL injection", async ({ page }) => {
    const problems = watchProblems(page);
    await scanVault(page);
    const before = await gradeLabel(page);
    const sim = await verify(page, { source: true });
    await expect(sim).toContainText(/3 confirmed/);
    await expect(sim).toContainText(/1 look mitigated/);
    await expect(sim).toContainText("Source was read");

    await codeOnly(page);
    // the real SQL injection, on the open write route: confirmed with high confidence
    await posture(page).getByRole("button", { name: /SQL built from request data/ }).click();
    const d = panel(page);
    await expect(d.getByRole("region", { name: "Simulation" })).toContainText("Confirmed by simulation");
    await expect(d).toContainText("POST /api/orders can be used for SQL injection");
    await expect(d).toContainText("PostgreSQL");
    await expect(d).toContainText("high");
    await d.getByText(/The test \(3 requests/).click();
    await expect(d).toContainText("expect: the weakness is exercised");
    await expect(d).toContainText("a different kind of hostile input is rejected");
    // every claim cites a step of the run's log
    await expect(d).toContainText(/audit steps #\d+/);

    // the proposed patch is a diff to read, fetched now
    await expect(d).toContainText("was refused");
    await d.getByRole("button", { name: "Show the proposed patch" }).click();
    const diff = d.getByLabel("Proposed patch");
    await expect(diff).toContainText('+  await db.query("UPDATE orders SET paid = true WHERE id = $1"');
    await expect(diff).toContainText("-  await db.query(`UPDATE orders SET paid = true WHERE id = ${");
    await expect(d).toContainText("Nothing was changed, nothing is stored, and nothing is pushed");
    await d.getByRole("button", { name: "Close finding" }).click();

    await posture(page).getByRole("button", { name: /File path built from request data/ }).click();
    await expect(panel(page)).toContainText("GET /api/files can be used for path traversal");
    await panel(page).getByRole("button", { name: "Show the proposed patch" }).click();
    await expect(panel(page).getByLabel("Proposed patch")).toContainText("path.basename(");
    await panel(page).getByRole("button", { name: "Close finding" }).click();

    // the false alarm: the id is made a number first, so it is marked as probably not real
    await posture(page).getByRole("button", { name: /SQL built by joining strings/ }).click();
    await expect(panel(page).getByRole("region", { name: "Simulation" })).toContainText("Looks mitigated");
    await expect(panel(page)).toContainText("converted to a number");
    await expect(panel(page)).toContainText("probably a false alarm");
    await expect(panel(page).getByRole("button", { name: "Show the proposed patch" })).toHaveCount(0);

    // a verdict is evidence, not proof: the grade does not move
    expect(await gradeLabel(page)).toBe(before);
    expect(problems).toEqual([]);
  });

  test("a likely false alarm drops down the fix-first list, below a confirmed one of the same kind", async ({ page }) => {
    await scanVault(page);
    await codeOnly(page);
    const names = async () => (await posture(page).getByRole("region", { name: /./ }).count(), await posture(page).locator("section").filter({ hasText: "Fix first" }).getByRole("button").allInnerTexts());
    await verify(page, { source: true });
    const after = (await names()).map((t) => t.replace(/\s+/g, " "));
    const real = after.findIndex((t) => /SQL built from request data/.test(t)), alarm = after.findIndex((t) => /SQL built by joining strings/.test(t));
    expect(real).toBeGreaterThanOrEqual(0);
    expect(alarm).toBeGreaterThan(real);
  });

  test("without permission to read source it says less, proposes no patch, and cannot tell the false alarm apart", async ({ page }) => {
    await scanVault(page);
    const sim = await verify(page, { source: false });
    await expect(sim).toContainText("Source was not read");
    await codeOnly(page);
    await posture(page).getByRole("button", { name: /SQL built from request data/ }).click();
    await expect(panel(page)).toContainText("The code was not read, so this shows the way in, not that the code is vulnerable");
    await expect(panel(page).getByRole("button", { name: "Show the proposed patch" })).toHaveCount(0);
    await panel(page).getByRole("button", { name: "Close finding" }).click();
    await posture(page).getByRole("button", { name: /SQL built by joining strings/ }).click();
    await expect(panel(page).getByRole("region", { name: "Simulation" })).toContainText("Confirmed by simulation");
    await expect(panel(page).getByRole("region", { name: "Simulation" })).toContainText("low"); // the scanner was not sure, and nothing was read
    await expect(panel(page)).not.toContainText("converted to a number");
  });

  test("what is stored holds no source and no patch, and a patch needs source to have been read", async ({ page }) => {
    await scanVault(page);
    await verify(page, { source: false });
    const stored = await page.request.get("/api/security/findings?repo=acme/vault");
    expect(stored.ok()).toBe(true);
    const json = await stored.text();
    expect(json).toContain('"simulation"');
    // strings that exist only in the fixture's own code (the scanner's fix advice legitimately mentions db.query)
    for (const code of ["UPDATE orders", "paid = true", "/srv/exports", "SELECT * FROM invoices", "--- a/"]) expect(json, code).not.toContain(code);

    const id = (JSON.parse(json) as { set: { findings: { id: string; ruleId: string }[] } }).set.findings.find((f) => f.ruleId === "CODE/sql-injection")!.id;
    expect((await page.request.get(`/api/security/simulate/patch?repo=acme/vault&finding=${id}`)).status()).toBe(409);

    await verify(page, { source: true });
    const again = await (await page.request.get("/api/security/findings?repo=acme/vault")).text();
    for (const code of ["UPDATE orders", "paid = true", "/srv/exports", "SELECT * FROM invoices", "--- a/"]) expect(again, code).not.toContain(code);
    expect((await page.request.get(`/api/security/simulate/patch?repo=acme/vault&finding=${id}`)).status()).toBeLessThan(500);
  });

  test("it rejects a malformed request, and the stop switch answers when nothing is running", async ({ page }) => {
    await scanVault(page);
    const bad = await page.request.post("/api/security/simulate?repo=acme/vault", { data: { source: "yes", extra: 1 } });
    expect(bad.status()).toBe(400);
    expect((await page.request.get("/api/security/simulate/patch?repo=acme/vault&finding=../x")).status()).toBe(400);
    const stop = await page.request.delete("/api/security/simulate?repo=acme/vault");
    expect(stop.ok()).toBe(true);
    expect(await stop.json()).toEqual({ stopped: 0 });
  });

  test("the report never carries a patch, and sharing never carries a verdict", async ({ page }) => {
    await scanVault(page);
    await verify(page, { source: true });
    const sarif = await (await page.request.get("/api/security/report?repo=acme/vault&format=sarif")).text();
    expect(sarif).not.toContain("--- a/");
    expect(sarif).not.toContain("UPDATE orders");
  });
});
