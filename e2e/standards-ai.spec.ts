import { expect, test, type Page } from "@playwright/test";
import { mapRepo, signIn } from "./helpers";

const panel = (page: Page) => page.getByRole("dialog", { name: /^Finding:/ });
const posture = (page: Page) => page.getByLabel("Security posture");
const standards = (page: Page) => posture(page).getByLabel("Standards");

async function scanVault(page: Page) {
  await signIn(page);
  await mapRepo(page, "acme/vault");
  await page.goto("/security?repo=acme/vault");
  await posture(page).getByRole("button", { name: /Run security scan|Scan again/ }).click();
  await expect(posture(page).getByRole("img", { name: /Security grade/ })).toBeVisible({ timeout: 30_000 });
}

test.describe("standards view and AI explanations", () => {
  test("findings are grouped by OWASP Top 10, and the categories a scan cannot judge say so", async ({ page }) => {
    await scanVault(page);
    await standards(page).getByText(/Standards · OWASP Top 10/).click();
    const tiles = standards(page).getByRole("group", { name: "OWASP Top 10 categories" });
    await expect(tiles.getByRole("button")).toHaveCount(10);

    // A03 has the SQL injection and the injected CI script; A07 has the leaked key; A06 has the vulnerable dependency
    await expect(tiles.getByRole("button", { name: /^A03 Injection: \d+ findings?, worst high/ })).toBeVisible();
    await expect(tiles.getByRole("button", { name: /^A07 .*: \d+ findings?, worst critical/ })).toBeVisible();
    await expect(tiles.getByRole("button", { name: /^A06 .*: \d+ findings?/ })).toBeVisible();

    // design review and operations cannot be judged from a repository: shown as such, never as a clean category
    for (const id of ["A04", "A09"]) {
      const t = tiles.getByRole("button", { name: new RegExp(`^${id} .*: not assessed$`) });
      await expect(t).toBeVisible();
      await expect(t).toBeDisabled();
      await expect(t).toContainText("Not assessed");
    }
    // an assessed category with nothing found is "None found", which is a different statement
    await expect(tiles.getByRole("button", { name: /^A10 .*: none found$/ })).toContainText("None found");
    await expect(standards(page)).toContainText("“Not assessed” means a scan of the repository cannot judge it");
    await expect(standards(page)).toContainText("does not mean fine");

    // opening a category lists what is in it, and each opens the deep dive
    await tiles.getByRole("button", { name: /^A03 Injection/ }).click();
    const list = standards(page).getByLabel("Findings in A03");
    await expect(list).toContainText("Checked here: SQL and command injection");
    await list.getByRole("button", { name: /SQL built from request data/ }).click();
    await expect(panel(page)).toBeVisible();
    await expect(panel(page).getByText("CWE-89")).toBeVisible();
  });

  test("the most common weaknesses are listed by CWE, linked to MITRE", async ({ page }) => {
    await scanVault(page);
    await standards(page).getByText(/Standards · OWASP Top 10/).click();
    const cwes = standards(page).getByLabel("Most common weaknesses");
    await expect(cwes.getByRole("link", { name: /CWE-798/ })).toHaveAttribute("href", "https://cwe.mitre.org/data/definitions/798.html");
    await expect(cwes.getByRole("link", { name: /CWE-89/ }).first()).toBeVisible();
  });

  test("the report carries the same mapping", async ({ page }) => {
    await scanVault(page);
    const html = await (await page.request.get("/api/security/report?repo=acme/vault&format=html")).text();
    expect(html).toContain("<h2>Standards mapping</h2>");
    expect(html).toMatch(/<b>A04<\/b> Insecure Design<\/td><td>n\/a<\/td><td>not assessed<\/td>/);
    expect(html).toMatch(/<b>A09<\/b> Security Logging[^<]*<\/td><td>n\/a<\/td><td>not assessed<\/td>/);
    expect(html).toMatch(/<b>A03<\/b> Injection<\/td><td>[1-9]\d*<\/td>/);
    expect(html).toContain("Most common weaknesses:");
  });

  test("with AI switched off, 'Explain this' says so plainly and the written reason and fix remain", async ({ page }) => {
    await scanVault(page);
    await posture(page).getByRole("button", { name: /^Code/ }).click();
    await posture(page).getByRole("button", { name: /SQL built from request data/ }).click();
    await panel(page).getByRole("button", { name: "Explain this in plain English" }).click();
    const note = panel(page).getByLabel("AI explanation").getByRole("alert");
    await expect(note).toContainText("AI explanations are off");
    await expect(note).toContainText("AI_GATEWAY_API_KEY");
    await expect(panel(page).getByText("Why it matters")).toBeVisible(); // the non-AI content is untouched
    await expect(panel(page).getByText("How to fix it")).toBeVisible();
  });

  test("the explain endpoint is for maintainers, validates its input, and only explains findings that exist", async ({ page, request }) => {
    await scanVault(page);
    const { set } = await (await page.request.get("/api/security/findings?repo=acme/vault")).json();
    const id = set.findings[0].id as string;
    const post = (r: typeof request, data: unknown) => r.post("/api/security/explain", { data, headers: { "content-type": "application/json" } });

    expect((await post(request, { repo: "acme/vault", findingId: id })).status()).toBe(401); // anonymous
    expect((await post(page.request, { repo: "acme/vault" })).status()).toBe(400); // no finding id
    expect((await post(page.request, { repo: "acme/vault", findingId: "not hex!" })).status()).toBe(400);
    expect((await post(page.request, { repo: "acme/vault", findingId: "0".repeat(16) })).status()).toBe(404); // a finding that does not exist
    const ok = await post(page.request, { repo: "acme/vault", findingId: id });
    expect(ok.status()).toBe(200);
    expect(await ok.json()).toMatchObject({ ok: false, message: expect.stringContaining("AI explanations are off") });
  });
});
