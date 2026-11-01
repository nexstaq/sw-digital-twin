import { expect, test, type Page } from "@playwright/test";
import { mapRepo, signIn } from "./helpers";

// the secret value the mock's secret-scanning API returns (as the real one does). It must never appear anywhere we keep or show.
const SECRET_VALUE = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE";
const MOCK = "http://localhost:4010";
const APP = "http://localhost:3300";

const panel = (page: Page) => page.getByRole("dialog", { name: /^Finding:/ });
const posture = (page: Page) => page.getByLabel("Security posture");
const sources = (page: Page) => posture(page).getByLabel("Sources and integrations");

async function scanVault(page: Page) {
  await signIn(page);
  // imported reports are kept across scans by design, so each test starts by removing the ones earlier tests left (404 = none)
  for (const source of ["sarif:nuclei", "sarif:nuclei-ci"]) await page.request.delete(`/api/security/import?repo=acme/vault&source=${encodeURIComponent(source)}`);
  await mapRepo(page, "acme/vault");
  await page.goto("/security?repo=acme/vault");
  await posture(page).getByRole("button", { name: /Run security scan|Scan again/ }).click();
  // the grade can already be on screen from an earlier test's stored scan, so wait for THIS scan to end ("Scanning…" turns back into "Scan again")
  await expect(posture(page).getByRole("button", { name: "Scan again" })).toBeEnabled({ timeout: 30_000 });
  await expect(posture(page).getByRole("img", { name: /Security grade/ })).toBeVisible();
}
const openSources = async (page: Page) => { await sources(page).getByText("Sources and live testing").click(); };

const nuclei = (results: number, name = "Nuclei") => JSON.stringify({
  version: "2.1.0",
  runs: [{
    tool: { driver: { name, rules: [
      { id: "exposed-env", shortDescription: { text: "Exposed .env file" }, help: { text: "Remove the file from the web root." }, properties: { tags: ["exposure", "cwe-538"], "security-severity": "7.5" } },
      { id: "missing-csp", shortDescription: { text: "Missing Content-Security-Policy header" }, defaultConfiguration: { level: "note" } },
    ] } },
    results: [
      { ruleId: "exposed-env", level: "error", message: { text: "The .env file is publicly readable." }, locations: [{ physicalLocation: { artifactLocation: { uri: "https://staging.example.com/.env?token=SECRETQUERY#frag" } } }] },
      { ruleId: "missing-csp", message: { text: "No CSP header is sent." }, locations: [{ physicalLocation: { artifactLocation: { uri: "https://staging.example.com/" } } }] },
    ].slice(0, results),
  }],
});
const upload = (page: Page, body: string, name = "nuclei.sarif") => sources(page).getByLabel("Import a SARIF report").setInputFiles({ name, mimeType: "application/json", buffer: Buffer.from(body) });
const token = async (request: import("@playwright/test").APIRequestContext, q: Record<string, string>) => (await (await request.get(`${MOCK}/__oidc/token?${new URLSearchParams(q)}`)).json()).value as string;
const importWith = (request: import("@playwright/test").APIRequestContext, jwt: string | null, body: string, repo = "acme/vault") =>
  request.post(`${APP}/api/security/import?repo=${repo}`, { data: body, headers: { "content-type": "application/json", ...(jwt ? { authorization: `Bearer ${jwt}` } : {}) } });

test.describe("other sources: GitHub alerts, imported reports, live testing from CI", () => {
  test("GitHub's alerts are pulled in, each source says whether it worked, and the secret value is never kept", async ({ page }) => {
    await scanVault(page);
    await openSources(page);
    await expect(sources(page).locator("[data-source=dependabot]")).toContainText("GitHub Dependabot · 2 findings");
    await expect(sources(page).locator("[data-source=code-scanning]")).toContainText("unavailable");
    await expect(sources(page).locator("[data-source=code-scanning]")).toContainText("Advanced Security"); // why, and what GitHub offers
    await expect(sources(page).locator("[data-source=secret-scanning]")).toContainText("1 finding");

    // an alert about a package we ALSO found is one finding with more evidence, not two
    await posture(page).getByRole("button", { name: /^Dependencies/ }).click();
    await posture(page).getByRole("button", { name: /lodash@4\.17\.15 has 2 known vulnerabilities/ }).click();
    await expect(panel(page).getByLabel("Where this finding came from")).toContainText("Also confirmed by GitHub Dependabot");
    await panel(page).getByRole("button", { name: "Close finding" }).click();
    await expect(posture(page).getByRole("button", { name: /lodash has \d+ open Dependabot alert/ })).toHaveCount(0);

    // information we did not have: left-pad
    await posture(page).getByRole("button", { name: /left-pad has 1 open Dependabot alert/ }).click();
    await expect(panel(page).getByLabel("Where this finding came from")).toContainText("Reported by GitHub Dependabot");
    await expect(panel(page).getByRole("link", { name: "Open it there" })).toHaveAttribute("href", "https://github.com/acme/vault/security/dependabot/2");
    await panel(page).getByRole("button", { name: "Close finding" }).click();

    // GitHub secret scanning: located from its locations API, and the value is gone
    await posture(page).getByRole("button", { name: /^Dependencies/ }).click(); // clear the filter
    await posture(page).getByRole("button", { name: /^Secrets/ }).click();
    await posture(page).getByRole("button", { name: /AWS Access Key ID found by GitHub secret scanning/ }).click();
    await expect(panel(page)).toContainText("src/config.ts:2");
    await expect(panel(page)).toContainText("Reported by GitHub secret scanning");
    await expect(panel(page)).toContainText("(value not stored)");

    expect(await page.content()).not.toContain(SECRET_VALUE);
    for (const url of ["/api/security/findings?repo=acme/vault", "/api/security/report?repo=acme/vault&format=json", "/api/security/report?repo=acme/vault&format=sarif", "/api/security/report?repo=acme/vault&format=html"]) {
      expect(await (await page.request.get(url)).text(), url).not.toContain(SECRET_VALUE);
    }
  });

  test("a SARIF report from any scanner is imported; a live-test finding points at its URL, not a file", async ({ page }) => {
    await scanVault(page);
    await openSources(page);
    await upload(page, nuclei(2));
    await expect(sources(page).getByRole("status")).toContainText("Imported 2 findings from Nuclei.");
    await expect(sources(page).locator("[data-source='sarif:nuclei']")).toContainText("Nuclei (imported report) · 2 findings · uploaded");

    await posture(page).getByRole("button", { name: /^Live testing 2/ }).click();
    const row = posture(page).getByRole("button", { name: /Exposed \.env file/ });
    await expect(posture(page).getByText(/not a file in the repository, so they are listed here but do not colour the map/)).toBeVisible();
    await expect(row).toContainText("https://staging.example.com/.env"); // location is the URL...
    await expect(row).not.toContainText("SECRETQUERY"); // ...with its query string (which can carry tokens) removed
    await row.click();
    const d = panel(page);
    await expect(d.getByText("High", { exact: true }).first()).toBeVisible(); // the tool's 7.5 score
    await expect(d.getByText("CWE-538")).toBeVisible();
    await expect(d).toContainText("Remove the file from the web root.");
    await expect(d.getByLabel("Where this finding came from")).toContainText("Reported by Nuclei (imported report)");
    await expect(d.getByRole("link", { name: /staging\.example\.com/ })).toHaveCount(0); // no made-up GitHub file link
    await expect(d.getByRole("button", { name: "Show on map" })).toHaveCount(0); // it is not a file in the repository
    await expect(d.locator("pre")).toHaveCount(0); // and there is no code to show
    expect(await page.content()).not.toContain("SECRETQUERY");
  });

  test("a new report from the same tool replaces the old one; a re-scan keeps imports; bad files are refused clearly", async ({ page }) => {
    await scanVault(page);
    await openSources(page);
    await upload(page, nuclei(2));
    await expect(sources(page).getByRole("status")).toContainText("Imported 2 findings");
    await expect(sources(page).locator("[data-source='sarif:nuclei']")).toContainText("2 findings");
    await upload(page, nuclei(1)); // the second run found less: fixed things disappear
    await expect(sources(page).getByRole("status")).toContainText("Imported 1 finding from Nuclei.");
    await expect(sources(page).locator("[data-source='sarif:nuclei']")).toContainText("1 finding");

    await posture(page).getByRole("button", { name: "Scan again" }).click();
    await expect(posture(page).getByRole("button", { name: "Scan again" })).toBeVisible({ timeout: 30_000 });
    await expect(sources(page).locator("[data-source='sarif:nuclei']")).toContainText("1 finding"); // a re-scan does not lose what CI told us

    await upload(page, "this is not json", "junk.sarif");
    await expect(sources(page).getByRole("alert")).toContainText("not valid JSON");
    await upload(page, JSON.stringify({ hello: "world" }), "other.json");
    await expect(sources(page).getByRole("alert")).toContainText("does not look like SARIF");
    await expect(sources(page).locator("[data-source='sarif:nuclei']")).toContainText("1 finding"); // nothing was damaged
  });

  test("an imported report can be removed, and only by a signed-in maintainer", async ({ page, request }) => {
    await scanVault(page);
    await openSources(page);
    await upload(page, nuclei(2));
    await expect(sources(page).getByRole("status")).toContainText("Imported 2 findings");
    await expect(posture(page).getByRole("button", { name: /^Live testing 2/ })).toBeVisible();

    await sources(page).getByRole("button", { name: "Remove Nuclei (imported report)" }).click();
    await expect(sources(page).getByRole("status")).toContainText("Removed 2 findings.");
    await expect(sources(page).locator("[data-source='sarif:nuclei']")).toHaveCount(0);
    await expect(posture(page).getByRole("button", { name: /^Live testing/ })).toBeDisabled();

    // the API: anonymous and CI callers cannot delete; only imported reports can be targeted; nothing to remove is a 404
    const del = (source: string, r = request, headers: Record<string, string> = {}) => r.delete(`${APP}/api/security/import?repo=acme/vault&source=${encodeURIComponent(source)}`, { headers });
    expect((await del("sarif:nuclei")).status()).toBe(401);
    expect((await del("sarif:nuclei", request, { authorization: `Bearer ${await token(request, { repo: "acme/vault", aud: APP })}` })).status()).toBe(401); // CI can add, not delete
    expect((await page.request.delete(`/api/security/import?repo=acme/vault&source=dependabot`)).status()).toBe(400); // built-in sources are not removable
    expect((await page.request.delete(`/api/security/import?repo=acme/vault&source=${encodeURIComponent("../../x")}`)).status()).toBe(400);
    expect((await page.request.delete(`/api/security/import?repo=acme/vault&source=sarif:nuclei`)).status()).toBe(404);
  });

  test("CI: a workflow's OIDC token imports into ITS OWN repository, with provenance", async ({ page, request }) => {
    await scanVault(page);
    const jwt = await token(request, { repo: "acme/vault", aud: APP });
    const r = await importWith(request, jwt, nuclei(2, "Nuclei CI"));
    expect(r.status()).toBe(200);
    expect(await r.json()).toMatchObject({ tool: "Nuclei CI", imported: 2, skipped: 0 });

    await page.reload();
    await openSources(page);
    const src = sources(page).locator("[data-source='sarif:nuclei-ci']");
    await expect(src).toContainText("2 findings · from CI");
    await expect(src).toContainText("workflow “Live security test”, main, started by alice"); // who ran it
    await expect(posture(page).getByRole("button", { name: /^Live testing 2/ })).toBeVisible();
  });

  test("CI tokens that must be refused: wrong repository, wrong audience, expired, tampered, unknown key", async ({ page, request }) => {
    await scanVault(page);
    const body = nuclei(1);
    const expectRefused = async (jwt: string, status: number, text: RegExp, label: string) => {
      const r = await importWith(request, jwt, body);
      expect(r.status(), label).toBe(status);
      expect(((await r.json()) as { error: string }).error, label).toMatch(text);
    };
    await expectRefused(await token(request, { repo: "acme/shop", aud: APP }), 403, /different repository/, "token for another repo");
    await expectRefused(await token(request, { repo: "acme/vault", aud: "https://evil.example" }), 401, /wrong audience/, "token minted for another service");
    await expectRefused(await token(request, { repo: "acme/vault", aud: APP, expIn: "-600" }), 401, /expired/, "expired");
    await expectRefused(await token(request, { repo: "acme/vault", aud: APP, kid: "other-key" }), 401, /unknown signing key/, "unknown key id");

    const good = await token(request, { repo: "acme/vault", aud: APP });
    const [h, p, s] = good.split(".");
    const forged = `${h}.${Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, "base64url").toString()), repository: "acme/shop" })).toString("base64url")}.${s}`;
    await expectRefused(forged, 401, /bad signature/, "payload swapped after signing");
    await expectRefused(`${h}.${p}.${s.slice(0, -4)}AAAA`, 401, /bad signature/, "corrupted signature");
    await expectRefused("not.a.jwt", 401, /refused/, "garbage");
  });

  test("with no token and no session, importing is refused; a signed-in maintainer is allowed", async ({ page, request }) => {
    const anon = await importWith(request, null, nuclei(1));
    expect(anon.status()).toBe(401);
    await scanVault(page);
    const viaSession = await page.request.post(`/api/security/import?repo=acme/vault`, { data: nuclei(1), headers: { "content-type": "application/json" } });
    expect(viaSession.status()).toBe(200);
  });

  test("an import is capped in size; with no scan yet, a person is told to scan first, but a CI run (which names its commit) can start the record", async ({ page, request }) => {
    await scanVault(page);
    const big = await page.request.post(`/api/security/import?repo=acme/vault`, { data: "x".repeat(5_100_000), headers: { "content-type": "application/json" } });
    expect(big.status()).toBe(413);

    // acme/shop has never had a security scan in this run
    const person = await page.request.post(`/api/security/import?repo=acme/shop`, { data: nuclei(1), headers: { "content-type": "application/json" } });
    expect(person.status()).toBe(409);
    expect(((await person.json()) as { error: string }).error).toMatch(/Run a security scan first/);

    const ci = await importWith(request, await token(request, { repo: "acme/shop", aud: APP }), nuclei(1), "acme/shop");
    expect(ci.status()).toBe(200);
    const { set } = await (await page.request.get("/api/security/findings?repo=acme/shop")).json();
    expect(set.sha).toMatch(/^[0-9a-f]{40}$/); // taken from the token's commit claim
    expect(set.findings.filter((f: { detail: { source?: string } }) => f.detail.source === "sarif:nuclei")).toHaveLength(1);
    expect(set.sources["sarif:nuclei"]).toMatchObject({ via: "ci", label: "Nuclei" });
    await page.request.delete(`/api/security/import?repo=acme/shop&source=sarif:nuclei`); // leave it as we found it
  });

  test("the CI workflow for live testing is offered with its safety steps, and the YAML says what it will and will not do", async ({ page }) => {
    await scanVault(page);
    await openSources(page);
    await sources(page).getByRole("button", { name: "Add live testing to your CI" }).click();
    const ci = sources(page).getByLabel("Live testing in your CI");
    await expect(ci).toContainText("Mission Control sends no test traffic anywhere");
    await expect(ci).toContainText("SECURITY_TEST_TARGET");
    await expect(ci).toContainText("only if you own that site or are authorised to test it");
    const yaml = await ci.getByLabel("Workflow file").innerText();
    for (const s of ["id-token: write", "workflow_dispatch", "SECURITY_TEST_CONFIRM_OWNER", "-etags dos,intrusive,fuzz,bruteforce", "@sha256:", `MC_ORIGIN: ${APP}`, "/api/security/import?repo=$GITHUB_REPOSITORY"]) expect(yaml, s).toContain(s);
    expect(yaml).not.toContain("pull_request");
    await expect(ci.getByRole("button", { name: "Copy workflow" })).toBeVisible();
  });

  test("the report lists every source, including the ones that were not available, and labels live testing", async ({ page }) => {
    await scanVault(page);
    await openSources(page);
    await upload(page, nuclei(2));
    await expect(sources(page).getByRole("status")).toContainText("Imported 2 findings");
    const html = await (await page.request.get("/api/security/report?repo=acme/vault&format=html")).text();
    expect(html).toContain("<b>GitHub Dependabot:</b> 2 findings included.");
    expect(html).toContain("<b>GitHub code scanning:</b> <b>not available.</b>");
    expect(html).toContain("Advanced Security");
    expect(html).toContain("<b>Nuclei (imported report):</b> 2 findings included (uploaded).");
    expect(html).toContain("Live testing: 2");
    expect(html).toContain("<code>https://staging.example.com/.env</code>");
    expect(html).not.toContain("SECRETQUERY");
  });
});
