import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import { mapRepo, signIn } from "./helpers";

const MOCK = "http://localhost:4010";
const SECRET_VALUE = "q7Zp4Lm9Xv2Kd8Tn5Rb3Wc6Yh1Jf0Ga"; // inside the fixture shop's exposed .env: must never be kept anywhere
const panel = (page: Page) => page.getByRole("dialog", { name: /^Finding:/ });
const posture = (page: Page) => page.getByLabel("Security posture");
const sources = (page: Page) => posture(page).getByLabel("Sources and integrations");

const mock = (r: APIRequestContext, p: string) => r.get(`${MOCK}/__passive/${p}`);
const hits = async (r: APIRequestContext, host: string) => ((await (await mock(r, "stats")).json()) as { hits: Record<string, number> }).hits[host] ?? 0;
const publish = (r: APIRequestContext, host: string, token: string) => mock(r, `publish?host=${host}&token=${token}`);
const api = (page: Page, action: string, domain: string) => page.request.post("/api/security/domains", { data: { repo: "acme/vault", action, domain }, headers: { "content-type": "application/json" } });
const domainsOf = async (page: Page) => ((await (await page.request.get("/api/security/domains?repo=acme/vault")).json()) as { domains: { domain: string; token: string; verifiedAt?: number }[] }).domains;

/** a fresh, scanned vault with no domains and a clean fixture internet */
async function start(page: Page) {
  await mock(page.request, "reset");
  await signIn(page);
  for (const d of await domainsOf(page)) await page.request.delete(`/api/security/domains?repo=acme/vault&domain=${d.domain}`);
  await mapRepo(page, "acme/vault");
  await page.goto("/security?repo=acme/vault");
  await posture(page).getByRole("button", { name: /Run security scan|Scan again/ }).click();
  await expect(posture(page).getByRole("img", { name: /Security grade/ })).toBeVisible({ timeout: 30_000 });
}
/** add, publish the proof as a person would, and verify */
async function verified(page: Page, domain: string) {
  const { domain: d } = await (await api(page, "add", domain)).json();
  await publish(page.request, domain, d.token);
  const v = await (await api(page, "verify", domain)).json();
  expect(v.verified, `verify ${domain}`).toBe(true);
  return d.token as string;
}

test.describe("passive checks on a verified domain", () => {
  test("only valid public domain names are accepted, and only by maintainers", async ({ page, request }) => {
    await start(page);
    for (const bad of ["127.0.0.1", "localhost", "intranet", "10.0.0.5", "shop.test:8443", "evil.com/path", "printer.local", "169.254.169.254"]) {
      const r = await api(page, "add", bad);
      expect(r.status(), bad).toBe(400);
    }
    const ok = await api(page, "add", "shop.test");
    expect(ok.status()).toBe(201);
    const { domain } = await ok.json();
    expect(domain.token).toMatch(/^mc-verify-[0-9a-f]{32}$/);
    expect(domain.instructions.dns).toEqual({ type: "TXT", name: "_mission-control-verify.shop.test", value: domain.token });
    expect(domain.instructions.file.url).toBe("https://shop.test/.well-known/mission-control-verify.txt");
    const again = await (await api(page, "add", "SHOP.test")).json();
    expect(again.domain.token).toBe(domain.token); // idempotent, and case-insensitive

    expect((await request.post("/api/security/domains", { data: { repo: "acme/vault", action: "add", domain: "shop.test" }, headers: { "content-type": "application/json" } })).status()).toBe(401);
    expect((await request.get("/api/security/domains?repo=acme/vault")).status()).toBe(401);
    expect((await api(page, "frobnicate", "shop.test")).status()).toBe(400);
  });

  test("NOTHING is sent to a domain until its owner has proved it", async ({ page, request }) => {
    await start(page);
    await api(page, "add", "shop.test");
    const before = await hits(request, "shop.test");

    // not verified: asking to check is refused, and the target receives no probe at all
    const refused = await api(page, "check", "shop.test");
    expect(refused.status()).toBe(403);
    expect(((await refused.json()) as { error: string }).error).toMatch(/nothing was sent to it/);
    const v = await (await api(page, "verify", "shop.test")).json();
    expect(v.verified).toBe(false);
    expect(v.reasons.join(" ")).toContain("_mission-control-verify.shop.test");
    expect(await hits(request, "shop.test")).toBe(before); // the proof-file lookups are not probes, and nothing else arrived
  });

  test("the DNS record proves ownership, and so does a file; a wrong token does not", async ({ page, request }) => {
    await start(page);
    const { domain } = await (await api(page, "add", "shop.test")).json();
    await publish(request, "shop.test", "mc-verify-" + "0".repeat(32)); // someone else's token
    expect((await (await api(page, "verify", "shop.test")).json()).verified).toBe(false);
    await publish(request, "shop.test", domain.token);
    const ok = await (await api(page, "verify", "shop.test")).json();
    expect(ok).toMatchObject({ verified: true, via: "dns" });
    expect((await domainsOf(page))[0].verifiedAt).toBeGreaterThan(0);
  });

  test("a full check of a badly configured site finds what is wrong, and keeps none of the file contents", async ({ page, request }) => {
    await start(page);
    await verified(page, "shop.test");
    const run = await api(page, "check", "shop.test");
    expect(run.status()).toBe(200);
    const done = await run.json();
    expect(done.findings).toBeGreaterThanOrEqual(12);
    expect(done.requests).toBeLessThanOrEqual(30); // ordinary, bounded
    expect(await hits(request, "shop.test")).toBeGreaterThan(10);

    const { set } = await (await page.request.get("/api/security/findings?repo=acme/vault")).json();
    const mine = (set.findings as { title: string; severity: string; path: string; detail: { source?: string } }[]).filter((f) => f.detail.source === "passive:shop.test");
    const titles = mine.map((f) => f.title);
    for (const t of ["No HSTS header", "No Content-Security-Policy", ".env file is publicly readable", "Git repository is publicly readable", "CORS reflects any origin and allows credentials", "The site answers over plain HTTP instead of redirecting to HTTPS", "The TLS certificate expires in 9 days", "No SPF record", "No DMARC record", "The HTTP TRACE method is enabled"]) expect(titles, t).toContain(t);
    expect(titles.some((t) => /^Cookie “sessionid” is missing Secure, HttpOnly, SameSite$/.test(t))).toBe(true);
    expect(titles.some((t) => /Server header reveals a version/.test(t))).toBe(true);
    expect(mine.find((f) => f.title === ".env file is publicly readable")).toMatchObject({ severity: "high", path: "https://shop.test/.env" });
    expect(set.sources["passive:shop.test"]).toMatchObject({ status: "ok", via: "check", label: "shop.test", count: mine.length });

    // the exposed file's CONTENTS are detected by signature and discarded: never stored, shown, reported or exported
    for (const url of ["/api/security/findings?repo=acme/vault", "/api/security/report?repo=acme/vault&format=json", "/api/security/report?repo=acme/vault&format=sarif", "/api/security/report?repo=acme/vault&format=html"]) {
      expect(await (await page.request.get(url)).text(), url).not.toContain(SECRET_VALUE);
    }
  });

  test("ownership is proved again on EVERY run: once the proof is removed, nothing is sent and the domain becomes unverified", async ({ page, request }) => {
    await start(page);
    await verified(page, "shop.test");
    expect((await api(page, "check", "shop.test")).status()).toBe(200);
    const after = await hits(request, "shop.test");

    await mock(request, "unpublish?host=shop.test"); // the person (or a new owner of the domain) removed the proof
    await page.waitForTimeout(2800); // past the cooldown, so this is refused for the right reason
    const r = await api(page, "check", "shop.test");
    expect(r.status()).toBe(403);
    expect(((await r.json()) as { reasons: string[] }).reasons.length).toBeGreaterThan(0);
    expect(await hits(request, "shop.test")).toBe(after);
    expect((await domainsOf(page))[0].verifiedAt).toBeUndefined();
  });

  test("a domain can only be checked once in a while, and the refusal says when to come back", async ({ page }) => {
    await start(page);
    await verified(page, "shop.test");
    expect((await api(page, "check", "shop.test")).status()).toBe(200);
    const again = await api(page, "check", "shop.test");
    expect(again.status()).toBe(429);
    const body = await again.json();
    expect(body.error).toMatch(/checked a moment ago\. Try again in \d+ seconds/);
    expect(body.retryAfterSec).toBeGreaterThan(0);
    await page.waitForTimeout((body.retryAfterSec + 0.3) * 1000);
    expect((await api(page, "check", "shop.test")).status()).toBe(200);
  });

  test("a domain that resolves to a private address is never contacted: the check is refused and the target receives nothing", async ({ page, request }) => {
    await start(page);
    const { domain } = await (await api(page, "add", "private.test")).json();
    await publish(request, "private.test", domain.token);
    // proving ownership only READS DNS, so it can succeed; it never opens a connection to the host
    expect((await (await api(page, "verify", "private.test")).json()).verified).toBe(true);
    const r = await api(page, "check", "private.test");
    expect(r.status()).toBe(400);
    expect(((await r.json()) as { error: string }).error).toMatch(/Refused: private\.test resolves to a non-public address/);
    expect(await hits(request, "private.test")).toBe(0); // nothing reached it
    const { set } = await (await page.request.get("/api/security/findings?repo=acme/vault")).json();
    expect(set.sources?.["passive:private.test"]).toBeUndefined(); // and no result was recorded
  });

  test("a well-configured site is reported as such: almost nothing", async ({ page }) => {
    await start(page);
    await verified(page, "clean.test");
    const done = await (await api(page, "check", "clean.test")).json();
    expect(done.findings).toBe(0);
    const { set } = await (await page.request.get("/api/security/findings?repo=acme/vault")).json();
    expect(set.sources["passive:clean.test"]).toMatchObject({ status: "ok", count: 0 });
  });

  test("there is a limit on how many domains one repository can register, and a domain can be removed with its findings", async ({ page }) => {
    await start(page);
    for (const d of ["a1.test", "a2.test", "a3.test", "a4.test", "a5.test"]) expect((await api(page, "add", d)).status()).toBe(201);
    const over = await api(page, "add", "a6.test");
    expect(over.status()).toBe(409);
    expect(((await over.json()) as { error: string }).error).toMatch(/At most 5 domains/);

    for (const d of ["a1.test", "a2.test", "a3.test", "a4.test", "a5.test"]) await page.request.delete(`/api/security/domains?repo=acme/vault&domain=${d}`);
    await verified(page, "shop.test");
    await api(page, "check", "shop.test");
    expect((await (await page.request.get("/api/security/findings?repo=acme/vault")).json()).set.sources["passive:shop.test"]).toBeTruthy();
    expect((await page.request.delete("/api/security/domains?repo=acme/vault&domain=shop.test")).status()).toBe(200);
    const { set } = await (await page.request.get("/api/security/findings?repo=acme/vault")).json();
    expect(set.sources?.["passive:shop.test"]).toBeUndefined();
    expect(set.findings.filter((f: { detail: { source?: string } }) => f.detail.source === "passive:shop.test")).toHaveLength(0);
    expect((await page.request.delete("/api/security/domains?repo=acme/vault&domain=shop.test")).status()).toBe(404);
  });

  test("the whole flow in the interface: prove ownership, run the checks, read a finding, remove the domain", async ({ page, request }) => {
    await start(page);
    await sources(page).getByText("Sources and live testing").click();
    const section = sources(page).getByLabel("Check your live site");
    await expect(section).toContainText("No attacks, no logins, no guessing passwords");

    await section.getByLabel("Domain to check").fill("shop.test");
    await section.getByRole("button", { name: "Add", exact: true }).click();
    const row = section.locator("[data-domain='shop.test']");
    await expect(row).toContainText("Not verified");
    const instr = row.getByLabel("Prove you own shop.test");
    await expect(instr).toContainText("_mission-control-verify.shop.test");
    await expect(instr).toContainText("/.well-known/mission-control-verify.txt");
    await expect(instr.getByRole("button", { name: "Copy DNS record value" })).toContainText(/mc-verify-[0-9a-f]{32}/);

    await row.getByRole("button", { name: "Check ownership" }).click(); // before putting anything in place
    await expect(section.getByRole("alert")).toContainText("We could not find the proof yet.");
    await expect(section.getByRole("alert")).toContainText("DNS TXT record");

    const token = (await domainsOf(page))[0].token;
    await publish(request, "shop.test", token);
    await row.getByRole("button", { name: "Check ownership" }).click();
    await expect(section.getByRole("status")).toContainText("Ownership confirmed (DNS record)");
    await expect(row).toContainText("Ownership proven");

    await row.getByRole("button", { name: "Run checks" }).click();
    await expect(section.getByRole("status")).toContainText(/Checked shop\.test: \d+ findings from \d+ ordinary requests\./, { timeout: 30_000 });
    await expect(row).toContainText("last run");

    await posture(page).getByRole("button", { name: /^Live testing \d+/ }).click();
    await posture(page).getByRole("button", { name: /\.env file is publicly readable/ }).click();
    const d = panel(page);
    await expect(d).toContainText("https://shop.test/.env"); // the location is the URL
    await expect(d.getByLabel("Where this finding came from")).toContainText("Reported by Live check of shop.test");
    await expect(d).toContainText("treat anything it contained as leaked");
    await expect(d.locator("pre")).toHaveCount(0); // no code and no file contents: it is about a running site
    expect(await page.content()).not.toContain(SECRET_VALUE);
    await d.getByRole("button", { name: "Close finding" }).click();

    await row.getByRole("button", { name: "Stop testing shop.test" }).click();
    await expect(section.getByRole("status")).toContainText("Stopped testing shop.test and removed its findings.");
    // other specs may have imported live-testing findings into the same repository, so check this domain's own finding, not the whole group
    const live = posture(page).getByRole("button", { name: /^Live testing/ });
    if (await live.isEnabled()) {
      await live.click();
      await expect(posture(page).getByRole("button", { name: /\.env file is publicly readable/ })).toHaveCount(0);
    }
  });

  test("the report says which sites were checked directly", async ({ page }) => {
    await start(page);
    await verified(page, "shop.test");
    await api(page, "check", "shop.test");
    const html = await (await page.request.get("/api/security/report?repo=acme/vault&format=html")).text();
    expect(html).toMatch(/<b>Live check of shop\.test:<\/b> \d+ findings included \(checked directly\)\./);
    expect(html).toContain("<code>https://shop.test/.env</code>");
    expect(html).not.toContain(SECRET_VALUE);
  });
});
