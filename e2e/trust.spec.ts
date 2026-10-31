import { expect, test } from "@playwright/test";
import { mapRepo, watchProblems } from "./helpers";

const SOURCE = "https://github.com/nexstaq/sw-digital-twin";

test.describe("identity and trust pages", () => {
  test("the root says what this is, who runs it, and what signing in does, instead of bouncing to a demo", async ({ page }) => {
    const problems = watchProblems(page);
    await page.goto("/");
    expect(new URL(page.url()).pathname).toBe("/"); // no redirect
    await expect(page.getByRole("heading", { level: 1 })).toContainText("how your software is built");
    await expect(page.getByText(/built and run by/i).first()).toContainText("nexstaq");
    await expect(page.getByRole("link", { name: /source code is public/i })).toHaveAttribute("href", SOURCE);
    await expect(page.getByText(/never sees your GitHub password/i).first()).toBeVisible();
    await expect(page.getByText(/not affiliated with, endorsed by or sponsored by GitHub/i)).toBeVisible();
    await expect(page.getByRole("link", { name: "Try the live demo" })).toHaveAttribute("href", "/demo");
    await expect(page.getByRole("link", { name: "Sign in with GitHub" })).toHaveAttribute("href", "/repos"); // never a direct jump to a login page
    expect(problems).toEqual([]);
  });

  test("About and Privacy exist, name the operator and the source, and carry the footer", async ({ page }) => {
    for (const [path, heading] of [["/about", /About Mission Control/], ["/privacy", /Privacy notice/]] as const) {
      const problems = watchProblems(page);
      await page.goto(path);
      await expect(page.getByRole("heading", { level: 1 })).toHaveText(heading);
      await expect(page.getByRole("link", { name: /nexstaq/ }).first()).toBeVisible();
      await expect(page.getByRole("contentinfo")).toContainText("not affiliated with");
      await expect(page.getByRole("link", { name: "Report a security problem" })).toBeVisible();
      expect(problems, path).toEqual([]);
    }
  });

  test("the privacy notice describes what the product really does", async ({ page }) => {
    await page.goto("/privacy");
    const text = await page.locator("main").innerText();
    for (const claim of ["twin_session", "twin_oauth", "never the value", "7 days", "OSV.dev", "never receive your GitHub password"]) expect(text, claim).toContain(claim);
    await expect(page.getByText(/Last updated/)).toBeVisible();
  });

  test("every link on the public pages works", async ({ page, request }) => {
    const internal = new Set<string>();
    for (const path of ["/", "/about", "/privacy"]) {
      await page.goto(path);
      for (const href of await page.locator("a[href]").evaluateAll((as) => as.map((a) => (a as HTMLAnchorElement).getAttribute("href")!))) {
        if (href.startsWith("/") && !href.startsWith("//")) internal.add(href.split("#")[0]);
      }
    }
    expect([...internal].length).toBeGreaterThan(5);
    for (const href of internal) {
      const r = await request.get(href, { maxRedirects: 0 });
      expect([200, 302], `${href} -> ${r.status()}`).toContain(r.status()); // 302 only for the sign-in handoff
    }
  });

  test("security.txt, robots and sitemap are served, and keep the API and share links away from crawlers", async ({ request }) => {
    const sec = await request.get("/.well-known/security.txt");
    expect(sec.status()).toBe(200);
    const body = await sec.text();
    expect(body).toContain("Contact: https://github.com/nexstaq/sw-digital-twin/security/advisories/new");
    const expires = /^Expires:\s*(.+)$/m.exec(body)?.[1];
    expect(Date.parse(expires!)).toBeGreaterThan(Date.now()); // an expired security.txt is worse than none

    const robots = await (await request.get("/robots.txt")).text();
    expect(robots).toMatch(/Disallow: \/api\//);
    expect(robots).toMatch(/Disallow: \/s\//);
    expect(robots).toContain("Sitemap:");
    const map = await (await request.get("/sitemap.xml")).text();
    for (const p of ["/about", "/privacy", "/demo"]) expect(map).toContain(p);
    expect(map).not.toMatch(/\/s\/|\/api\//);
  });

  test("the sign-in screen explains what happens on GitHub before you click", async ({ page }) => {
    await page.goto("/repos");
    await expect(page.getByText(/Signing in happens on github\.com/)).toBeVisible();
    await expect(page.getByRole("link", { name: "Privacy notice" })).toBeVisible();
    await expect(page.getByRole("contentinfo")).toBeVisible();
  });

  test("a signed-out visitor really gets no cookies, as the privacy notice says", async ({ page, context }) => {
    for (const path of ["/", "/about", "/privacy", "/demo", "/repos"]) await page.goto(path);
    await mapRepo(page, "acme/shop");
    await page.waitForTimeout(500);
    expect(await context.cookies()).toEqual([]);
  });

  test("no address on this site redirects to GitHub's login by itself: crawlers see an explanation page instead", async ({ request }) => {
    // the old bare sign-in URL now only leads to OUR page
    for (const url of ["/api/auth/login", "/api/auth/login?returnTo=/repos", "/api/auth/login?returnTo=https://evil.example"]) {
      const r = await request.get(url, { maxRedirects: 0 });
      expect(r.status(), url).toBe(302);
      const loc = r.headers()["location"];
      expect(loc, url).toMatch(/^\/signin\?returnTo=/);
      expect(loc).not.toContain("github");
      expect(loc).not.toContain("evil.example"); // an off-site returnTo is dropped
    }
    // and a GET can no longer start the handshake at all
    const post = await request.post("/api/auth/login", { form: { returnTo: "/repos" }, maxRedirects: 0 });
    expect(post.status()).toBe(303);
    expect(post.headers()["location"]).toContain("/login/oauth/authorize");
    expect(post.headers()["set-cookie"]).toContain("twin_oauth");
  });

  test("the sign-in page says what is about to happen, and only its button continues to GitHub", async ({ page }) => {
    const problems = watchProblems(page);
    await page.goto("/signin?returnTo=/repos");
    await expect(page.getByRole("heading", { name: "Sign in with GitHub" })).toBeVisible();
    await expect(page.getByText(/This site never sees it/)).toBeVisible();
    await expect(page.getByText(/read-only/).first()).toBeVisible();
    await expect(page.getByRole("link", { name: /source is public/ })).toHaveAttribute("href", SOURCE);
    const form = page.locator("form[action='/api/auth/login']");
    await expect(form).toHaveAttribute("method", /post/i);
    await expect(form.locator("input[name=returnTo]")).toHaveValue("/repos");
    // nothing on the page is a direct link to the login endpoint
    expect(await page.locator("a[href*='api/auth/login']").count()).toBe(0);
    await page.waitForTimeout(300);
    expect(new URL(page.url()).pathname).toBe("/signin"); // it stays put until the button is pressed
    expect(problems).toEqual([]);
  });

  test("the returnTo survives the round trip, and a hostile one is ignored", async ({ page }) => {
    await page.goto("/signin?returnTo=" + encodeURIComponent("/scan?repo=acme/shop"));
    await page.getByRole("button", { name: "Continue to GitHub" }).click();
    await expect(page.getByRole("button", { name: "Signed in as alice" })).toBeVisible();
    expect(page.url()).toContain("/scan");
    const other = await page.context().newPage();
    await other.goto("/signin?returnTo=" + encodeURIComponent("https://evil.example/steal"));
    await other.getByRole("button", { name: "Continue to GitHub" }).click();
    await expect(other).toHaveURL(/\/repos/); // not off-site: the default
  });

  test("public pages never link straight to the login endpoint", async ({ page }) => {
    for (const path of ["/", "/about", "/privacy", "/repos", "/signin"]) {
      await page.goto(path);
      expect(await page.locator("a[href*='api/auth/login']").count(), path).toBe(0);
    }
  });
});
