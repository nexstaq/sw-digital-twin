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
});
