import { chromium, expect, test, type BrowserContext, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const APP = "http://localhost:3300";
const EXT = path.resolve("extension/dist-e2e");

// A stand-in for a GitHub repo page: the real extension is loaded, and github.com requests are answered locally.
const GITHUB_PAGE = (header: boolean) => `<!doctype html><html><body><h1>fake github</h1>${header ? '<ul class="pagehead-actions"><li>Watch</li><li>Star</li></ul>' : ""}</body></html>`;

let ctx: BrowserContext;

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  execFileSync("node", ["extension/build.mjs", `--out=${EXT}`], { env: { ...process.env, TWIN_ORIGIN: APP }, stdio: "pipe" });
  ctx = await chromium.launchPersistentContext(mkdtempSync(path.join(tmpdir(), "ext-")), {
    channel: "chromium", viewport: { width: 1280, height: 800 },
    args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`],
  });
  let header = true;
  await ctx.route("https://github.com/**", (route) => route.fulfill({ contentType: "text/html", body: GITHUB_PAGE(header) }));
  (ctx as unknown as { setHeader: (h: boolean) => void }).setHeader = (h) => { header = h; };
});
test.afterAll(async () => { await ctx.close(); });

const widget = (page: Page) => page.locator("#sw-twin-extension a");
const open = async (url: string) => { const p = await ctx.newPage(); await p.goto(url); return p; };

async function signedInAndMapped() {
  const p = await ctx.newPage();
  await p.goto(`${APP}/api/auth/login?returnTo=/repos`);
  await expect(p.getByRole("button", { name: "Signed in as alice" })).toBeVisible();
  await p.goto(`${APP}/scan?repo=acme/vault`);
  await expect(p.locator(".react-flow__node").first()).toBeVisible({ timeout: 30_000 });
  await p.close();
}

test("a public repo page gets the button and its live verdict, placed in GitHub's own button row", async () => {
  const p = await ctx.newPage();
  await p.goto(`${APP}/scan?repo=acme/shop`); // someone has mapped it
  await expect(p.locator(".react-flow__node").first()).toBeVisible({ timeout: 30_000 });
  await p.goto("https://github.com/acme/shop");

  await expect(widget(p)).toContainText("View Twin");
  await expect(widget(p)).toContainText("NO-GO"); // the fixture's newest CI run failed
  await expect(p.locator("ul.pagehead-actions li #sw-twin-extension")).toHaveCount(1);
  await expect(widget(p)).toHaveAttribute("href", `${APP}/scan?repo=acme%2Fshop`);
  await expect(widget(p)).toHaveAttribute("target", "_blank");
  expect(await widget(p).getAttribute("rel")).toContain("noopener");
  await expect(widget(p)).toHaveAttribute("title", /Launch status: NO-GO/);
  await p.close();
});

test("pages that are not a repository get nothing", async () => {
  for (const url of ["https://github.com/settings/profile", "https://github.com/acme", "https://github.com/marketplace/actions"]) {
    const p = await open(url);
    await p.waitForTimeout(800);
    await expect(p.locator("#sw-twin-extension")).toHaveCount(0);
    await p.close();
  }
});

test("GitHub navigates without reloading: the button follows to the next repo, and goes away on a non-repo page", async () => {
  const p = await open("https://github.com/acme/shop");
  await expect(widget(p)).toContainText("NO-GO");
  await p.evaluate(() => history.pushState({}, "", "/acme/vault"));
  // signed out, so a private repo points at sign-in; either way the link names the NEW repo
  await expect(widget(p)).toHaveAttribute("href", /acme(%2F|%252F)vault/, { timeout: 8_000 });
  await p.evaluate(() => history.pushState({}, "", "/settings/profile"));
  await expect(p.locator("#sw-twin-extension")).toHaveCount(0, { timeout: 8_000 });
  await p.close();
});

test("a private repo asks you to sign in, then shows its verdict through your own session", async () => {
  const before = await open("https://github.com/acme/vault");
  await expect(widget(before)).toContainText("Sign in");
  await expect(widget(before)).toHaveAttribute("href", /\/api\/auth\/login\?returnTo=/);

  await signedInAndMapped();
  // back on the GitHub tab: it refreshes by itself (after the short cache for non-verdicts has lapsed), no reload needed
  await before.waitForTimeout(5_500);
  await before.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
  await expect(widget(before)).not.toContainText("Sign in", { timeout: 15_000 });
  await expect(widget(before)).toContainText(/NO DATA|GO|HOLD/);
  await expect(widget(before)).toHaveAttribute("href", `${APP}/scan?repo=acme%2Fvault`);

  // and a brand-new page view of the same private repo works too
  const again = await open("https://github.com/acme/vault");
  await expect(widget(again)).toContainText(/NO DATA|GO|HOLD/);
  await again.close();
  await before.close();
});

test("with no button row to hook into, it falls back to a floating button", async () => {
  (ctx as unknown as { setHeader: (h: boolean) => void }).setHeader(false);
  const p = await open("https://github.com/acme/shop");
  await expect(widget(p)).toContainText("View Twin");
  await expect(p.locator("#sw-twin-extension a.float")).toHaveCount(1);
  (ctx as unknown as { setHeader: (h: boolean) => void }).setHeader(true);
  await p.close();
});

test("GitHub's own scripts get no handle on the extension, and the button holds only text", async () => {
  const p = await open("https://github.com/acme/shop");
  await expect(widget(p)).toContainText("NO-GO");
  // the page world has no extension runtime to message or inspect
  expect(await p.evaluate(() => (window as unknown as { chrome?: { runtime?: { id?: string } } }).chrome?.runtime?.id)).toBeUndefined();
  expect(await widget(p).locator("script, img, iframe").count()).toBe(0);
  await p.close();
});
