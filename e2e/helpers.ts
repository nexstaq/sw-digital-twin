import { expect, type BrowserContext, type Page } from "@playwright/test";

/** Sign in through the real OAuth redirect chain (app -> mock GitHub -> callback). The test user is "alice". */
export async function signIn(page: Page, returnTo = "/repos") {
  await page.goto(`/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`);
  await expect(page.getByRole("button", { name: "Signed in as alice" })).toBeVisible();
}

export const tiles = (page: Page) => page.locator(".react-flow__node");
export const tile = (page: Page, text: string | RegExp) => page.locator(".react-flow__node", { hasText: text });

/** Paste a repo into the scan form and wait for the map to appear. */
export async function mapRepo(page: Page, repo: string) {
  await page.goto("/scan");
  await page.getByLabel("GitHub repository").fill(repo);
  await page.getByRole("button", { name: "Map it" }).click();
  await expect(tiles(page).first()).toBeVisible({ timeout: 30_000 });
}

/** Console messages that mean the page is broken: CSP violations, uncaught errors, failed resource loads. */
export function watchProblems(page: Page): string[] {
  const bad: string[] = [];
  page.on("console", (m) => { if (/Content Security|Refused to|violates/i.test(m.text())) bad.push(m.text().slice(0, 200)); });
  page.on("pageerror", (e) => bad.push(`pageerror: ${e.message.slice(0, 200)}`));
  return bad;
}

/** A clean browser with no cookies: what an anonymous person holding a link sees. */
export const anonymous = (ctx: BrowserContext) => ctx.browser()!.newContext({ viewport: { width: 1440, height: 900 } });

/** The page's own error box. Next injects an empty role=alert route announcer, which getByRole("alert") would also match. */
export const errorBox = (page: Page) => page.locator("[role=alert]:not(#__next-route-announcer__)");
