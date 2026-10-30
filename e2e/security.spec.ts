import { expect, test } from "@playwright/test";
import { mapRepo, watchProblems } from "./helpers";

const PAGES = ["/", "/repos", "/demo", "/demo/incident", "/design"];

for (const path of PAGES) {
  test(`${path} renders with no CSP violations or script errors`, async ({ page }) => {
    const problems = watchProblems(page);
    await page.goto(path);
    await page.waitForLoadState("networkidle");
    expect(problems).toEqual([]);
  });
}

test("a scanned map renders with no CSP violations", async ({ page }) => {
  const problems = watchProblems(page);
  await mapRepo(page, "acme/shop");
  await page.waitForTimeout(1500);
  expect(problems).toEqual([]);
});

test("pages carry the hardening headers, and the badge alone is embeddable", async ({ request }) => {
  const page = await request.get("/repos");
  const h = page.headers();
  expect(h["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(h["content-security-policy"]).not.toContain("unsafe-eval");
  expect(h["x-content-type-options"]).toBe("nosniff");
  expect(h["x-frame-options"]).toBe("DENY");
  expect(h["strict-transport-security"]).toContain("max-age");
  expect(h["cross-origin-resource-policy"]).toBe("same-origin");
  expect(h["x-powered-by"]).toBeUndefined();

  await request.get("/scan?repo=acme/shop"); // make sure there is something to badge
  const badge = await request.get("/api/badge/acme/shop");
  expect(badge.headers()["content-type"]).toContain("image/svg+xml");
  expect(badge.headers()["cross-origin-resource-policy"]).toBe("cross-origin");
});

test("the extension's verdict endpoint follows the same access rule as everything else", async ({ request }) => {
  await request.get("/api/scan?repo=acme/shop"); // map it first
  const pub = await (await request.get("/api/verdict?repo=acme/shop")).json();
  expect(pub).toMatchObject({ state: "ok", private: false, word: "NO-GO" });
  expect((await request.get("/api/verdict?repo=acme/vault")).status()).toBe(401); // private, signed out
  expect((await request.get("/api/verdict?repo=nope")).status()).toBe(400);
  expect(JSON.stringify(pub)).not.toMatch(/token|secret|hash/i);
});

test("API writes refuse anonymous callers", async ({ request }) => {
  for (const [method, url] of [["POST", "/api/shares?repo=acme/vault"], ["PUT", "/api/overrides?repo=acme/vault"], ["PUT", "/api/mappings?repo=acme/vault"]] as const) {
    const r = await request.fetch(url, { method, data: { overrides: {}, mappings: {} } });
    expect(r.status(), `${method} ${url}`).toBe(401);
  }
  expect((await request.get("/api/repos")).status()).toBe(401);
});
