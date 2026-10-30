import { expect, test } from "@playwright/test";

// Runs last (alphabetical): it deliberately exhausts a limit, which would otherwise slow every login after it.
test("a client that hammers sign-in is slowed down with a Retry-After", async ({ request }) => {
  const statuses: number[] = [];
  let retryAfter: string | undefined;
  for (let i = 0; i < 130; i++) { // login allows 20/min x RATE_LIMIT_SCALE (5) = 100
    const r = await request.get("/api/auth/login", { maxRedirects: 0 });
    statuses.push(r.status());
    if (r.status() === 429) { retryAfter = r.headers()["retry-after"]; break; }
  }
  expect(statuses).toContain(429);
  expect(Number(retryAfter)).toBeGreaterThan(0);
  expect(statuses.slice(0, 20).every((s) => s === 302)).toBe(true); // ordinary use is never throttled
});
