import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { memoryPersist } from "@/lib/persist/memory";
import { resetRateLimits } from "@/lib/security/ratelimit";
import { fixtureWorld, SHA } from "@/lib/sim/whitebox/world";

vi.mock("@/lib/persist", () => ({ persist: () => store }));
vi.mock("@/lib/security/oidc", () => ({ verifyActionsToken: vi.fn() }));

import { verifyActionsToken } from "@/lib/security/oidc";
import { POST } from "./route";

const store = memoryPersist();
const ok = (repo: string) => (verifyActionsToken as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ ok: true, claims: { repository: repo, actor: "alice" } });

const call = (body: unknown, o: { auth?: string; repo?: string } = {}) =>
  POST(new Request(`http://x/api/security/simulate/ci-plan?repo=${encodeURIComponent(o.repo ?? "acme/shop")}`, {
    method: "POST", headers: { ...(o.auth !== undefined ? { authorization: o.auth } : { authorization: "Bearer t" }), "content-type": "application/json" }, body: JSON.stringify(body),
  }));

describe("POST /api/security/simulate/ci-plan", () => {
  beforeEach(async () => {
    resetRateLimits();
    process.env.SESSION_SECRET = "s".repeat(32);
    const { graph, set } = await fixtureWorld();
    await store.putSnapshot("acme/shop", { sha: SHA, graph, createdAt: 1 });
    await store.putFindings("acme/shop", set);
    vi.mocked(verifyActionsToken).mockReset();
  });
  afterEach(() => { delete process.env.SESSION_SECRET; });

  it("refuses everyone without a bearer token", async () => {
    expect((await call({}, { auth: "" })).status).toBe(401);
  });
  it("refuses a token GitHub itself refused", async () => {
    vi.mocked(verifyActionsToken).mockResolvedValueOnce({ ok: false, reason: "bad signature" });
    expect((await call({})).status).toBe(401);
  });
  it("refuses a token for another repository: the acceptance case", async () => {
    ok("acme/other");
    const r = await call({ url: "https://staging.example.com", profile: "access", confirmed: true });
    expect(r.status).toBe(403);
  });
  it("refuses a malformed body (bad origin, unknown profile, or an unset confirmation)", async () => {
    for (const bad of [{ url: "http://staging.example.com", profile: "access", confirmed: true }, { url: "https://staging.example.com", profile: "exploit", confirmed: true }, { url: "https://staging.example.com", profile: "access", confirmed: false }, {}]) {
      ok("acme/shop");
      expect((await call(bad)).status, JSON.stringify(bad)).toBe(400);
    }
  });
  it("needs a scan and a map first", async () => {
    ok("acme/new");
    expect((await call({ url: "https://staging.example.com", profile: "access", confirmed: true }, { repo: "acme/new" })).status).toBe(409);
  });
  it("returns a plan with routes and a sealed token, never a secret or the map itself", async () => {
    ok("acme/shop");
    const r = await call({ url: "https://staging.example.com", profile: "access", confirmed: true });
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(body.runId).toMatch(/^cp_/);
    expect(Array.isArray(body.routes)).toBe(true);
    expect(typeof body.token).toBe("string");
    expect(JSON.stringify(body)).not.toMatch(/password|secret/i);
  });
  it("503s cleanly when the signing secret is not configured, rather than issuing an unsigned plan", async () => {
    delete process.env.SESSION_SECRET;
    ok("acme/shop");
    expect((await call({ url: "https://staging.example.com", profile: "access", confirmed: true })).status).toBe(503);
  });
});
