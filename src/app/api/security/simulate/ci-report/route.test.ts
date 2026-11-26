import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { seal } from "@/lib/auth/session";
import { memoryPersist } from "@/lib/persist/memory";
import { resetRateLimits } from "@/lib/security/ratelimit";
import { accessGraph, shopFindings } from "@/lib/sim/range/fixtures";

vi.mock("@/lib/persist", () => ({ persist: () => store }));
vi.mock("@/lib/security/oidc", () => ({ verifyActionsToken: vi.fn() }));

import { verifyActionsToken } from "@/lib/security/oidc";
import { POST } from "./route";

const store = memoryPersist();
const SECRET = "s".repeat(32);
const ok = (repo: string) => (verifyActionsToken as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ ok: true, claims: { repository: repo, actor: "alice" } });
const token = (over: Record<string, unknown> = {}) => seal({ v: 1, repo: "acme/shop", url: "https://staging.example.com", profile: "access", controlPath: "/__mc-control-aaaa1111", routes: ["/api/admin/stats"], exp: Date.now() + 10 * 60_000, ...over }, SECRET);

const call = (body: unknown, o: { auth?: string; repo?: string } = {}) =>
  POST(new Request(`http://x/api/security/simulate/ci-report?repo=${encodeURIComponent(o.repo ?? "acme/shop")}`, {
    method: "POST", headers: { ...(o.auth !== undefined ? { authorization: o.auth } : { authorization: "Bearer t" }), "content-type": "application/json" }, body: JSON.stringify(body),
  }));

describe("POST /api/security/simulate/ci-report", () => {
  beforeEach(async () => {
    resetRateLimits();
    process.env.SESSION_SECRET = SECRET;
    const set = shopFindings();
    await store.putSnapshot("acme/shop", { sha: set.sha, graph: accessGraph(), createdAt: 1 });
    await store.putFindings("acme/shop", set);
    vi.mocked(verifyActionsToken).mockReset();
  });
  afterEach(() => { delete process.env.SESSION_SECRET; });

  it("refuses everyone without a bearer token", async () => {
    expect((await call({}, { auth: "" })).status).toBe(401);
  });
  it("refuses a token for another repository", async () => {
    ok("acme/other");
    expect((await call({ token: token(), controlStatus: 404, controlBytes: 10, observations: [] })).status).toBe(403);
  });
  it("refuses a tampered token", async () => {
    ok("acme/shop");
    const t = token(); const bad = t.slice(0, -2) + (t.slice(-2) === "AA" ? "BB" : "AA");
    expect((await call({ token: bad, controlStatus: 404, controlBytes: 10, observations: [] })).status).toBe(401);
  });
  it("refuses an expired plan", async () => {
    ok("acme/shop");
    const t = token({ exp: Date.now() - 1000 });
    expect((await call({ token: t, controlStatus: 404, controlBytes: 10, observations: [] })).status).toBe(401);
  });
  it("refuses a plan whose own repo does not match the one in the URL (a token sealed for a different repo, replayed here)", async () => {
    ok("acme/shop");
    const t = token({ repo: "acme/other" });
    expect((await call({ token: t, controlStatus: 404, controlBytes: 10, observations: [] })).status).toBe(403);
  });
  it("accepts a well-formed report, stores a finding for an authorised route that answered, and ignores one that was not authorised", async () => {
    ok("acme/shop");
    const r = await call({ token: token(), controlStatus: 404, controlBytes: 10, observations: [{ path: "/api/admin/stats", status: 200, bytes: 2000 }, { path: "/api/not-authorised", status: 200, bytes: 2000 }] });
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(body).toMatchObject({ findings: 1, accepted: 1, rejected: 1 });
    const stored = await store.getFindings("acme/shop");
    const found = stored!.findings.find((f) => f.ruleId === "SIM/anonymous-access");
    expect(found).toBeDefined();
    expect(found!.detail.source).toBe("ci-runner");
  });
  it("a later report for the same domain replaces the earlier ci-runner findings rather than piling them up", async () => {
    ok("acme/shop");
    await call({ token: token(), controlStatus: 404, controlBytes: 10, observations: [{ path: "/api/admin/stats", status: 200, bytes: 2000 }] });
    ok("acme/shop");
    await call({ token: token(), controlStatus: 404, controlBytes: 10, observations: [{ path: "/api/admin/stats", status: 401, bytes: 10 }] }); // now fixed
    const stored = await store.getFindings("acme/shop");
    expect(stored!.findings.filter((f) => f.detail.source === "ci-runner")).toHaveLength(0);
  });
  it("the report body has no field for url or profile at all: the sealed token is the only source for both, so there is nothing to override", async () => {
    ok("acme/shop");
    const r = await call({ token: token(), controlStatus: 404, controlBytes: 10, observations: [{ path: "/api/admin/stats", status: 200, bytes: 2000 }], url: "https://evil.example.com", profile: "reachability" });
    expect(r.status).toBe(400); // an unrecognised field refuses the whole request, rather than silently ignoring it
  });
});
