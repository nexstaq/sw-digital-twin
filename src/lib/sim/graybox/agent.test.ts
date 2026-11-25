import { describe, expect, it } from "vitest";
import { SimulationSchema, type Finding, type FindingSet } from "@/lib/security/types";
import { verifyChain } from "../audit";
import { KillRegistry } from "../agent/killswitch";
import { inspectTool } from "../agent/tools/range";
import { buildRange } from "../range/generate";
import { accessGraph, reported, shopFindings } from "../range/fixtures";
import { scope } from "../whitebox/test-scope";
import { discoverAccess, GRAYBOX_KINDS, type GrayboxInput, type GrayboxResult } from "./agent";
import { grayboxRoe, T } from "./roe";

const NOW = 1_800_000_000_000;
const SHA = "b".repeat(40);
/** the shop's own findings (including the open write route under /admin) plus whatever imported reports are given */
const withReports = (...fs: Finding[]): FindingSet => { const s = shopFindings(); return { ...s, findings: [...s.findings, ...fs] }; };
const discover = (set: FindingSet, over: Partial<GrayboxInput> = {}) => discoverAccess({ repo: "acme/shop", sha: SHA, graph: accessGraph(), set, now: () => NOW, ...over });
const violations = (r: GrayboxResult) => r.observations.filter((o) => o.violation);
const sim = (r: GrayboxResult, id: string) => r.simulations[id];
const proofOf = (r: GrayboxResult, id: string) => r.spec.weaknesses.find((w) => w.findingId === id)!.proof;

const ALL = [
  reported("f_idor", "CWE-639", "api/src/order.ts"), reported("f_authz", "CWE-862", "api/src/admin-stats.ts"), reported("f_rate", "CWE-307", "api/src/login.ts"),
  reported("f_sess", "CWE-384", "api/src/users.ts"), reported("f_mass", "CWE-915", "api/src/users.ts"), reported("f_skip", "CWE-841", "api/src/checkout.ts"), reported("f_replay", "CWE-294", "api/src/checkout.ts"),
];

describe("the acceptance case: it finds the seeded IDOR and the unauthenticated admin route", () => {
  it("IDOR: a user reads another user's order, and the finding that reported it is confirmed", async () => {
    const r = await discover(withReports(reported("f_idor", "CWE-639", "api/src/order.ts")));
    const o = violations(r).find((x) => x.test === "object-level")!;
    expect(o).toMatchObject({ route: "GET /api/orders/[id]", role: "user", status: 200, observed: "accepted", proof: proofOf(r, "f_idor") });
    expect(sim(r, "f_idor")).toMatchObject({ by: "graybox", verdict: "confirmed", confidence: "medium", source: { read: false } });
    expect(sim(r, "f_idor").summary).toMatch(/read another user's object/);
  });

  it("the unauthenticated admin route: an anonymous caller is accepted on POST /api/admin/reset", async () => {
    const r = await discover(withReports());
    const o = violations(r).find((x) => x.test === "function-level" && x.route === "POST /api/admin/reset")!;
    expect(o).toMatchObject({ role: "anonymous", status: 200, observed: "accepted", proof: proofOf(r, "f2") });
    expect(sim(r, "f2")).toMatchObject({ by: "graybox", verdict: "confirmed" });
    expect(sim(r, "f2").summary).toMatch(/not signed in.*meant for admins/);
  });

  it("it does this blind: it was told only who each route is intended for, so it tested the open route as an admin route although the range marks it open", async () => {
    const spec = buildRange({ sha: SHA, graph: accessGraph() }, withReports());
    expect(spec.endpoints.find((e) => e.path === "/api/admin/reset")).toMatchObject({ auth: "none", authSource: "finding", minRole: "admin" });
    const blind = (await inspectTool({ spec, blind: true }).run({}, { signal: new AbortController().signal })) as { routes: Record<string, unknown>[]; weaknesses?: unknown };
    for (const route of blind.routes) { expect(Object.keys(route).sort()).toEqual(["id", "login", "method", "minRole", "object", "path"]); }
    expect(blind.weaknesses).toBeUndefined();
    expect(JSON.stringify(blind)).not.toMatch(/SIM-PROOF|authSource|"auth"|findingId/);
  });

  it("every other kind of access-control weakness is found the same way, with the right test and the right marker", async () => {
    const r = await discover(withReports(...ALL));
    const want: [string, string, string][] = [
      ["f_idor", "object-level", "GET /api/orders/[id]"], ["f_authz", "function-level", "GET /api/admin/stats"], ["f_rate", "rate-limit", "POST /api/auth/login"],
      ["f_sess", "session", "PATCH /api/users/[id]"], ["f_mass", "mass-assignment", "PATCH /api/users/[id]"], ["f_skip", "workflow", "POST /api/checkout/pay"], ["f_replay", "workflow", "POST /api/checkout/pay"],
    ];
    for (const [id, test, route] of want) {
      expect(violations(r).some((o) => o.test === test && o.route === route && o.proof === proofOf(r, id)), `${id}: ${test} on ${route}`).toBe(true);
      expect(sim(r, id), id).toMatchObject({ by: "graybox", verdict: "confirmed" });
    }
  });

  it("mass assignment is followed through: the caller then reaches an admin route, and that is its own observation", async () => {
    const r = await discover(withReports(reported("f_mass", "CWE-915", "api/src/users.ts")));
    const esc = violations(r).find((o) => o.test === "escalation")!;
    expect(esc).toMatchObject({ role: "user", status: 200, observed: expect.stringMatching(/had become an admin/), proof: proofOf(r, "f_mass") });
    expect(esc.steps.length).toBe(2); // the mass-assignment request and the admin request
    expect(sim(r, "f_mass").summary).toMatch(/privileged field.*reach.*meant for admins/);
  });
});

describe("a correct system produces no false alarms", () => {
  it("with nothing wrong, every test runs and every one of them is as expected", async () => {
    const r = await discover({ ...shopFindings(), findings: [] });
    expect(violations(r)).toEqual([]);
    expect(r.simulations).toEqual({});
    const tests = new Set(r.observations.map((o) => o.test));
    for (const t of ["function-level", "object-level", "session", "workflow", "rate-limit", "mass-assignment"]) expect(tests.has(t as never), t).toBe(true);
    expect(tests.has("escalation")).toBe(false); // nothing was applied, so there is nothing to follow up
    expect(r.observations.length).toBeGreaterThan(15);
  });
  it("the lower roles really are refused, with the right codes: 401 when not signed in, 403 when signed in but not allowed", async () => {
    const r = await discover({ ...shopFindings(), findings: [] });
    const f = r.observations.filter((o) => o.test === "function-level");
    expect(f.filter((o) => o.role === "anonymous").every((o) => o.status === 401)).toBe(true);
    expect(f.filter((o) => o.role === "user").every((o) => o.status === 403)).toBe(true);
    expect(r.observations.filter((o) => o.test === "object-level").every((o) => o.status === 403)).toBe(true);
    expect(r.observations.find((o) => o.test === "rate-limit")).toMatchObject({ observed: "limited", violation: false });
  });
  it("a route that is open to everyone is reported as open once, not again as 'accepting an expired session'", async () => {
    const r = await discover(withReports());
    const reset = r.observations.filter((o) => o.route === "POST /api/admin/reset");
    expect(reset.filter((o) => o.violation).map((o) => o.test)).toEqual(["function-level", "function-level"]); // anonymous and user, nothing else
    expect(reset.some((o) => o.test === "session")).toBe(false);
    // a route that DOES refuse an anonymous caller keeps its session tests (in this graph only admin/reset is open)
    expect(r.observations.filter((o) => o.route === "POST /api/orders" && o.test === "session")).toHaveLength(2);
  });
  it("a route that does refuse anonymous callers still gets its session tests", async () => {
    const r = await discover(withReports());
    expect(r.observations.filter((o) => o.test === "session" && o.route === "GET /api/admin/stats")).toHaveLength(2);
  });
  it("a weakness reported in a file with no route to test it on is unreachable, and says the map may be missing something", async () => {
    const r = await discover(withReports(reported("f_far", "CWE-639", "api/src/login.ts")));
    expect(sim(r, "f_far")).toMatchObject({ by: "graybox", verdict: "unreachable", confidence: "low" });
    expect(sim(r, "f_far").summary).toMatch(/not a clean bill of health/);
  });
  it("only some kinds of finding get a verdict from this agent; the rest are left alone", async () => {
    const r = await discover(withReports(...ALL));
    for (const w of r.spec.weaknesses) expect(!!r.simulations[w.findingId], `${w.kind}`).toBe(GRAYBOX_KINDS.has(w.kind));
    expect(r.simulations.f1).toBeUndefined(); // the SQL injection is the white-box agent's
  });
  it("a route beyond the limit is said not to have been tested, not wrongly called safe", async () => {
    const r = await discover(withReports(reported("f_idor", "CWE-639", "api/src/order.ts")), { maxRoutes: 2 });
    expect(sim(r, "f_idor")).toMatchObject({ verdict: "not-reproduced" });
    expect(sim(r, "f_idor").summary).toMatch(/was not tested: only the first 2 routes/);
    expect(r.notes.join(" ")).toMatch(/Only the first 2 of \d+ routes/);
  });
});

describe("every claim cites the audit log, and the run stays inside its rules", () => {
  it("each cited step is a real result, and the log verifies against its head", async () => {
    const r = await discover(withReports(...ALL));
    const results = new Set(r.run.audit.filter((e) => e.kind === "tool-result").map((e) => e.seq));
    for (const [id, s] of Object.entries(r.simulations)) if (s.verdict === "confirmed") { expect(s.steps.length, id).toBeGreaterThan(0); for (const n of s.steps) expect(results.has(n), `${id} cites #${n}`).toBe(true); expect(s.head).toBe(r.run.head); }
    for (const o of violations(r)) for (const n of o.steps) expect(results.has(n)).toBe(true);
    expect(verifyChain(r.run.audit, { expectedHead: r.run.head })).toMatchObject({ ok: true });
  });
  it("every request was allowed by the guard, none refused; range only, no model, no money; only the four named techniques", async () => {
    const r = await discover(withReports(...ALL));
    expect(r.run.denies).toEqual({});
    expect(r.run.stopReason).toBe("finished");
    expect(r.run.usage).toMatchObject({ tokens: 0, costUsd: 0 });
    expect(r.run.audit[0].summary).toMatch(/agent=graybox.*targets=range/);
    const techs = new Set(r.run.audit.filter((e) => e.kind === "decision").map((e) => e.technique).filter(Boolean));
    expect([...techs].every((t) => Object.values(T).includes(t as never))).toBe(true);
    expect(techs.size).toBeGreaterThanOrEqual(3);
  });
  it("the step budget covers the work it does and is not exceeded", async () => {
    const r = await discover(withReports(...ALL));
    const roe = grayboxRoe({ repo: "acme/shop", rangeId: r.spec.id, now: NOW, routes: r.spec.endpoints.length });
    expect(r.run.usage.steps).toBeLessThanOrEqual(roe.budgets.steps);
  });
  it("its rules refuse anything but the range: another technique, a real site, an intrusive step", () => {
    const roe = grayboxRoe({ repo: "a/b", rangeId: "range_x", now: NOW, routes: 3 });
    const act = (over: Record<string, unknown>) => scope({ id: "a1", agent: "graybox", tool: "range_request", class: "probe", technique: T.access, target: { kind: "range", rangeId: "range_x" }, ...over }, roe, NOW);
    expect(act({})).toEqual({ ok: true });
    expect(act({ technique: "T1566" })).toMatchObject({ reason: "technique-not-allowed" });
    expect(act({ target: { kind: "verified-domain", url: "https://shop.example.com/" } })).toMatchObject({ reason: "target-not-in-roe" });
    expect(act({ class: "intrusive" })).toMatchObject({ reason: "class-above-agent-ceiling" });
  });
});

describe("credentials are never kept", () => {
  it("there are none to keep: a role is a name, and nothing credential-shaped is in the result, the log or the stored verdicts", async () => {
    const r = await discover(withReports(...ALL));
    const json = JSON.stringify({ o: r.observations, s: r.simulations, a: r.run.audit });
    expect(json).not.toMatch(/password|passwd|cookie|authorization|bearer|api[_-]?key|secret|session[_-]?id|jwt/i);
    for (const s of Object.values(r.simulations)) expect(SimulationSchema.safeParse(s).success).toBe(true);
    for (const o of r.observations) expect(["anonymous", "user", "admin"]).toContain(o.role);
  });
});

describe("stopping and repeating", () => {
  it("the kill switch stops it between routes: what was done is kept, and nothing else is claimed", async () => {
    const reg = new KillRegistry();
    let calls = 0;
    const set = withReports(...ALL);
    const x = discoverAccess({ repo: "acme/shop", sha: SHA, graph: accessGraph(), set, now: () => { if (++calls === 60) void reg.killRepo("acme/shop"); return NOW; }, killRegistry: reg });
    const r = await x;
    expect(r.run.stopReason).toBe("killed");
    expect(r.notes.join(" ")).toMatch(/stopped|ended early/);
    expect(reg.active()).toHaveLength(0);
    expect(r.run.audit.some((e) => e.kind === "kill")).toBe(true);
  });
  it("the same inputs give the same observations, verdicts and log head", async () => {
    const [a, b] = [await discover(withReports(...ALL)), await discover(withReports(...ALL))];
    expect(a.observations).toEqual(b.observations);
    expect(a.simulations).toEqual(b.simulations);
    expect(a.run.head).toBe(b.run.head);
  });
});
