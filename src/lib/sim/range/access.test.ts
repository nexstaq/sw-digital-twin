import { describe, expect, it } from "vitest";
import { accessFindings, accessGraph, reported } from "./fixtures";
import { buildRange, classify } from "./generate";
import { startRange } from "./runtime";
import type { RangeRequest, RangeSpec, Role } from "./types";

const build = (...fs: ReturnType<typeof reported>[]) => buildRange({ sha: "b".repeat(40), graph: accessGraph() }, accessFindings(...fs));
const range = (spec: RangeSpec) => startRange(spec);
const req = (method: RangeRequest["method"], path: string, role: Role, extra: Partial<RangeRequest> = {}): RangeRequest => ({ method, path, role, ...extra });
const proofOf = (spec: RangeSpec, findingId: string) => spec.weaknesses.find((w) => w.findingId === findingId)!.proof;

describe("an access model that is enforced by default, so a weakness is a deviation from correct behaviour", () => {
  const clean = () => range(build());

  it("object ownership: a user reads their own objects, not someone else's; an admin reads any", () => {
    const r = clean();
    expect(r.handle(req("GET", "/api/orders/1", "user")).status).toBe(200); // user A's
    expect(r.handle(req("GET", "/api/orders/2", "user")).status).toBe(403); // user B's
    expect(r.handle(req("GET", "/api/orders/2", "admin")).status).toBe(200);
    expect(r.handle(req("GET", "/api/orders/2", "anonymous")).status).toBe(200); // reads are open by assumption; ownership is about signed-in callers
  });
  it("admin routes: anonymous is not signed in (401), a user is not allowed (403), an admin is", () => {
    const r = clean();
    expect(r.handle(req("GET", "/api/admin/stats", "anonymous")).status).toBe(401);
    expect(r.handle(req("GET", "/api/admin/stats", "user")).status).toBe(403);
    expect(r.handle(req("GET", "/api/admin/stats", "admin")).status).toBe(200);
  });
  it("a login route allows ten attempts a minute and then refuses, per caller", () => {
    const r = clean();
    const codes = Array.from({ length: 12 }, () => r.handle(req("POST", "/api/auth/login", "user")).status);
    expect(codes.slice(0, 10).every((c) => c === 200)).toBe(true);
    expect(codes.slice(10)).toEqual([429, 429]);
    expect(r.handle(req("POST", "/api/auth/login", "admin")).status).toBe(200); // another caller has their own count
  });
  it("the limit is per minute of virtual time: waiting clears it", () => {
    const r = clean();
    for (let i = 0; i < 11; i++) r.handle(req("POST", "/api/auth/login", "user"));
    expect(r.handle(req("POST", "/api/auth/login", "user")).status).toBe(429);
    r.advance(61_000);
    expect(r.handle(req("POST", "/api/auth/login", "user")).status).toBe(200);
  });
  it("routes that are not login-like are not rate limited", () => {
    const r = clean();
    expect(Array.from({ length: 30 }, () => r.handle(req("GET", "/api/orders", "user")).status).every((c) => c === 200)).toBe(true);
  });
  it("an expired session and a session planted by an attacker are refused on routes that need a sign-in", () => {
    const r = clean();
    for (const c of ["stale-session", "fixed-session"] as const) expect(r.handle(req("POST", "/api/orders", "user", { abuse: { class: c } })).status, c).toBe(401);
    expect(r.handle(req("GET", "/api/orders", "user", { abuse: { class: "stale-session" } })).status).toBe(200); // a public route has no session to abuse
  });
  it("skipping a step and replaying a request are refused on writes; on a read the attempt means nothing", () => {
    const r = clean();
    for (const c of ["skip-step", "replay"] as const) expect(r.handle(req("POST", "/api/checkout/pay", "user", { abuse: { class: c } })).status, c).toBe(409);
    expect(r.handle(req("GET", "/api/orders", "user", { abuse: { class: "replay" } })).status).toBe(400);
  });
  it("a privileged field in a write is ignored: nothing is applied and nobody becomes an admin", () => {
    const r = clean();
    const res = r.handle(req("PATCH", "/api/users/1", "user", { abuse: { class: "privileged-field" } }));
    expect(res).toMatchObject({ status: 200 });
    expect(res.applied).toBeUndefined();
    expect(res.proof).toBeUndefined();
    expect(r.handle(req("GET", "/api/admin/stats", "user")).status).toBe(403);
  });
  it("a request carries a payload class or an abuse class, not both", () => {
    expect(clean().handle(req("POST", "/api/orders", "user", { payload: { class: "sqli" }, abuse: { class: "replay" } })).status).toBe(400);
  });
  it("none of it shows a proof marker, because there is no weakness", () => {
    const r = clean();
    const all = [req("GET", "/api/orders/2", "user"), req("GET", "/api/admin/stats", "user"), req("PATCH", "/api/users/1", "user", { abuse: { class: "privileged-field" } }), req("POST", "/api/checkout/pay", "user", { abuse: { class: "replay" } })];
    for (const q of all) expect(r.handle(q).proof).toBeUndefined();
  });
});

describe("a weakness is a seeded deviation, and exercising it returns that finding's marker", () => {
  it("IDOR (CWE-639): a user reads another user's object", () => {
    const spec = build(reported("f_idor", "CWE-639", "api/src/order.ts"));
    const res = range(spec).handle(req("GET", "/api/orders/2", "user"));
    expect(res).toMatchObject({ status: 200, proof: proofOf(spec, "f_idor") });
    expect(range(spec).handle(req("GET", "/api/orders/1", "user")).proof).toBeUndefined(); // their own object shows nothing
  });
  it("missing function-level authorisation (CWE-862): a user reaches an admin route", () => {
    const spec = build(reported("f_authz", "CWE-862", "api/src/admin-stats.ts"));
    expect(range(spec).handle(req("GET", "/api/admin/stats", "user"))).toMatchObject({ status: 200, proof: proofOf(spec, "f_authz") });
    expect(range(spec).handle(req("GET", "/api/admin/stats", "anonymous")).status).toBe(401); // not being signed in is a different rule, still enforced
  });
  it("no limit on attempts (CWE-307): the eleventh attempt is accepted and shows the marker", () => {
    const spec = build(reported("f_rate", "CWE-307", "api/src/login.ts"));
    const r = range(spec);
    const codes = Array.from({ length: 12 }, () => r.handle(req("POST", "/api/auth/login", "user")));
    expect(codes.map((c) => c.status)).toEqual(Array(12).fill(200));
    expect(codes[9].proof).toBeUndefined();
    expect(codes[10].proof).toBe(proofOf(spec, "f_rate"));
  });
  it("weak sessions (CWE-384 / CWE-613): both an expired and a planted session are accepted", () => {
    const spec = build(reported("f_sess", "CWE-384", "api/src/users.ts"));
    for (const c of ["stale-session", "fixed-session"] as const) expect(range(spec).handle(req("PATCH", "/api/users/1", "user", { abuse: { class: c } })), c).toMatchObject({ status: 200, proof: proofOf(spec, "f_sess") });
  });
  it("business logic: a skipped step (CWE-841) and a replayed request (CWE-294) are each accepted only where reported", () => {
    const spec = build(reported("f_skip", "CWE-841", "api/src/checkout.ts"));
    expect(range(spec).handle(req("POST", "/api/checkout/pay", "user", { abuse: { class: "skip-step" } }))).toMatchObject({ status: 200, proof: proofOf(spec, "f_skip") });
    expect(range(spec).handle(req("POST", "/api/checkout/pay", "user", { abuse: { class: "replay" } })).status).toBe(409); // a different weakness, not reported
    const replay = build(reported("f_replay", "CWE-294", "api/src/checkout.ts"));
    expect(range(replay).handle(req("POST", "/api/checkout/pay", "user", { abuse: { class: "replay" } })).proof).toBe(proofOf(replay, "f_replay"));
  });
  it("mass assignment (CWE-915): the privileged field is applied, and the caller then reaches an admin route; the second call says why it was allowed", () => {
    const spec = build(reported("f_mass", "CWE-915", "api/src/users.ts"));
    const r = range(spec);
    expect(r.handle(req("GET", "/api/admin/stats", "user")).status).toBe(403); // before
    const first = r.handle(req("PATCH", "/api/users/1", "user", { abuse: { class: "privileged-field" } }));
    expect(first).toMatchObject({ status: 200, applied: true, proof: proofOf(spec, "f_mass") });
    const after = r.handle(req("GET", "/api/admin/stats", "user"));
    expect(after).toMatchObject({ status: 200, via: "escalated", proof: proofOf(spec, "f_mass") });
  });
  it("an escalation lasts as long as the range does, and applies to the caller who did it", () => {
    const spec = build(reported("f_mass", "CWE-915", "api/src/users.ts"));
    const a = range(spec);
    a.handle(req("PATCH", "/api/users/1", "user", { abuse: { class: "privileged-field" } }));
    expect(range(spec).handle(req("GET", "/api/admin/stats", "user")).status).toBe(403); // a fresh range starts clean
    expect(a.handle(req("GET", "/api/admin/stats", "anonymous")).status).toBe(401);      // nobody else gained anything
    expect(a.handle(req("GET", "/api/orders/2", "user")).via).toBeUndefined();          // and an ordinary route says nothing about it
  });
  it("without the report there is no weakness: the same requests are refused", () => {
    const r = range(build());
    expect(r.handle(req("GET", "/api/orders/2", "user")).status).toBe(403);
    expect(r.handle(req("GET", "/api/admin/stats", "user")).status).toBe(403);
  });
});

describe("where a weakness is allowed to attach", () => {
  const latent = (spec: RangeSpec, id: string) => spec.weaknesses.find((w) => w.findingId === id)!;

  it("only to routes where the behaviour exists: IDOR needs an object, a rate limit needs a login-like route, missing authorisation needs an admin route", () => {
    const spec = build(
      reported("a", "CWE-639", "api/src/login.ts"), reported("b", "CWE-307", "api/src/order.ts"), reported("c", "CWE-862", "api/src/order.ts"),
      reported("d", "CWE-639", "api/src/order.ts"), reported("e", "CWE-307", "api/src/login.ts"), reported("f", "CWE-862", "api/src/admin-stats.ts"),
    );
    for (const id of ["a", "b", "c"]) expect(latent(spec, id), id).toMatchObject({ reachable: false, endpointIds: [] });
    for (const id of ["d", "e", "f"]) expect(latent(spec, id), id).toMatchObject({ reachable: true });
  });
  it("mass assignment, skipped steps and replays attach to write routes, never to reads", () => {
    const spec = build(reported("m", "CWE-915", "api/src/order.ts"), reported("k", "CWE-841", "api/src/users.ts"));
    expect(latent(spec, "m").reachable).toBe(false); // that file only has a GET
    expect(latent(spec, "k")).toMatchObject({ reachable: true, endpointIds: ["route:api:PATCH:/api/users/[id]"] });
  });
  it("weak sessions attach only to routes that need a sign-in", () => {
    const spec = build(reported("s", "CWE-613", "api/src/order.ts"), reported("t", "CWE-613", "api/src/users.ts"));
    expect(latent(spec, "s").reachable).toBe(false); // a public read has no session
    expect(latent(spec, "t").reachable).toBe(true);
    expect(latent(spec, "t").abuses).toEqual(["stale-session", "fixed-session"]);
  });
  it("a finding about a file with no route is recorded as latent, never invented onto a route", () => {
    expect(latent(build(reported("z", "CWE-639", "api/src/elsewhere.ts")), "z")).toMatchObject({ kind: "idor", reachable: false, endpointIds: [] }); // placed on the owning service, but no route to exercise it on
  });

  it("the CWE table, and a built-in rule id always wins over a CWE tag", () => {
    const k = (ruleId: string, cwe: string[], category = "code") => classify({ ruleId, category: category as never, cwe })?.kind ?? null;
    expect(k("x", ["CWE-639"])).toBe("idor");
    expect(k("x", ["CWE-566"])).toBe("idor");
    for (const c of ["CWE-862", "CWE-285", "CWE-863", "CWE-425"]) expect(k("x", [c]), c).toBe("missing-authz");
    for (const c of ["CWE-915", "CWE-269"]) expect(k("x", [c]), c).toBe("mass-assignment");
    for (const c of ["CWE-307", "CWE-770", "CWE-799"]) expect(k("x", [c]), c).toBe("no-rate-limit");
    for (const c of ["CWE-384", "CWE-613"]) expect(k("x", [c]), c).toBe("weak-session");
    expect(k("x", ["CWE-841"])).toBe("skip-step");
    expect(k("x", ["CWE-294"])).toBe("replay");
    expect(k("CODE/sql-injection", ["CWE-639"])).toBe("sql-injection");
    expect(k("x", ["CWE-9999"])).toBeNull();
    expect(k("x", [])).toBeNull();
    expect(k("x", ["CWE-9999", "CWE-639"])).toBe("idor"); // the first one it knows
  });
});

describe("what the spec says about each route", () => {
  const spec = build();
  const ep = (label: string) => spec.endpoints.find((e) => `${e.method} ${e.path}` === label)!;
  it("the lowest role each route is meant for, whether it names one object, and whether it looks like a login", () => {
    expect(ep("GET /api/admin/stats")).toMatchObject({ minRole: "admin", auth: "required", authSource: "assumed", object: false, login: false });
    expect(ep("GET /api/orders/[id]")).toMatchObject({ minRole: "anonymous", object: true });
    expect(ep("PATCH /api/users/[id]")).toMatchObject({ minRole: "user", object: true });
    expect(ep("POST /api/auth/login")).toMatchObject({ login: true, minRole: "anonymous", auth: "public-read" }); // a sign-in route is open to someone who is not signed in yet
    expect(ep("POST /api/checkout/pay")).toMatchObject({ login: false, object: false });
  });
  it("what counts as a sign-in route: login, password, one-time-code routes, but not an admin 'reset' (found by the gray-box agent testing a clean system)", () => {
    const mk = (label: string) => buildRange({ sha: "b".repeat(40), graph: (() => { const g = accessGraph(); g.nodes.push({ ...g.nodes.find((n) => n.id === "route:api:POST:/api/auth/login")!, id: `x:${label}`, label }); return g; })() }, null).endpoints.find((e) => e.nodeId === `x:${label}`)!.login;
    for (const yes of ["POST /api/login", "POST /api/signin", "POST /api/auth/token", "POST /api/password/forgot", "POST /api/auth/reset-password", "POST /api/otp", "POST /api/2fa/verify"]) expect(mk(yes), yes).toBe(true);
    for (const no of ["POST /api/admin/reset", "POST /api/admin/login", "POST /api/reset", "GET /api/orders", "POST /api/authors"]) expect(mk(no), no).toBe(false);
  });
  it("these are labelled as assumptions", () => { for (const e of spec.endpoints) expect(e.authSource).toBe("assumed"); });
});
