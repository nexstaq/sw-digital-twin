import { describe, expect, it } from "vitest";
import { buildRange } from "./generate";
import { RangeDestroyedError, RangeLimitError, startRange } from "./runtime";
import { edge, finding, JOB_DEPLOY, JOB_TEST, shopFindings, shopGraph, WF } from "./fixtures";
import type { RangeRequest, RangeSpec } from "./types";
import { fixtureGraph } from "@/lib/graph/fixture";

const spec = (over: { seed?: number } = {}) => buildRange({ sha: "b".repeat(40), graph: shopGraph() }, shopFindings(), over);
const start = (s: RangeSpec = spec(), maxEvents?: number) => startRange(s, { maxEvents });
const req = (over: Partial<RangeRequest> & Pick<RangeRequest, "method" | "path">): RangeRequest => ({ role: "user", ...over });
const proofOf = (id: string) => spec().weaknesses.find((w) => w.findingId === id)!.proof;

describe("requests", () => {
  it("an unknown path is a 404 and a malformed request is a 400", () => {
    const r = start();
    expect(r.handle(req({ method: "GET", path: "/nope" })).status).toBe(404);
    expect(r.handle(req({ method: "GET", path: "api/orders" })).status).toBe(400);
    expect(r.handle(req({ method: "GET", path: "/api/orders?x=1" })).status).toBe(400);
    expect(r.handle(req({ method: "TRACE" as never, path: "/api/orders" })).status).toBe(400);
    expect(r.handle({ method: "GET", path: "/api/orders", role: "user", extra: 1 } as never).status).toBe(400);
    expect(r.handle(req({ method: "GET", path: "/api/orders", payload: { class: "rm -rf" as never } })).status).toBe(400);
  });
  it("a route with a parameter matches any value, and a plain route wins over a parameter route", () => {
    const r = start();
    expect(r.handle(req({ method: "GET", path: "/api/orders/41" })).status).toBe(200);   // an object this user owns
    expect(r.handle(req({ method: "GET", path: "/api/orders/42" })).status).toBe(403);   // someone else's: owners are enforced by default
    expect(r.handle(req({ method: "GET", path: "/api/orders/42/extra" })).status).toBe(404);
  });
  it("the method must match", () => { expect(start().handle(req({ method: "DELETE", path: "/api/orders" })).status).toBe(404); });
  it("a normal request walks the service's dependencies and reports the time it took", () => {
    const r = start();
    const res = r.handle(req({ method: "GET", path: "/api/orders" }));
    expect(res).toMatchObject({ status: 200, body: "ok" });
    expect(res.ms).toBeGreaterThan(0);
    const visited = r.events().filter((e) => e.kind === "visit").map((e) => e.nodeId);
    expect(visited).toEqual(expect.arrayContaining(["svc:api", "svc:payments", "ext:stripe", "db:main", "q:jobs"]));
  });
});

describe("authentication", () => {
  it("an anonymous call to a write route that needs a sign-in is refused, and that is not a server error", () => {
    const r = start();
    expect(r.handle(req({ method: "POST", path: "/api/orders", role: "anonymous" })).status).toBe(401);
    expect(r.handle(req({ method: "POST", path: "/api/orders", role: "user" })).status).toBe(200);
    const e = r.events().find((x) => x.status === 401)!;
    expect(e.ok).toBe(true);
  });
  it("the unauthenticated write the scanner found is open, and calling it proves the weakness", () => {
    const res = start().handle(req({ method: "POST", path: "/api/admin/reset", role: "anonymous" }));
    expect(res).toMatchObject({ status: 200, proof: proofOf("f2") });
  });
  it("the no-auth proof is only ever given for a write, even if a read route were somehow marked open", () => {
    const s = spec();
    const get = s.endpoints.find((e) => e.method === "GET" && e.path === "/api/orders")!;
    get.auth = "none"; get.authSource = "finding";
    s.weaknesses.push({ id: "w_x", kind: "no-auth", findingId: "fx", ruleId: "CODE/no-auth-seen", severity: "low", nodeId: get.nodeId, endpointIds: [get.nodeId], proof: "SIM-PROOF-x", reachable: true });
    expect(startRange(s).handle(req({ method: "GET", path: "/api/orders", role: "anonymous" })).proof).toBeUndefined();
  });
  it("a normal signed-in call to that route proves nothing", () => { expect(start().handle(req({ method: "POST", path: "/api/admin/reset", role: "user" })).proof).toBeUndefined(); });
  it("an open read route is open to everyone and proves nothing", () => {
    const res = start().handle(req({ method: "GET", path: "/api/orders", role: "anonymous" }));
    expect(res).toMatchObject({ status: 200 });
    expect(res.proof).toBeUndefined();
  });
});

describe("a payload class only works where the scanner found that weakness", () => {
  it("the right class on the right route returns the marker, what it reached, and the crown", () => {
    const r = start();
    const res = r.handle(req({ method: "POST", path: "/api/orders", payload: { class: "sqli" } }));
    expect(res).toMatchObject({ status: 200, proof: proofOf("f1") });
    expect(res.reached).toEqual(expect.arrayContaining(["db:main", "q:jobs", "ext:stripe"]));
    expect(res.crown).toEqual([spec().datastores[0].crown]);
  });
  it("the wrong class on that route is rejected", () => { expect(start().handle(req({ method: "POST", path: "/api/orders", payload: { class: "xss" } }))).toMatchObject({ status: 400, body: "input rejected" }); });
  it("the right class on a different route is rejected", () => {
    expect(start().handle(req({ method: "GET", path: "/api/orders/7", payload: { class: "sqli" } })).status).toBe(400);
    expect(start().handle(req({ method: "GET", path: "/api/orders/7", payload: { class: "ssrf" } })).proof).toBe(proofOf("f3"));
  });
  it("a range built with no findings cannot be exploited by any class", () => {
    const clean = start(buildRange({ sha: "b".repeat(40), graph: shopGraph() }, { ...shopFindings(), findings: [] }));
    for (const c of ["sqli", "cmdi", "code-injection", "path-traversal", "ssrf", "xss", "open-redirect"] as const) {
      for (const [method, path] of [["POST", "/api/orders"], ["GET", "/api/orders/1"], ["POST", "/api/admin/reset"]] as const) {
        const res = clean.handle(req({ method, path, role: "admin", payload: { class: c } }));
        expect(res.proof).toBeUndefined();
        expect(res.status).toBe(400);
      }
    }
  });
  it("a latent weakness cannot be exercised through a request", () => {
    const r = start();
    for (const c of ["cmdi", "path-traversal", "open-redirect"] as const) expect(r.handle(req({ method: "POST", path: "/api/orders", payload: { class: c } })).proof).toBeUndefined();
  });
  it("an exploit cannot complete through a dependency that is down", () => {
    const r = start();
    r.inject("db:main", { kind: "outage" });
    const res = r.handle(req({ method: "POST", path: "/api/orders", payload: { class: "sqli" } }));
    expect(res.status).toBe(503);
    expect(res.proof).toBeUndefined();
  });
});

describe("faults", () => {
  it("an outage anywhere on the path fails the request and names where", () => {
    const r = start();
    r.inject("ext:stripe", { kind: "outage" });
    expect(r.handle(req({ method: "GET", path: "/api/orders" })).status).toBe(503);
    const failed = r.events().filter((e) => !e.ok && e.kind === "visit").map((e) => e.nodeId);
    expect(failed).toEqual(expect.arrayContaining(["ext:stripe", "svc:payments", "svc:api"]));
    expect(r.events().find((e) => e.kind === "request")!.note).toMatch(/Stripe/);
  });
  it("clearing the fault restores service", () => {
    const r = start();
    r.inject("db:main", { kind: "outage" });
    r.clearFault("db:main");
    expect(r.handle(req({ method: "GET", path: "/api/orders" })).status).toBe(200);
  });
  it("a latency fault makes the request slower by that much", () => {
    const base = start().handle(req({ method: "GET", path: "/api/orders" })).ms;
    const r = start();
    r.inject("db:main", { kind: "latency", ms: 900 });
    expect(r.handle(req({ method: "GET", path: "/api/orders" })).ms).toBeGreaterThanOrEqual(base + 900);
  });
  it("an error fault fails about that share of requests, deterministically", () => {
    const run = () => { const r = start(); r.inject("db:main", { kind: "error", rate: 0.5 }); return Array.from({ length: 200 }, () => r.handle(req({ method: "GET", path: "/api/orders" })).status); };
    const a = run();
    expect(a).toEqual(run());
    const failed = a.filter((s) => s === 503).length;
    expect(failed).toBeGreaterThan(60); expect(failed).toBeLessThan(140);
  });
  it("rejects nonsense faults", () => {
    const r = start();
    expect(() => r.inject("nope", { kind: "outage" })).toThrow(/unknown node/);
    expect(() => r.inject("db:main", { kind: "error", rate: 1.5 })).toThrow(/rate/);
    expect(() => r.inject("db:main", { kind: "error", rate: NaN })).toThrow(/rate/);
    expect(() => r.inject("db:main", { kind: "latency", ms: -1 })).toThrow(/ms/);
    expect(() => r.inject("db:main", { kind: "latency", ms: 1e9 })).toThrow(/ms/);
  });
});

describe("flows, queues and cycles", () => {
  it("a publish reaches the queue and is counted", () => {
    const r = start();
    r.flow("svc:api"); r.flow("svc:api");
    expect(r.queueDepth("q:jobs")).toBe(2);
    expect(r.flow("svc:api").reached).toEqual(expect.arrayContaining(["q:jobs", "db:main"]));
  });
  it("a queue that is down fails the publisher and nothing is queued", () => {
    const r = start();
    r.inject("q:jobs", { kind: "outage" });
    const f = r.flow("svc:api");
    expect(f).toMatchObject({ ok: false, failedAt: "q:jobs" });
    expect(r.queueDepth("q:jobs")).toBe(0);
  });
  it("a cycle in the map does not loop", () => {
    const g = shopGraph(); g.edges.push(edge("cyc", "svc:payments", "svc:api", "calls"));
    const r = start(buildRange({ sha: "b".repeat(40), graph: g }, null));
    r.flow("svc:api");
    const visits = r.events().filter((e) => e.kind === "visit");
    for (const id of ["svc:api", "svc:payments", "db:main"]) expect(visits.filter((e) => e.nodeId === id), id).toHaveLength(1);
  });
  it("a shared dependency reached by two paths is visited once per flow", () => {
    const g = shopGraph(); g.edges.push(edge("dia", "svc:payments", "db:main", "reads"));
    const r = start(buildRange({ sha: "b".repeat(40), graph: g }, null));
    r.flow("svc:api");
    expect(r.events().filter((e) => e.kind === "visit" && e.nodeId === "db:main")).toHaveLength(1);
  });
  it("an unknown node is an error, not a silent no-op", () => { expect(() => start().flow("nope")).toThrow(/unknown node/); });
});

describe("determinism", () => {
  const session = (s: RangeSpec) => {
    const r = start(s);
    r.handle(req({ method: "GET", path: "/api/orders" }));
    r.inject("db:main", { kind: "latency", ms: 300 });
    r.handle(req({ method: "POST", path: "/api/orders", payload: { class: "sqli" } }));
    r.runWorkflow(WF, { sha: "c".repeat(40) });
    return r.finish();
  };
  it("the same range and the same calls give identical events", () => { expect(session(spec())).toEqual(session(spec())); });
  it("a different seed changes the timings but not the outcomes", () => {
    const a = session(spec({ seed: 1 })), b = session(spec({ seed: 99 }));
    expect(a.events.map((e) => e.ms)).not.toEqual(b.events.map((e) => e.ms));
    expect(a.events.map((e) => `${e.nodeId}:${e.ok}`)).toEqual(b.events.map((e) => `${e.nodeId}:${e.ok}`));
  });
  it("virtual time never goes backwards", () => {
    const e = session(spec()).events.map((x) => x.t);
    expect(e.length).toBeGreaterThan(10);
    expect(e.every((t, i) => i === 0 || t >= e[i - 1])).toBe(true); // the log is in time order, event by event
    const r = start();
    const t0 = r.now(); r.handle(req({ method: "GET", path: "/api/orders" })); expect(r.now()).toBeGreaterThan(t0);
  });
  it("advance moves only the virtual clock, and refuses nonsense", () => {
    const r = start();
    r.advance(5 * 60_000);
    expect(r.now()).toBe(300_000);
    for (const bad of [-1, NaN, Infinity, 25 * 3_600_000]) expect(() => r.advance(bad)).toThrow(/advance/);
  });
});

describe("workflows", () => {
  it("run their jobs in order and deploy on success", () => {
    const r = start();
    const w = r.runWorkflow(WF, { sha: "d".repeat(40) });
    expect(w.conclusion).toBe("success");
    expect(w.jobs.map((j) => j.nodeId)).toEqual([JOB_TEST, JOB_DEPLOY]);
    expect(w.jobs[1].startedAt).toBeGreaterThanOrEqual(w.jobs[0].endedAt);
    expect(w.deploys).toEqual([{ envId: "env:production", state: "success", sha: "d".repeat(40) }]);
  });
  it("a failed job fails the run, skips what depends on it, and does not deploy", () => {
    const w = start().runWorkflow(WF, { failJob: JOB_TEST });
    expect(w.conclusion).toBe("failure");
    expect(w.jobs.map((j) => j.conclusion)).toEqual(["failure", "skipped"]);
    expect(w.jobs[0].failedStep).toBe("(simulated failure)");
    expect(w.deploys).toEqual([]);
  });
  it("a failed deploy job reports a failed deployment", () => {
    const w = start().runWorkflow(WF, { failJob: JOB_DEPLOY });
    expect(w.deploys).toEqual([{ envId: "env:production", state: "failure", sha: "0".repeat(40) }]);
  });
  it("an outsider's pull request exercises the pipeline weakness; an ordinary push does not", () => {
    const f6 = spec().weaknesses.find((w) => w.findingId === "f6")!;
    expect(start().runWorkflow(WF, { trigger: "outsider-pr" }).proofs).toEqual([f6.proof]);
    expect(start().runWorkflow(WF, { trigger: "push" }).proofs).toEqual([]);
    expect(start().runWorkflow(WF, { trigger: "pull_request" }).proofs).toEqual([]);
  });
  it("only a workflow can be run", () => {
    expect(() => start().runWorkflow("svc:api")).toThrow(/not a workflow/);
    expect(() => start().runWorkflow("wf:missing.yml")).toThrow(/not a workflow/);
  });
  it("a job with no findings behind it proves nothing even for an outsider", () => {
    const r = start(buildRange({ sha: "b".repeat(40), graph: shopGraph() }, { ...shopFindings(), findings: [finding("fx", "CODE/weak-hash", "code", "x.ts")] }));
    expect(r.runWorkflow(WF, { trigger: "outsider-pr" }).proofs).toEqual([]);
  });
});

describe("workflows on a map whose ids are not wf:/job:/env: (the demo)", () => {
  const demo = () => startRange(buildRange({ sha: "b".repeat(40), graph: fixtureGraph }, null));
  it("an environment inside a workflow is a deploy step, in the order the edges say", () => {
    const w = demo().runWorkflow("release");
    expect(w.jobs.map((j) => `${j.stage}:${j.nodeId}`)).toEqual(["env:rel-stage", "job:rel-gate", "env:rel-prod"]);
    expect(w.deploys.map((d) => `${d.envId}:${d.state}`)).toEqual(["rel-stage:success", "rel-prod:success"]);
  });
  it("a failed gate skips the production deploy, and the earlier staging deploy still happened", () => {
    const w = demo().runWorkflow("release", { failJob: "rel-gate" });
    expect(w.conclusion).toBe("failure");
    expect(w.jobs.map((j) => j.conclusion)).toEqual(["success", "failure", "skipped"]);
    expect(w.deploys.map((d) => `${d.envId}:${d.state}`)).toEqual(["rel-stage:success"]);
  });
  it("parallel jobs run side by side and the build waits for all of them", () => {
    const w = demo().runWorkflow("ci");
    const by = Object.fromEntries(w.jobs.map((j) => [j.nodeId, j]));
    expect(by["wf-build"].startedAt).toBeGreaterThanOrEqual(Math.max(by["wf-lint"].endedAt, by["wf-unit"].endedAt, by["wf-e2e"].endedAt));
    expect(by["wf-lint"].startedAt).toBe(by["wf-unit"].startedAt);
  });
  it("a failed environment stage reports a failed deploy", () => {
    const r = demo(); r.inject("rel-prod", { kind: "outage" });
    expect(r.runWorkflow("release").deploys.map((d) => `${d.envId}:${d.state}`)).toEqual(["rel-stage:success", "rel-prod:failure"]);
  });
  it("a job with no stages is not a workflow", () => { expect(() => demo().runWorkflow("wf-lint")).toThrow(/not a workflow/); });
});

describe("hard limits and teardown", () => {
  it("stops at the event limit and destroys itself", () => {
    const r = start(spec(), 25);
    expect(() => { for (let i = 0; i < 100; i++) r.handle(req({ method: "GET", path: "/api/orders" })); }).toThrow(RangeLimitError);
    expect(r.destroyed).toBe(true);
    expect(() => r.handle(req({ method: "GET", path: "/api/orders" }))).toThrow(RangeDestroyedError);
  });
  it("finish returns the events and then nothing works", () => {
    const r = start();
    r.handle(req({ method: "GET", path: "/api/orders" }));
    const { events } = r.finish();
    expect(events.length).toBeGreaterThan(0);
    expect(r.destroyed).toBe(true);
    expect(r.events()).toEqual([]);
    for (const call of [() => r.handle(req({ method: "GET", path: "/api/orders" })), () => r.flow("svc:api"), () => r.runWorkflow(WF), () => r.now(), () => r.advance(1), () => r.inject("db:main", { kind: "outage" }), () => r.queueDepth("q:jobs"), () => r.finish()]) {
      expect(call).toThrow(RangeDestroyedError);
    }
  });
  it("destroy is safe to call twice", () => { const r = start(); r.destroy(); expect(() => r.destroy()).not.toThrow(); expect(r.destroyed).toBe(true); });
  it("one range's teardown does not touch another", () => {
    const a = start(), b = start();
    a.destroy();
    expect(b.handle(req({ method: "GET", path: "/api/orders" })).status).toBe(200);
  });
});
