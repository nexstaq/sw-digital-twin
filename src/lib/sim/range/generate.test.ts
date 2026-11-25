import { describe, expect, it } from "vitest";
import { buildRange, canonical, classify } from "./generate";
import { edge, finding, JOB_DEPLOY, MASK_CANARY, node, shopFindings, shopGraph, SUMMARY_CANARY, WF } from "./fixtures";
import { parseRoe } from "../roe";
import { fixtureGraph } from "@/lib/graph/fixture";
import { startRange } from "./runtime";

const SHA = "b".repeat(40);
const build = (over: { graph?: ReturnType<typeof shopGraph>; set?: ReturnType<typeof shopFindings> | null; seed?: number } = {}) =>
  buildRange({ sha: SHA, graph: over.graph ?? shopGraph() }, over.set === undefined ? shopFindings() : over.set, { seed: over.seed });
const ep = (spec: ReturnType<typeof build>, label: string) => spec.endpoints.find((e) => `${e.method} ${e.path}` === label)!;
const weak = (spec: ReturnType<typeof build>, findingId: string) => spec.weaknesses.find((w) => w.findingId === findingId);

describe("the same snapshot always gives the same range", () => {
  it("is byte-identical when built twice", () => { expect(canonical(build())).toBe(canonical(build())); });
  it("does not depend on the order of nodes, edges or findings", () => {
    const g = shopGraph(); g.nodes.reverse(); g.edges.reverse();
    const s = shopFindings(); s.findings.reverse();
    expect(build({ graph: g, set: s }).specHash).toBe(build().specHash);
  });
  it("a different seed, graph or finding changes the hash", () => {
    const base = build().specHash;
    expect(build({ seed: 2 }).specHash).not.toBe(base);
    const g = shopGraph(); g.nodes.push(node("svc:extra", 1, "service", "Extra"));
    expect(build({ graph: g }).specHash).not.toBe(base);
    const s = shopFindings(); s.findings.push(finding("f9", "CODE/xss-react", "code", "api/src/orders.ts"));
    expect(build({ set: s }).specHash).not.toBe(base);
  });
  it("golden: the hash of the sample range, so an accidental change to the generator is noticed", () => { expect(build().specHash).toBe("62e6f76d0f1ff46a"); });
  it("the id can be named as a `range` target in the rules of engagement", () => {
    const spec = build();
    expect(spec.id).toMatch(/^range_[0-9a-f]{16}$/);
    const roe = { version: 1, runId: "run_1", repo: "acme/shop", targets: [{ kind: "range", rangeId: spec.id }], agents: ["redteam"], allowedClasses: ["observe"], allowedTechniques: [], forbiddenTechniques: [],
      window: { notBefore: 1, notAfter: 2 }, budgets: { steps: 1, tokens: 1, wallMs: 1, costUsd: 1 }, killSwitchId: "k" };
    expect(parseRoe(roe).ok).toBe(true);
  });
});

describe("what becomes an emulator", () => {
  const spec = build();
  it("concrete runtime parts and CI jobs, not clusters, route groups, packages or files", () => {
    const ids = spec.emulators.map((e) => e.nodeId);
    expect(ids).toEqual(expect.arrayContaining(["svc:api", "svc:payments", "db:main", "q:jobs", "ext:stripe", "env:production", WF, JOB_DEPLOY]));
    for (const skipped of ["blk:backend", "pkg:api", "grp:api"]) expect(ids).not.toContain(skipped);
    expect(spec.notes.join(" ")).toMatch(/3 map nodes were not emulated/);
  });
  it("only edges between emulated nodes survive", () => { expect(spec.edges.map((e) => e.id)).toEqual(["e1", "e2", "e3", "e4", "e5", "e6"]); });
  it("routes are parsed with method, path, segments and the service that owns them", () => {
    expect(ep(spec, "GET /api/orders/[id]")).toMatchObject({ ownerId: "svc:api", segments: ["api", "orders", "[id]"] });
    expect(spec.endpoints).toHaveLength(4);
  });
  it("a node that is a group, not a route, is never a route", () => { expect(spec.endpoints.some((e) => e.nodeId === "grp:api")).toBe(false); });
  it("only jobs get a duration", () => {
    expect(spec.emulators.filter((e) => e.durationMs !== undefined).map((e) => e.kind)).toEqual(["job", "job", "job"]);
  });
});

describe("auth is assumed, except where the scanner found otherwise", () => {
  const spec = build();
  it("write routes are assumed to need a sign-in; reads are assumed open", () => {
    expect(ep(spec, "POST /api/orders")).toMatchObject({ auth: "required", authSource: "assumed" });
    expect(ep(spec, "GET /api/orders")).toMatchObject({ auth: "public-read", authSource: "assumed" });
  });
  it("a no-auth finding opens the write routes in that file, and says so", () => {
    expect(ep(spec, "POST /api/admin/reset")).toMatchObject({ auth: "none", authSource: "finding" });
  });
  it("without the finding nothing is open", () => {
    const s = build({ set: { ...shopFindings(), findings: [] } });
    expect(s.endpoints.every((e) => e.auth !== "none")).toBe(true);
  });
  it("a no-auth finding on a file with only read routes opens nothing and is latent", () => {
    const s = shopFindings(); s.findings = [finding("fa", "CODE/no-auth-seen", "code", "api/src/order.ts")];
    const r = build({ set: s });
    expect(r.endpoints.every((e) => e.auth !== "none")).toBe(true);
    expect(weak(r, "fa")).toMatchObject({ kind: "no-auth", reachable: false, endpointIds: [] });
  });
});

describe("weaknesses come only from findings", () => {
  const spec = build();
  it("a code finding attaches to every route in its file, and is reachable", () => {
    expect(weak(spec, "f1")).toMatchObject({ kind: "sql-injection", payload: "sqli", reachable: true, endpointIds: ["route:api:GET:/api/orders", "route:api:POST:/api/orders"] });
    expect(weak(spec, "f3")).toMatchObject({ kind: "ssrf", payload: "ssrf", reachable: true, endpointIds: ["route:api:GET:/api/orders/[id]"] });
  });
  it("the no-auth finding is reachable through the write route", () => { expect(weak(spec, "f2")).toMatchObject({ kind: "no-auth", reachable: true, endpointIds: ["route:api:POST:/api/admin/reset"] }); });
  it("a pipeline finding is reachable when it sits on a workflow or job", () => { expect(weak(spec, "f6")).toMatchObject({ kind: "pipeline-injection", reachable: true }); });
  it("dependency and credential findings are recorded but latent", () => {
    expect(weak(spec, "f4")).toMatchObject({ kind: "vulnerable-dependency", reachable: false });
    expect(weak(spec, "f5")).toMatchObject({ kind: "exposed-credential", reachable: false });
  });
  it("findings with no emulation, or that are not in the repository, are counted, not silently dropped", () => {
    expect(weak(spec, "f7")).toBeUndefined();
    expect(weak(spec, "f8")).toBeUndefined();
    expect(spec.notes.join(" ")).toMatch(/2 findings have no emulation yet/);
  });
  it("every weakness cites a real finding and real nodes", () => {
    const ids = new Set(shopFindings().findings.map((f) => f.id));
    const eps = new Set(spec.endpoints.map((e) => e.nodeId));
    for (const w of spec.weaknesses) { expect(ids.has(w.findingId)).toBe(true); for (const e of w.endpointIds) expect(eps.has(e)).toBe(true); }
  });
  it("no scan means no weaknesses, and the range says so", () => {
    const s = build({ set: null });
    expect(s.weaknesses).toEqual([]);
    expect(s.notes.join(" ")).toMatch(/No security scan/);
  });
  it("classification table", () => {
    const c = (ruleId: string, category: string) => classify({ ruleId, category } as never)?.kind ?? null;
    expect(c("CODE/command-injection", "code")).toBe("command-injection");
    expect(c("CODE/eval", "code")).toBe("code-injection");
    expect(c("CODE/xss-dom", "code")).toBe("xss");
    expect(c("CODE/open-redirect", "code")).toBe("open-redirect");
    expect(c("CODE/path-traversal", "code")).toBe("path-traversal");
    expect(c("GHA/unpinned-action", "pipeline")).toBe("pipeline-misconfig");
    expect(c("DOCKER/runs-as-root", "container")).toBe("container-misconfig");
    expect(c("CODE/weak-hash", "code")).toBeNull();
  });
});

describe("nothing sensitive is copied into the range", () => {
  const json = JSON.stringify(build());
  it("no node summary text, finding reason text, secret kind or masked hint", () => {
    for (const bad of [SUMMARY_CANARY, "REASON-TEXT-DO-NOT-COPY", MASK_CANARY, "GitHub token"]) expect(json).not.toContain(bad);
  });
  it("no file path from a finding", () => {
    for (const p of ["api/src/orders.ts", "api/src/order.ts", "api/src/admin.ts", "api/src/config.ts"]) expect(json).not.toContain(p);
  });
  it("proof and crown markers are synthetic and carry no real value", () => {
    for (const w of build().weaknesses) expect(w.proof).toMatch(/^SIM-PROOF-[A-Za-z0-9]+$/);
    for (const d of build().datastores) expect(d.crown).toMatch(/^SIM-CROWN-[A-Za-z0-9]+-[0-9a-f]{6}$/);
  });
});

describe("datastores", () => {
  it("get a seeded synthetic schema that never changes for the same node", () => {
    const [d] = build().datastores;
    expect(d.nodeId).toBe("db:main");
    expect(d.tables.length).toBeGreaterThanOrEqual(2);
    expect(d.tables.every((t) => /^[a-z]+$/.test(t.name) && t.rows >= 5)).toBe(true);
    expect(build().datastores[0]).toEqual(d);
  });
});

describe("the demo repository", () => {
  it("builds and starts in well under 20 seconds, and every emulated service can be walked", () => {
    const t0 = performance.now();
    const spec = buildRange({ sha: SHA, graph: fixtureGraph }, null);
    const r = startRange(spec);
    expect(performance.now() - t0).toBeLessThan(20_000);
    expect(spec.emulators.length).toBeGreaterThan(10);
    for (const e of spec.emulators.filter((x) => x.kind === "service")) expect(() => r.flow(e.nodeId)).not.toThrow();
    r.finish();
    expect(r.destroyed).toBe(true);
  });
  it("the only top-level nodes that are emulated are workflows (jobs that hold stages), never clusters", () => {
    const spec = buildRange({ sha: SHA, graph: fixtureGraph }, null);
    const top = spec.emulators.filter((e) => fixtureGraph.nodes.find((n) => n.id === e.nodeId)!.level === 0);
    expect(top.map((e) => e.nodeId).sort()).toEqual(["ci", "release"]);
    expect(top.every((e) => e.kind === "job")).toBe(true);
  });
  it("single named entry points are emulated, route groups are not", () => {
    const demo = buildRange({ sha: SHA, graph: fixtureGraph }, null).emulators.map((e) => e.nodeId);
    expect(demo).toEqual(expect.arrayContaining(["api-gw", "pay-hook"]));
    expect(build().emulators.map((e) => e.nodeId)).not.toContain("grp:api");
  });
});

describe("size", () => {
  it("a graph of several thousand nodes builds quickly", () => {
    const g = shopGraph();
    for (let i = 0; i < 3000; i++) { g.nodes.push(node(`svc:x${i}`, 1, "service", `S${i}`)); g.edges.push(edge(`ex${i}`, `svc:x${i}`, "db:main", "reads")); }
    const t0 = performance.now();
    const spec = build({ graph: g });
    expect(spec.emulators.length).toBeGreaterThan(3000);
    expect(performance.now() - t0).toBeLessThan(5000);
  });
});
