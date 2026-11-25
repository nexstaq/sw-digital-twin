import { describe, expect, it } from "vitest";
import { fixtureGraph } from "@/lib/graph/fixture";
import type { TwinGraph } from "@/lib/graph/types";
import { buildRange } from "../range/generate";
import { shopGraph, WF, JOB_TEST, JOB_DEPLOY } from "../range/fixtures";
import { PERSONAS, runScenario, type SimRun } from "./play";
import { scenarioFor, suggest, type Scenario } from "./scenario";
import { simulateHealth } from "./fault";

const BASE = Date.UTC(2026, 10, 25, 12, 0, 0);
const rig = (graph: TwinGraph) => {
  const spec = buildRange({ sha: "b".repeat(40), graph }, null);
  const sc = (id: string): Scenario => { const r = scenarioFor(spec, graph, id); if (!r.ok) throw new Error(`${id}: ${r.reason}`); return r.scenario; };
  return { spec, graph, sc, run: (id: string, fault?: NonNullable<Parameters<typeof runScenario>[3]>["fault"]) => runScenario(spec, graph, sc(id), { fault }) };
};
const shop = rig(shopGraph());
const demo = rig(fixtureGraph);
const state = (g: TwinGraph, id: string) => g.nodes.find((n) => n.id === id)!.state;

describe("what gets simulated for each kind of block", () => {
  it("a route: one request through it, with a path that matches the route and a signed-in user", () => {
    expect(shop.sc("route:api:GET:/api/orders/[id]")).toMatchObject({ kind: "request", entryId: "route:api:GET:/api/orders/[id]", request: { method: "GET", path: "/api/orders/1", role: "user" } });
  });
  it("a service: a request reaching it", () => { expect(shop.sc("svc:api")).toMatchObject({ kind: "flow", entryId: "svc:api", focusId: "svc:api" }); });
  it("a datastore, queue or outside service: the first service that uses it, so you see it in use", () => {
    for (const id of ["db:main", "q:jobs"]) expect(shop.sc(id)).toMatchObject({ kind: "flow", entryId: "svc:api", focusId: id });
    expect(shop.sc("ext:stripe")).toMatchObject({ entryId: "svc:payments", focusId: "ext:stripe" });
  });
  it("a pipeline, and a job inside it: the whole pipeline running", () => {
    expect(shop.sc(WF)).toMatchObject({ kind: "workflow", entryId: WF });
    expect(shop.sc(JOB_TEST)).toMatchObject({ kind: "workflow", entryId: WF, focusId: JOB_TEST });
  });
  it("an environment that a pipeline releases to: that release", () => { expect(shop.sc("env:production")).toMatchObject({ kind: "workflow", entryId: WF }); });
  it("an environment inside a pipeline (the demo): the pipeline it belongs to", () => { expect(demo.sc("rel-prod")).toMatchObject({ kind: "workflow", entryId: "release" }); });
  it("a grouping block: the most connected thing inside it", () => {
    expect(demo.sc("orders")).toMatchObject({ focusId: "orders", entryId: "ord-svc" });
    expect(demo.sc("ci")).toMatchObject({ kind: "workflow", entryId: "ci" });
  });
  it("code structure and unknown blocks explain why there is nothing to run", () => {
    expect(scenarioFor(shop.spec, shop.graph, "pkg:api")).toMatchObject({ ok: false, reason: expect.stringMatching(/not something that runs/) });
    expect(scenarioFor(shop.spec, shop.graph, "nope")).toMatchObject({ ok: false, reason: expect.stringMatching(/not on the map/) });
    expect(scenarioFor(demo.spec, demo.graph, "f-idem")).toMatchObject({ ok: false });
  });
  it("every block on the demo map either has a scenario or says why not, and none throws", () => {
    for (const n of fixtureGraph.nodes) {
      const r = scenarioFor(demo.spec, demo.graph, n.id);
      expect(r.ok ? r.scenario.focusId : r.reason.length > 10, n.id).toBeTruthy();
      if (r.ok) expect(() => runScenario(demo.spec, demo.graph, r.scenario), n.id).not.toThrow();
    }
  });
});

describe("the steps of a run", () => {
  it("a request: the route first, then the service, then what it depends on, parents before children", () => {
    const run = shop.run("route:api:POST:/api/orders");
    const ids = run.steps.map((s) => s.nodeId);
    expect(ids[0]).toBe("route:api:POST:/api/orders");
    expect(ids[1]).toBe("svc:api");
    expect(new Set(ids)).toEqual(new Set(["route:api:POST:/api/orders", "svc:api", "svc:payments", "ext:stripe", "db:main", "q:jobs"]));
    for (const s of run.steps.slice(1)) expect(ids.indexOf(s.from!), `${s.nodeId} comes after what called it`).toBeLessThan(ids.indexOf(s.nodeId));
    expect(run.ok).toBe(true);
    expect(run.edges).toEqual(expect.arrayContaining(["e1", "e2", "e3", "e4"]));
  });
  it("a pipeline: a trigger, the jobs in dependency order, then the release they lead to", () => {
    expect(shop.run(WF).steps.map((s) => `${s.kind}:${s.nodeId}`)).toEqual([`trigger:${WF}`, `job:${JOB_TEST}`, `job:${JOB_DEPLOY}`, "deploy:env:production"]);
  });
  it("the demo's release pipeline shows its environments as deploy steps", () => {
    expect(demo.run("release").steps.map((s) => `${s.kind}:${s.nodeId}`)).toEqual(["trigger:release", "deploy:rel-stage", "job:rel-gate", "deploy:rel-prod"]);
  });
  it("the queue demo: publish, then the consumer", () => {
    const ids = demo.run("ord-q").steps.map((s) => s.nodeId);
    expect(ids).toEqual(["ord-svc", "ord-q", "ord-wh"]);
  });
  it("is the same every time", () => { expect(shop.run("svc:api")).toEqual(shop.run("svc:api")); });
  it("step numbers are 0..n-1 in order", () => { expect(shop.run("svc:api").steps.map((s) => s.index)).toEqual([0, 1, 2, 3, 4, 5].slice(0, shop.run("svc:api").steps.length)); });
});

describe("a fault changes what is shown", () => {
  it("an outage stops the flow where it happens and says so in all three voices", () => {
    const run = shop.run("svc:api", { nodeId: "db:main", fault: { kind: "outage" } });
    expect(run.ok).toBe(false);
    expect(run.failedAt).toBe("db:main");
    const db = run.steps.find((s) => s.nodeId === "db:main")!;
    expect(db.ok).toBe(false);
    for (const p of PERSONAS) expect(db.text[p]).toMatch(/not answer|failed|unavailable/i);
    expect(run.steps.find((s) => s.nodeId === "svc:api")!.ok).toBe(false);
  });
  it("a failed pipeline job: the job fails and what needs it is skipped", () => {
    const run = shop.run(WF, { nodeId: JOB_TEST, fault: { kind: "outage" } });
    expect(run.steps.map((s) => [s.nodeId, s.ok, s.note])).toEqual([[WF, true, undefined], [JOB_TEST, false, "(injected fault)"], [JOB_DEPLOY, true, "skipped"]]);
    expect(run.ok).toBe(false);
    expect(run.steps.at(-1)!.text.engineer).toMatch(/skipped/);
  });
});

const wordsOf = (graph: TwinGraph, run: SimRun) => run.steps.flatMap((s) => PERSONAS.map((p) => ({ s, p, text: s.text[p] })));
describe("the words never invent a block", () => {
  const runs: [string, SimRun][] = [
    ["shop route", shop.run("route:api:POST:/api/orders")], ["shop service", shop.run("svc:api")], ["shop pipeline", shop.run(WF)],
    ["shop outage", shop.run("svc:api", { nodeId: "q:jobs", fault: { kind: "outage" } })],
    ["demo release", demo.run("release")], ["demo queue", demo.run("ord-q")], ["demo payments", demo.run("pay-hook")], ["demo web", demo.run("web-cdn")],
    ["demo failing gate", demo.run("release", { nodeId: "rel-gate", fault: { kind: "outage" } })],
  ];
  it.each(runs)("%s: every ref is on the map", (_n, run) => {
    for (const s of run.steps) for (const id of s.refs) expect(fixtureGraph.nodes.concat(shopGraph().nodes).some((n) => n.id === id), id).toBe(true);
  });
  it.each(runs)("%s: each voice names the block it is about, and no other block on the map", (_n, run) => {
    const graph = run.steps[0].nodeId in Object.fromEntries(fixtureGraph.nodes.map((n) => [n.id, 1])) ? fixtureGraph : shopGraph();
    for (const { s, p, text } of wordsOf(graph, run)) {
      const refs = s.refs.map((id) => graph.nodes.find((n) => n.id === id)!);
      const allowed = refs.flatMap((n) => [n.label, n.narrative?.name ?? n.label]);
      expect(allowed.some((l) => text.includes(l)), `${p}: "${text}" should name ${allowed.join(" / ")}`).toBe(true);
      for (const n of graph.nodes) {
        const names = [n.label, n.narrative?.name].filter((x): x is string => !!x && x.length >= 4);
        for (const nm of names) {
          if (!text.includes(nm)) continue;
          const covered = allowed.some((a) => a.includes(nm) || nm.includes(a) && a === nm);
          expect(covered, `${p}: "${text}" mentions "${nm}" which is not one of its blocks`).toBe(true);
        }
      }
    }
  });
  it("the three voices differ", () => {
    for (const [, run] of runs) for (const s of run.steps) expect(new Set(PERSONAS.map((p) => s.text[p])).size, s.nodeId).toBe(3);
  });
  it("evidence is only what the map itself cites, never empty text, and never the placeholder path", () => {
    for (const [, run] of runs) for (const s of run.steps) for (const e of s.evidence) {
      expect(e).not.toMatch(/^\.($|:)/);
      const path = e.split(":")[0];
      expect([...fixtureGraph.nodes, ...shopGraph().nodes].some((n) => n.evidence.some((x) => x.path === path))).toBe(true);
    }
  });
  it("a route step says whether its sign-in rule is a fact or an assumption", () => {
    expect(shop.run("route:api:POST:/api/orders").steps[0].text.security).toMatch(/assumption/);
  });
  it("no step is written by a model", () => { for (const [, run] of runs) for (const s of run.steps) expect(Object.keys(s.text).sort()).toEqual([...PERSONAS].sort()); });
});

describe("faults and the health of the map (judged by the real engine)", () => {
  const sc = shop.sc("route:api:GET:/api/orders");
  const sim = (fault?: Parameters<typeof simulateHealth>[3]["fault"]) => simulateHealth(shop.spec, shop.graph, sc, { baseTs: BASE, fault });
  it("with no fault, what the run touched is healthy and everything else is unknown, never a guessed green", () => {
    const { graph, changed } = sim();
    for (const id of ["svc:api", "svc:payments", "db:main", "q:jobs", "ext:stripe"]) expect(state(graph, id), id).toBe("nominal");
    expect(state(graph, JOB_TEST)).toBe("unknown");
    expect(state(graph, WF)).toBe("unknown");
    expect(changed).toEqual([]);
  });
  it("an outage turns that block and what depends on it failing, and lists exactly what changed", () => {
    const { graph, changed } = sim({ nodeId: "db:main", fault: { kind: "outage" } });
    expect(state(graph, "db:main")).toBe("failing");
    expect(state(graph, "svc:api")).toBe("failing");
    expect(changed.map((c) => c.nodeId)).toEqual(expect.arrayContaining(["db:main", "svc:api"]));
    for (const c of changed) { expect(c.before).toBe("nominal"); expect(c.after).toBe(state(graph, c.nodeId)); expect(c.reasons.length).toBeGreaterThan(0); }
    expect(changed.every((c) => c.before !== c.after)).toBe(true);
  });
  it("blocks the run never touched are not blamed", () => {
    const { changed } = sim({ nodeId: "db:main", fault: { kind: "outage" } });
    expect(changed.map((c) => c.nodeId)).not.toContain(JOB_TEST);
  });
  it("errors on half the calls make it failing; the reason says error rate", () => {
    const { graph } = sim({ nodeId: "db:main", fault: { kind: "error", rate: 0.5 } });
    expect(state(graph, "db:main")).toBe("failing");
    expect(graph.nodes.find((n) => n.id === "db:main")!.reasons.join(" ")).toMatch(/Error rate/);
  });
  it("every reason says it came from the simulation, so it can never be mistaken for a real signal", () => {
    const { graph } = sim({ nodeId: "db:main", fault: { kind: "outage" } });
    const reasons = graph.nodes.filter((n) => n.state === "failing").flatMap((n) => n.reasons);
    expect(reasons.length).toBeGreaterThan(0);
    expect(reasons.filter((r) => /Error rate/.test(r)).every((r) => /simulation/.test(r))).toBe(true);
  });
  it("slowness is noticed by the latency rule, not the error rule", () => {
    const { graph, changed } = sim({ nodeId: "db:main", fault: { kind: "latency", ms: 900 } });
    const db = graph.nodes.find((n) => n.id === "db:main")!;
    expect(db.state).not.toBe("nominal");
    expect(db.reasons.join(" ")).toMatch(/p95 latency/);
    expect(db.reasons.join(" ")).not.toMatch(/Error rate/);
    expect(changed.some((c) => c.nodeId === "db:main")).toBe(true);
  });
  it("a tiny slowdown is not an incident", () => {
    const { graph } = sim({ nodeId: "db:main", fault: { kind: "latency", ms: 2 } });
    expect(state(graph, "db:main")).toBe("nominal");
  });
  it("an edge into a failing block shows as an error edge, and no other does", () => {
    const { graph } = sim({ nodeId: "db:main", fault: { kind: "outage" } });
    expect(graph.edges.find((e) => e.id === "e2")!.errorRate).toBeGreaterThan(0.05);
    expect(graph.edges.find((e) => e.id === "e5")!.errorRate).toBe(0);
  });
  it("a pipeline: a failing job goes red, on a map whose ids the engine does not special-case too", () => {
    for (const [r, wf, job] of [[shop, WF, JOB_TEST], [demo, "ci", "wf-unit"]] as const) {
      const s = simulateHealth(r.spec, r.graph, r.sc(wf), { baseTs: BASE, fault: { nodeId: job, fault: { kind: "outage" } } });
      expect(state(s.graph, job), job).toBe("failing");
    }
  });
  it("the same inputs give the same answer", () => {
    const f = { nodeId: "db:main", fault: { kind: "outage" as const } };
    expect(sim(f)).toEqual(sim(f));
  });
  it("does not change the map it was given", () => {
    const g = shopGraph(); const before = JSON.stringify(g);
    const r = rig(g); simulateHealth(r.spec, g, r.sc("svc:api"), { baseTs: BASE, fault: { nodeId: "db:main", fault: { kind: "outage" } } });
    expect(JSON.stringify(g)).toBe(before);
  });
});

describe("suggestions for an empty lens", () => {
  it("a service with dependencies, a queue and a pipeline, when the map has them, and each one works", () => {
    expect(suggest(demo.spec, demo.graph)).toEqual(["pay-svc", "ord-q", "ci"]);
    expect(suggest(shop.spec, shop.graph)).toEqual(["svc:api", "q:jobs", WF]);
    for (const id of suggest(demo.spec, demo.graph)) expect(scenarioFor(demo.spec, demo.graph, id).ok).toBe(true);
  });
  it("nothing to suggest on a map with nothing that runs", () => {
    const g = shopGraph(); g.nodes = g.nodes.filter((n) => n.kind === "package"); g.edges = [];
    const r = rig(g);
    expect(suggest(r.spec, r.graph)).toEqual([]);
  });
});
