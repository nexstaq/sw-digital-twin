import { describe, expect, it } from "vitest";
import { applyHealth } from "@/lib/health/engine";
import { buildRange } from "./generate";
import { rangeSignals } from "./health";
import { startRange } from "./runtime";
import { JOB_DEPLOY, JOB_TEST, shopFindings, shopGraph, WF } from "./fixtures";
import type { WorkflowResult } from "./types";

const BASE = Date.UTC(2026, 10, 25, 12, 0, 0);
const spec = buildRange({ sha: "b".repeat(40), graph: shopGraph() }, shopFindings());
const state = (g: ReturnType<typeof shopGraph>, id: string) => g.nodes.find((n) => n.id === id)!;
const FIVE = 5 * 60_000;

/** `rounds` windows of 20 requests each, then the clock moves on 5 minutes */
function traffic(r: ReturnType<typeof startRange>, rounds: number) {
  for (let i = 0; i < rounds; i++) {
    for (let k = 0; k < 20; k++) r.handle({ method: "GET", path: "/api/orders", role: "user" });
    r.advance(FIVE);
  }
}

describe("the range lights up the real health engine", () => {
  it("steady healthy traffic makes the parts it touched nominal, and leaves the rest unknown", () => {
    const r = startRange(spec);
    traffic(r, 4);
    const now = BASE + r.now();
    const g = applyHealth(shopGraph(), rangeSignals(spec, { events: r.events(), workflows: [] }, { baseTs: BASE, now }), now);
    for (const id of ["svc:api", "svc:payments", "db:main", "ext:stripe", "q:jobs"]) expect(state(g, id).state, id).toBe("nominal");
    expect(state(g, JOB_TEST).state).toBe("unknown");
  });

  it("a database outage turns the database and everything that depends on it red, and not what does not", () => {
    const r = startRange(spec);
    traffic(r, 3);
    r.inject("db:main", { kind: "outage" });
    traffic(r, 3);
    const now = BASE + r.now();
    const g = applyHealth(shopGraph(), rangeSignals(spec, { events: r.events(), workflows: [] }, { baseTs: BASE, now }), now);
    expect(state(g, "db:main").state).toBe("failing");
    expect(state(g, "svc:api").state).toBe("failing");
    expect(state(g, "svc:api").reasons.join(" ")).toMatch(/Error rate/);
    // the payment path is only visited before the database fails in this flow order, so it is not blamed
    expect(["nominal", "degraded", "unknown"]).toContain(state(g, "ext:stripe").state);
    expect(state(g, "blk:backend").state).toBe("failing"); // rolls up
  });

  it("recovery after the outage clears the red", () => {
    const r = startRange(spec);
    traffic(r, 2);
    r.inject("db:main", { kind: "outage" });
    traffic(r, 2);
    r.clearFault("db:main");
    traffic(r, 4);
    const now = BASE + r.now();
    const g = applyHealth(shopGraph(), rangeSignals(spec, { events: r.events(), workflows: [] }, { baseTs: BASE, now }), now);
    expect(state(g, "svc:api").state).not.toBe("failing");
  });

  it("a failed CI job names the step, and the deploy job is not blamed", () => {
    const r = startRange(spec);
    const ok = r.runWorkflow(WF, { sha: "e".repeat(40) });
    r.advance(FIVE);
    const bad = r.runWorkflow(WF, { sha: "f".repeat(40), failJob: JOB_TEST });
    const now = BASE + r.now();
    const g = applyHealth(shopGraph(), rangeSignals(spec, { events: r.events(), workflows: [ok, bad] }, { baseTs: BASE, now }), now);
    expect(state(g, JOB_TEST).state).toBe("failing");
    expect(state(g, JOB_TEST).reasons.join(" ")).toContain("(simulated failure)");
    expect(state(g, JOB_DEPLOY).state).not.toBe("failing");
  });

  it("a successful pipeline turns the environment green", () => {
    const r = startRange(spec);
    const w = r.runWorkflow(WF, { sha: "e".repeat(40) });
    const now = BASE + r.now() + 1000;
    const g = applyHealth(shopGraph(), rangeSignals(spec, { events: r.events(), workflows: [w] }, { baseTs: BASE, now }), now);
    expect(state(g, "env:production").state).toBe("nominal");
    expect(state(g, JOB_TEST).state).toBe("nominal");
  });

  it("a failed deploy turns the environment red", () => {
    const r = startRange(spec);
    const w = r.runWorkflow(WF, { failJob: JOB_DEPLOY });
    const now = BASE + r.now() + 1000;
    const g = applyHealth(shopGraph(), rangeSignals(spec, { events: r.events(), workflows: [w] }, { baseTs: BASE, now }), now);
    expect(state(g, "env:production").state).toBe("failing");
  });
});

describe("the signals themselves", () => {
  it("buckets are five minutes wide, mapped to the node they describe, and carry rates not counts", () => {
    const r = startRange(spec);
    traffic(r, 1);
    const s = rangeSignals(spec, { events: r.events(), workflows: [] }, { baseTs: BASE, now: BASE + r.now() });
    const api = s.runtime!.filter((b) => b.key === "svc:api");
    expect(api).toHaveLength(1);
    expect(api[0]).toMatchObject({ source: "range", requests: 4, errors: 0 });
    expect(api[0].ts % FIVE).toBe(0);
    expect(s.mappings!["range:svc:api"]).toBe("svc:api");
  });
  it("workflow results become runs and deploys with real timestamps", () => {
    const r = startRange(spec);
    const w: WorkflowResult = r.runWorkflow(WF);
    const s = rangeSignals(spec, { events: [], workflows: [w] }, { baseTs: BASE, now: BASE + 1 });
    expect(s.runs[0]).toMatchObject({ workflowPath: ".github/workflows/ci.yml", conclusion: "success", branch: "main" });
    expect(s.runs[0].jobs!.map((j) => j.name)).toEqual(["test", "deploy"]);
    expect(s.deploys[0]).toMatchObject({ environment: "production", state: "success" });
    expect(Date.parse(s.runs[0].createdAt)).toBeGreaterThanOrEqual(BASE);
  });
  it("no events and no runs is an empty, valid signal set (the nodes stay unknown)", () => {
    const s = rangeSignals(spec, { events: [], workflows: [] }, { baseTs: BASE, now: BASE });
    expect(s).toMatchObject({ runs: [], deploys: [], runtime: [], mappings: {} });
    const g = applyHealth(shopGraph(), s, BASE);
    expect(state(g, "svc:api").state).toBe("unknown");
  });
});
