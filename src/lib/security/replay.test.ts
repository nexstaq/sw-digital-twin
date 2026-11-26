import { describe, expect, it } from "vitest";
import type { Finding, FindingSet, Severity, Simulation } from "./types";
import type { TwinGraph, TwinNode } from "@/lib/graph/types";
import { buildReplaySteps } from "./replay";

const node = (id: string, label: string, paths: string[]): TwinNode => ({
  id, level: 1, parentId: undefined, kind: "service", label, summary: "", state: "nominal", score: 1, spark: [], reasons: [], evidence: paths.map((path) => ({ path })), criticality: 2,
});
const GRAPH: TwinGraph = {
  repo: "a/b", deploys: [],
  nodes: [node("svc:api", "API", ["api/package.json"]), node("db:main", "PostgreSQL", ["api/db.ts"]), node("ext:stripe", "Stripe", ["api/stripe.ts"])],
  edges: [],
};
const sim = (over: Partial<Simulation> = {}): Simulation => ({
  by: "redteam", verdict: "confirmed", confidence: "low", summary: "s", reaches: [], steps: [], source: { read: false }, runId: "r", head: "h", verifiedAt: 0, ...over,
});
const F = (id: string, path: string, severity: Severity, extra: Partial<Finding> = {}): Finding => ({ id, ruleId: "R", category: "code", severity, title: `t-${id}`, path, reason: "r", fix: "f", cwe: [], confidence: "high", detail: {}, ...extra });
type Coverage = NonNullable<NonNullable<FindingSet["simulated"]>["blue"]>["coverage"][number];
const C = (over: Partial<Coverage> = {}): Coverage => ({ kind: "sql-injection", nodeId: "db:main", label: "POST /api/orders", outcome: "missed", suggestion: "add a signal", ...over });

describe("buildReplaySteps: reachability (red-team)", () => {
  it("turns a red-team verdict into a reachability step, entry node first, crown-reached marked distinctly from one that is not", () => {
    const crown = F("f1", "api/package.json", "high", { simulation: sim({ confidence: "medium", reaches: ["PostgreSQL", "Stripe"], summary: "reaches the crown jewel" }) });
    const noCrown = F("f2", "api/package.json", "low", { simulation: sim({ confidence: "low", reaches: ["Stripe"], summary: "no crown jewel" }) });
    const steps = buildReplaySteps(GRAPH, [crown, noCrown]);
    expect(steps).toHaveLength(2);
    expect(steps[0]).toMatchObject({ kind: "reachability", icon: "crown", nodeIds: ["svc:api", "db:main", "ext:stripe"] });
    expect(steps[1]).toMatchObject({ kind: "reachability", icon: "path", nodeIds: ["svc:api", "ext:stripe"] });
  });
  it("ignores findings from the other two agents and plain scanner findings: this is only the reachability story here", () => {
    const whitebox = F("f5", "api/package.json", "high", { simulation: sim({ by: "whitebox" }) });
    const plain = F("f6", "api/package.json", "high");
    expect(buildReplaySteps(GRAPH, [whitebox, plain])).toEqual([]);
  });
  it("never lists the entry node twice, even if its own label is also among the reached ones", () => {
    const f = F("f8", "api/package.json", "high", { simulation: sim({ reaches: ["API", "Stripe"] }) }); // "API" is svc:api's own label
    expect(buildReplaySteps(GRAPH, [f])[0].nodeIds).toEqual(["svc:api", "ext:stripe"]);
  });
  it("a reached label with no matching node is skipped, never a crash", () => {
    const f = F("f7", "api/package.json", "high", { simulation: sim({ reaches: ["Nowhere"] }) });
    expect(buildReplaySteps(GRAPH, [f])[0].nodeIds).toEqual(["svc:api"]);
  });
});

describe("buildReplaySteps: detection coverage (blue), a genuine detection distinct from a miss", () => {
  it("a detected row and a missed row get different icons and different detail text", () => {
    const steps = buildReplaySteps(GRAPH, [], [C({ outcome: "missed", suggestion: "add X" }), C({ outcome: "detected", timeToDetectMs: 10 * 60_000, nodeId: "svc:api" })]);
    expect(steps).toHaveLength(2);
    expect(steps[0]).toMatchObject({ kind: "detection", icon: "missed", nodeIds: ["db:main"] });
    expect(steps[0].title).toMatch(/^Not noticed:/);
    expect(steps[0].detail).toBe("add X");
    expect(steps[1]).toMatchObject({ kind: "detection", icon: "detected", nodeIds: ["svc:api"] });
    expect(steps[1].title).toMatch(/^Noticed:/);
    expect(steps[1].detail).toMatch(/caught this, about 10 minute/);
  });
  it("a not-tried row produces no step: there is nothing to replay for it", () => {
    expect(buildReplaySteps(GRAPH, [], [C({ outcome: "not-tried" })])).toEqual([]);
  });
  it("the general read-amplification check's node (not a repo file) still resolves, since coverage carries the node id directly", () => {
    const steps = buildReplaySteps(GRAPH, [], [C({ kind: "read-amplification", nodeId: "svc:api", label: "GET /api/orders" })]);
    expect(steps[0].nodeIds).toEqual(["svc:api"]);
    expect(steps[0].title).toContain("a flood of reads on");
  });
  it("a coverage row naming a node not on this map highlights nothing rather than guessing", () => {
    expect(buildReplaySteps(GRAPH, [], [C({ nodeId: "nowhere" })])[0].nodeIds).toEqual([]);
  });
});

describe("buildReplaySteps: ordering and purity", () => {
  it("lists reachability steps before detection steps, in the order each list was given, and mutates nothing", () => {
    const findings = [F("a", "api/package.json", "high", { simulation: sim() })];
    const coverage = [C({ nodeId: "db:main" }), C({ nodeId: "svc:api", kind: "no-auth" })];
    const graphJson = JSON.stringify(GRAPH), findingsJson = JSON.stringify(findings), coverageJson = JSON.stringify(coverage);
    const steps = buildReplaySteps(GRAPH, findings, coverage);
    expect(steps.map((s) => s.kind)).toEqual(["reachability", "detection", "detection"]);
    expect(JSON.stringify(GRAPH)).toBe(graphJson);
    expect(JSON.stringify(findings)).toBe(findingsJson);
    expect(JSON.stringify(coverage)).toBe(coverageJson);
  });
  it("with neither findings nor coverage, there is nothing to replay", () => {
    expect(buildReplaySteps(GRAPH, [])).toEqual([]);
  });
});
