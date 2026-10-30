import { describe, expect, it } from "vitest";
import { fixtureGraph, childrenOf } from "./fixture";
import { validateGraph } from "./integrity";
import { SnapshotSchema } from "./schemas";

describe("fixture", () => {
  it("is structurally sound", () => expect(validateGraph(fixtureGraph)).toEqual([]));

  it("has ~40 nodes over 3 levels", () => {
    expect(fixtureGraph.nodes.length).toBeGreaterThanOrEqual(38);
    expect(new Set(fixtureGraph.nodes.map((n) => n.level))).toEqual(new Set([0, 1, 2]));
    expect(childrenOf(fixtureGraph, null)).toHaveLength(8);
  });

  it("round-trips through the Snapshot schema", () => {
    const snap = { schemaVersion: 1, repoId: "acme/shop", commitSha: "abc123", createdAt: 0, graph: fixtureGraph };
    expect(SnapshotSchema.parse(snap).graph.nodes).toHaveLength(fixtureGraph.nodes.length);
  });
});

describe("validateGraph", () => {
  const base = fixtureGraph;
  it("flags dangling edges", () => {
    const bad = { ...base, edges: [...base.edges, { id: "x", from: "ci", to: "nope", kind: "calls", throughput: 0, errorRate: 0 }] };
    expect(validateGraph(bad).join()).toMatch(/dangling/);
  });
  it("flags nodes without evidence", () => {
    const bad = { ...base, nodes: base.nodes.map((n, i) => (i === 0 ? { ...n, evidence: [] } : n)) };
    expect(validateGraph(bad).join()).toMatch(/no evidence/);
  });
  it("flags wrong parent level", () => {
    const bad = { ...base, nodes: base.nodes.map((n) => (n.id === "f-charge" ? { ...n, parentId: "pay" } : n)) };
    expect(validateGraph(bad).join()).toMatch(/parent is level/);
  });
  it("flags edges across different parents", () => {
    const bad = { ...base, edges: [...base.edges, { id: "x", from: "ci", to: "wf-lint", kind: "calls", throughput: 0, errorRate: 0 }] };
    expect(validateGraph(bad).join()).toMatch(/different parents/);
  });
});
