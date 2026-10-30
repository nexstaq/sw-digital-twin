import { describe, expect, it } from "vitest";
import { blastRadius } from "./blast";
import { fixtureGraph, childrenOf } from "./fixture";

const l0 = new Set(childrenOf(fixtureGraph, null).map((n) => n.id));
const l0Edges = fixtureGraph.edges.filter((e) => l0.has(e.from) && l0.has(e.to));

describe("blastRadius", () => {
  it("callers are impacted when a dependency fails", () => {
    const { nodes } = blastRadius(l0Edges, "pay");
    expect(nodes).toEqual(new Set(["api", "web"]));
  });
  it("follows reads transitively up through callers", () => {
    const { nodes } = blastRadius(l0Edges, "data");
    expect(nodes).toEqual(new Set(["pay", "orders", "api", "web"]));
  });
  it("downstream is impacted transitively when a trigger source fails (nothing can ship)", () => {
    const { nodes } = blastRadius(l0Edges, "ci");
    expect(nodes).toEqual(new Set(["release", "web", "api", "pay"]));
  });
  it("never includes the failing node and terminates on cycles", () => {
    const edges = [
      { id: "a", from: "x", to: "y", kind: "calls" as const, throughput: 0, errorRate: 0 },
      { id: "b", from: "y", to: "x", kind: "calls" as const, throughput: 0, errorRate: 0 },
    ];
    const r = blastRadius(edges, "x");
    expect(r.nodes).toEqual(new Set(["y"]));
    expect(r.edges).toEqual(new Set(["a", "b"]));
  });
  it("returns nothing for a leaf nobody depends on", () => expect(blastRadius(l0Edges, "web").nodes.size).toBe(0));
});
