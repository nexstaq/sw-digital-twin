import { describe, expect, it } from "vitest";
import { fixtureGraph } from "./fixture";
import { dimmedIds, tileSubtitle } from "./lens";
import { ancestry, culprits } from "./nav";
import { explainVerdict } from "./verdict";
import type { TwinGraph, TwinNode } from "./types";

const top = fixtureGraph.nodes.filter((n) => !n.parentId);
const mk = (o: Partial<TwinNode> & { id: string }): TwinNode => ({
  level: 0, kind: "service", label: o.id, summary: "", state: "nominal", score: 1, spark: [0, 0], reasons: [], evidence: [{ path: "x" }], criticality: 2, ...o,
});

describe("nav", () => {
  it("ancestry is root-first and excludes the node", () => {
    const leaf = fixtureGraph.nodes.find((n) => n.level === 2)!;
    const a = ancestry(fixtureGraph, leaf.id);
    expect(a).toHaveLength(2);
    expect(fixtureGraph.nodes.find((n) => n.id === a[0])!.level).toBe(0);
    expect(ancestry(fixtureGraph, top[0].id)).toEqual([]);
  });
  it("culprits are the deepest unhealthy nodes, failing first", () => {
    const g: TwinGraph = { repo: "x", edges: [], deploys: [], nodes: [
      mk({ id: "a", state: "failing" }), mk({ id: "a1", level: 1, parentId: "a", state: "failing", reasons: ["boom"] }),
      mk({ id: "b", state: "degraded" }), mk({ id: "c" }),
    ] };
    expect(culprits(g).map((n) => n.id)).toEqual(["a1", "b"]);
  });
});

describe("explainVerdict", () => {
  const g = (...n: TwinNode[]): TwinGraph => ({ repo: "x", nodes: n, edges: [], deploys: [] });
  it("says NO DATA when nothing reports, never GO", () => {
    expect(explainVerdict(g(mk({ id: "a", state: "unknown" }))).word).toBe("NO DATA");
  });
  it("NO-GO names the culprit, its reason and a path that reveals it", () => {
    const v = explainVerdict(g(mk({ id: "a", state: "failing" }), mk({ id: "a1", level: 1, parentId: "a", state: "failing", reasons: ["Step \"x\" failed"] })));
    expect(v.word).toBe("NO-GO");
    expect(v.blockers[0]).toMatchObject({ id: "a1", reason: 'Step "x" failed', path: ["a"] });
    expect(v.rule).toMatch(/failing/);
  });
  it("HOLD for degraded, GO otherwise, and is honest about coverage", () => {
    expect(explainVerdict(g(mk({ id: "a", state: "degraded" }))).word).toBe("HOLD");
    const v = explainVerdict(g(mk({ id: "a" }), mk({ id: "b", state: "unknown" })));
    expect(v.word).toBe("GO");
    expect(v.why).toMatch(/1 not monitored/);
    expect(v.coverage).toEqual({ known: 1, total: 2 });
  });
});

describe("lens", () => {
  it("ops dims healthy tiles only when something needs attention", () => {
    const a = mk({ id: "a", state: "failing" }), b = mk({ id: "b" });
    expect([...dimmedIds([a, b], "ops")]).toEqual(["b"]);
    expect(dimmedIds([b], "ops").size).toBe(0);
  });
  it("flow and risk keep their own kinds bright", () => {
    const job = mk({ id: "j", kind: "job" }), ext = mk({ id: "e", kind: "external" });
    expect([...dimmedIds([job, ext], "flow")]).toEqual(["e"]);
    expect([...dimmedIds([job, ext], "risk")]).toEqual(["j"]);
    expect(dimmedIds([job, ext], "overview").size).toBe(0);
  });
  it("subtitles speak the lens's language", () => {
    const n = mk({ id: "a", reasons: ["Latest run failed"], narrative: { name: "A", purpose: "", exec: "Takes payments.", engineer: "", security: "Holds card tokens.", confidence: "high", citations: [] } });
    expect(tileSubtitle(n, "overview")).toBe("Takes payments.");
    expect(tileSubtitle(n, "ops")).toBe("Latest run failed");
    expect(tileSubtitle(n, "risk")).toBe("Holds card tokens.");
    expect(tileSubtitle(n, "flow")).toBeUndefined();
  });
});
