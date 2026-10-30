import { describe, expect, it } from "vitest";
import { mapFindings } from "./map";
import { attackPaths, pathHighlight } from "./paths";
import type { Finding, Severity } from "./types";
import type { TwinEdge, TwinGraph, TwinNode } from "@/lib/graph/types";

const node = (id: string, kind: TwinNode["kind"], level: 0 | 1 | 2, parentId: string | undefined, paths: string[] = []): TwinNode => ({
  id, level, parentId, kind, label: id, summary: "", state: "nominal", score: 1, spark: [], reasons: [], evidence: paths.map((path) => ({ path })), criticality: 2,
});
const edge = (from: string, to: string, kind: TwinEdge["kind"]): TwinEdge => ({ id: `${from}-${to}-${kind}`, from, to, kind, throughput: 0.5, errorRate: 0 });
const F = (id: string, path: string, severity: Severity, extra: Partial<Finding> = {}): Finding => ({ id, ruleId: "R", category: "code", severity, title: `t-${id}`, path, reason: "r", fix: "f", cwe: [], confidence: "high", detail: {}, ...extra });
const paths = (g: TwinGraph, fs: Finding[], exposure?: Parameters<typeof attackPaths>[3]) => attackPaths(g, fs, mapFindings(g, fs), exposure);

// web (service, 2 endpoints) --reads--> data (block with a datastore in it); an unrelated lib; a CI block
const G: TwinGraph = {
  repo: "a/b", deploys: [],
  nodes: [
    node("web", "service", 0, undefined, ["apps/web/package.json"]),
    node("ep1", "endpoint", 1, "web", ["apps/web/app/api/users/route.ts"]), node("ep2", "endpoint", 1, "web", ["apps/web/app/api/orders/route.ts"]),
    node("data", "datastore", 0, undefined, []), node("db", "datastore", 1, "data", ["packages/db/index.ts"]),
    node("ext", "external", 0, undefined, []),
    node("lib", "package", 0, undefined, ["packages/lib/package.json"]),
    node("ci", "job", 0, undefined, []), node("wf", "job", 1, "ci", [".github/workflows/pr.yml"]),
    node("prod", "env", 0, undefined, []),
  ],
  edges: [edge("web", "data", "reads"), edge("web", "lib", "depends_on"), edge("ci", "prod", "deploys_to"), edge("wf", "prod", "deploys_to")],
};

describe("attackPaths: web", () => {
  it("finds the path from an exposed service to the datastore it reads, and counts what is wrong on it", () => {
    const [p] = paths(G, [F("sqli", "apps/web/app/api/users/route.ts", "high", { title: "SQL built from request data" })]);
    expect(p).toMatchObject({ kind: "web", entry: "web", target: "data", nodes: ["web", "data"], endpoints: 2, worst: "high" });
    expect(p.findings).toEqual(["sqli"]);
    expect(p.facts[0]).toBe("2 public endpoints in web");
    expect(p.facts[1]).toBe("Reaches data (reads)");
    expect(p.facts[2]).toBe("1 finding along the way, worst: high (SQL built from request data)");
  });
  it("a finding inside the asset itself counts too", () => {
    const [p] = paths(G, [F("dbf", "packages/db/index.ts", "critical")]);
    expect(p.worst).toBe("critical");
  });
  it("an exposed route to an asset with NOTHING wrong on it is not a finding", () => {
    expect(paths(G, [])).toEqual([]);
    expect(paths(G, [F("elsewhere", "packages/lib/other.ts", "high")]).filter((p) => p.kind === "web")).toHaveLength(1); // the lib is depended on by web: it IS exposure
    expect(paths(G, [F("unrelated", "scripts/x.ts", "high")])).toEqual([]); // maps to nothing on the path
  });
  it("unauthenticated writes make a path even with no finding, and raise its risk", () => {
    const exposure = { endpointFiles: 2, unauthenticatedWrites: ["apps/web/app/api/orders/route.ts"], middlewareAuth: false };
    const [p] = paths(G, [], exposure);
    expect(p).toMatchObject({ unauthenticated: 1, endpoints: 2 });
    expect(p.facts[0]).toContain("1 of which accepts writes with no authentication check");
    const base = paths(G, [F("x", "apps/web/app/api/users/route.ts", "high")])[0].risk;
    expect(paths(G, [F("x", "apps/web/app/api/users/route.ts", "high")], exposure)[0].risk).toBeGreaterThan(base);
  });
  it("depends_on contributes risk (supply chain) but is never a route an attacker walks", () => {
    const g: TwinGraph = { ...G, edges: [edge("web", "lib", "depends_on")] }; // no flow edge to any asset
    expect(paths(g, [F("dep", "packages/lib/package.json", "critical", { category: "dependency" })])).toEqual([]);
    const [p] = paths(G, [F("dep", "packages/lib/package.json", "critical", { category: "dependency" })]);
    expect(p.findings).toContain("dep");
    expect(p.nodes).toEqual(["web", "data"]); // the lib is not on the walked path
  });
  it("where something is HOSTED is not a route an attacker walks: a public endpoint does not reach its environment", () => {
    const g: TwinGraph = { ...G, edges: [edge("web", "prod", "deploys_to")] };
    expect(paths(g, [F("f", "apps/web/app/api/users/route.ts", "critical")])).toEqual([]);
  });
  it("no edge means no path, never a claim of safety", () => {
    expect(paths({ ...G, edges: [] }, [F("sqli", "apps/web/app/api/users/route.ts", "critical")])).toEqual([]);
  });
  it("a chain longer than the depth limit is not followed", () => {
    const chain: TwinGraph = { repo: "a/b", deploys: [], nodes: [node("e", "endpoint", 1, "s", ["e.ts"]), node("s", "service", 0, undefined, ["package.json"]), node("a", "service", 0, undefined), node("b", "service", 0, undefined), node("c", "service", 0, undefined), node("d", "service", 0, undefined), node("t", "datastore", 0, undefined)],
      edges: [edge("s", "a", "calls"), edge("a", "b", "calls"), edge("b", "c", "calls"), edge("c", "d", "calls"), edge("d", "t", "calls")] };
    expect(paths(chain, [F("f", "e.ts", "high")])).toEqual([]);
    expect(paths({ ...chain, edges: [edge("s", "a", "calls"), edge("a", "b", "calls"), edge("b", "t", "calls")] }, [F("f", "e.ts", "high")])[0].nodes).toEqual(["s", "a", "b", "t"]);
  });
  it("cycles terminate, and the shortest route to each asset is the one reported", () => {
    const g: TwinGraph = { ...G, edges: [edge("web", "data", "reads"), edge("data", "web", "calls"), edge("web", "ext", "calls")] };
    const found = paths(g, [F("f", "apps/web/app/api/users/route.ts", "high")]);
    expect(found.map((p) => p.target).sort()).toEqual(["data", "ext"]);
  });
  it("orders the worst paths first", () => {
    const g: TwinGraph = { ...G, edges: [edge("web", "data", "reads"), edge("web", "ext", "calls")] };
    const fs = [F("a", "apps/web/app/api/users/route.ts", "high"), F("b", "packages/db/index.ts", "critical")];
    const found = paths(g, fs);
    expect(found[0].risk).toBeGreaterThanOrEqual(found[1].risk);
    expect(found[0].target).toBe("data"); // the critical finding lives in the datastore
  });
});

describe("attackPaths: pipelines", () => {
  const pr = F("pwn", ".github/workflows/pr.yml", "critical", { ruleId: "GHA/pwn-request", category: "pipeline", title: "pull_request_target checks out untrusted code" });
  it("a pipeline an outsider can trigger leads to the environment it deploys to", () => {
    const found = paths(G, [pr]).filter((p) => p.kind === "pipeline");
    expect(found.length).toBeGreaterThan(0);
    expect(found[0]).toMatchObject({ entry: "wf", target: "prod", worst: "critical" });
    expect(found[0].facts[0]).toContain("can be triggered from outside");
  });
  it("an ordinary pipeline finding (unpinned action) does not create an attack path", () => {
    expect(paths(G, [F("u", ".github/workflows/pr.yml", "medium", { ruleId: "GHA/unpinned-action", category: "pipeline" })])).toEqual([]);
  });
});

describe("pathHighlight", () => {
  it("lights the foothold as the origin and the rest as what it reaches", () => {
    const [p] = paths(G, [F("sqli", "apps/web/app/api/users/route.ts", "high")]);
    const h = pathHighlight(p, G);
    expect(h).toMatchObject({ mode: "impact", focusId: "web", ids: ["data"], path: [] });
    expect(h.title).toBe("Attack path: web → data");
    expect(h.detail).toContain("Reaches data");
  });
});
