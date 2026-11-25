import { describe, expect, it } from "vitest";
import { buildRange } from "../range/generate";
import { startRange } from "../range/runtime";
import { fixtureWorld, SHA } from "./world";

describe("what the real scanner and map builder make of the fixture", () => {
  it("the scanner reports the seeded weaknesses: SQL injection, path traversal, an open write route, and one that merely looks like SQL injection", async () => {
    const { set } = await fixtureWorld();
    const code = set.findings.filter((x) => x.ruleId.startsWith("CODE/")).map((x) => `${x.ruleId} ${x.path} ${x.severity}/${x.confidence}`).sort();
    expect(code).toEqual([
      "CODE/no-auth-seen app/api/admin/reset/route.ts low/low",
      "CODE/no-auth-seen app/api/orders/route.ts low/low",
      "CODE/path-traversal app/api/files/route.ts high/medium",
      "CODE/sql-injection app/api/invoices/route.ts medium/low",
      "CODE/sql-injection app/api/orders/route.ts high/medium",
    ]);
  });

  it("the map has one top-level service that holds the five routes, and groups for the data stores and outside services", async () => {
    const { graph } = await fixtureWorld();
    expect(graph.nodes.filter((n) => n.kind === "endpoint").map((n) => n.label).sort()).toEqual(["GET /api/files", "GET /api/invoices", "GET /api/orders/[id]", "POST /api/admin/reset", "POST /api/orders"]);
    expect(graph.edges.some((e) => e.from === "pkg:." && e.to === "cl:data")).toBe(true);
  });
});

describe("the range built from a real scan of a small repository", () => {
  it("emulates the service that holds the routes, and the data store and outside service behind its groups", async () => {
    const { graph, set } = await fixtureWorld();
    const spec = buildRange({ sha: SHA, graph }, set);
    const ids = spec.emulators.map((e) => e.nodeId);
    expect(ids).toEqual(expect.arrayContaining(["pkg:.", "ds:postgresql", "ext:stripe"]));
    expect(ids).not.toContain("cl:data"); // the group itself is not emulated
    expect(spec.endpoints.map((e) => `${e.method} ${e.path} ${e.ownerId}`).sort()).toEqual(["GET /api/files pkg:.", "GET /api/invoices pkg:.", "GET /api/orders/[id] pkg:.", "POST /api/admin/reset pkg:.", "POST /api/orders pkg:."]);
    // "reads the data stores" became "reads the Postgres data store", and likewise for the outside service
    expect(spec.edges.filter((e) => e.from === "pkg:.").map((e) => `${e.kind} ${e.to}`).sort()).toEqual(expect.arrayContaining(["calls ext:stripe", "reads ds:postgresql"]));
  });

  it("every code weakness the scanner found is reachable in it, and the open write route is open", async () => {
    const { graph, set } = await fixtureWorld();
    const spec = buildRange({ sha: SHA, graph }, set);
    const by = (rule: string, file: string) => spec.weaknesses.find((w) => w.ruleId === rule && set.findings.find((f) => f.id === w.findingId)!.path === file)!;
    expect(by("CODE/sql-injection", "app/api/orders/route.ts")).toMatchObject({ kind: "sql-injection", reachable: true });
    expect(by("CODE/path-traversal", "app/api/files/route.ts")).toMatchObject({ kind: "path-traversal", reachable: true });
    expect(by("CODE/sql-injection", "app/api/invoices/route.ts")).toMatchObject({ kind: "sql-injection", reachable: true });
    expect(by("CODE/no-auth-seen", "app/api/orders/route.ts")).toMatchObject({ kind: "no-auth", reachable: true });
    expect(spec.endpoints.find((e) => e.path === "/api/orders")).toMatchObject({ auth: "none", authSource: "finding" });
  });

  it("exploiting the SQL injection now reaches the database and the outside service, and proves impact with the crown marker", async () => {
    const { graph, set } = await fixtureWorld();
    const spec = buildRange({ sha: SHA, graph }, set);
    const r = startRange(spec);
    const res = r.handle({ method: "POST", path: "/api/orders", role: "anonymous", payload: { class: "sqli" } });
    expect(res.status).toBe(200);
    expect(res.proof).toMatch(/^SIM-PROOF-/);
    expect(res.reached).toEqual(expect.arrayContaining(["ds:postgresql", "ext:stripe"]));
    expect(res.crown).toEqual([spec.datastores.find((d) => d.nodeId === "ds:postgresql")!.crown]);
  });
});
