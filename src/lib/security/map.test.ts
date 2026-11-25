import { describe, expect, it } from "vitest";
import { byPriority, findingsUnder, mapFindings, nodeFor, posture, priority, rollup, securityGraph } from "./map";
import type { Finding, Severity } from "./types";
import type { TwinGraph, TwinNode } from "@/lib/graph/types";

const node = (id: string, level: 0 | 1 | 2, parentId: string | undefined, paths: string[], state: TwinNode["state"] = "nominal"): TwinNode => ({
  id, level, parentId, kind: "service", label: id, summary: "", state, score: 1, spark: [], reasons: [], evidence: paths.map((path) => ({ path })), criticality: 2,
  links: [{ label: "run", url: "https://x" }], live: true,
});
const GRAPH: TwinGraph = {
  repo: "a/b", deploys: [], activity: { running: 1, queued: 0 },
  nodes: [
    node("ci", 0, undefined, []), node("wf", 1, "ci", [".github/workflows/ci.yml"]), node("job", 2, "wf", [".github/workflows/ci.yml"]),
    node("web", 0, undefined, ["apps/web/package.json"]), node("api", 0, undefined, ["apps/api/package.json"]), node("infra", 0, undefined, ["Dockerfile"]),
  ],
  edges: [],
};
const F = (id: string, path: string, severity: Severity, extra: Partial<Finding> = {}): Finding => ({ id, ruleId: "R", category: "dependency", severity, title: `t-${id}`, path, reason: "r", fix: "f", cwe: [], confidence: "high", detail: {}, ...extra });

describe("nodeFor", () => {
  it("prefers the deepest node that cites the exact file", () => { expect(nodeFor(GRAPH, { path: ".github/workflows/ci.yml" })).toBe("job"); });
  it("falls back to the manifest that owns the enclosing folder, nearest first", () => {
    expect(nodeFor(GRAPH, { path: "apps/web/src/deep/page.tsx" })).toBe("web");
    expect(nodeFor(GRAPH, { path: "apps/api/package-lock.json" })).toBe("api");
  });
  it("has a sensible answer for root files and none when nothing encloses", () => {
    expect(nodeFor(GRAPH, { path: "Dockerfile" })).toBe("infra");
    expect(nodeFor({ ...GRAPH, nodes: GRAPH.nodes.filter((n) => n.id === "web") }, { path: "libs/x/y.ts" })).toBeNull();
  });
});

describe("nodeFor: who owns a file", () => {
  // acme-shop owns the repo; the database and Stripe merely CITE package.json / src/server.ts as proof they are used
  const g: TwinGraph = { repo: "a/b", deploys: [], edges: [], nodes: [
    node("shop", 0, undefined, ["package.json"]),
    { ...node("db", 1, "data", ["package.json", "src/server.ts"]), kind: "datastore" },
    { ...node("stripe", 1, "ext", ["package.json"]), kind: "external" },
  ] };
  it("a vulnerable dependency belongs to the package that declares it, not to the datastore that also cites the manifest", () => {
    expect(nodeFor(g, { path: "package.json" })).toBe("shop");
    expect(nodeFor(g, { path: "package-lock.json" })).toBe("shop");
  });
  it("a code file belongs to the package that contains it, not to the datastore whose evidence sits in the same folder", () => {
    expect(nodeFor(g, { path: "src/config.ts" })).toBe("shop");
  });
  it("a monorepo file goes to its own package", () => {
    const m: TwinGraph = { ...g, nodes: [node("root", 0, undefined, ["package.json"]), node("web", 1, "root", ["apps/web/package.json"]), node("api", 1, "root", ["apps/api/package.json"])] };
    expect(nodeFor(m, { path: "apps/web/src/a.ts" })).toBe("web");
    expect(nodeFor(m, { path: "apps/api/package-lock.json" })).toBe("api");
    expect(nodeFor(m, { path: "scripts/x.ts" })).toBe("root");
  });
});

describe("nodeFor: findings that are not files in the repository", () => {
  it("a live-test URL or an unknown location never maps to a node", () => {
    expect(nodeFor(GRAPH, { path: "https://staging.example.com/api/users" })).toBeNull();
    expect(nodeFor(GRAPH, { path: "(location not provided by GitHub)" })).toBeNull();
  });
});

describe("rollup", () => {
  it("counts a finding on the node and on every ancestor, so a block glows for what is inside it", () => {
    const fs = [F("1", ".github/workflows/ci.yml", "high"), F("2", "apps/web/a.ts", "low")];
    const r = rollup(GRAPH, fs, mapFindings(GRAPH, fs));
    expect(r.get("job")).toMatchObject({ worst: "high", total: 1 });
    expect(r.get("wf")?.worst).toBe("high");
    expect(r.get("ci")?.counts.high).toBe(1);
    expect(r.get("web")).toMatchObject({ worst: "low", total: 1 });
    expect(r.has("api")).toBe(false);
  });
  it("takes the worst severity when several are present", () => {
    const fs = [F("1", "apps/web/a", "low"), F("2", "apps/web/b", "critical"), F("3", "apps/web/c", "medium")];
    expect(rollup(GRAPH, fs, mapFindings(GRAPH, fs)).get("web")).toMatchObject({ worst: "critical", total: 3 });
  });
});

describe("securityGraph", () => {
  const fs = [F("1", ".github/workflows/ci.yml", "critical", { title: "Pwn request" }), F("2", "apps/web/x", "medium")];
  it("recolours by security: critical/high fail, medium degrades, clean is nominal", () => {
    const g = securityGraph(GRAPH, fs, true);
    const st = Object.fromEntries(g.nodes.map((n) => [n.id, n.state]));
    expect(st).toMatchObject({ job: "failing", wf: "failing", ci: "failing", web: "degraded", api: "nominal", infra: "nominal" });
    expect(g.nodes.find((n) => n.id === "job")!.reasons[0]).toBe("Pwn request");
    expect(g.nodes.find((n) => n.id === "ci")!.reasons[0]).toBe("Pwn request"); // the block leads with the worst thing inside it
    expect(g.nodes.find((n) => n.id === "api")!.reasons).toEqual(["No findings in this part"]);
  });
  it("before a scan nothing is called safe: everything is unknown", () => {
    const g = securityGraph(GRAPH, [], false);
    expect(g.nodes.every((n) => n.state === "unknown")).toBe(true);
  });
  it("drops health-only decorations and does not mutate its input", () => {
    const g = securityGraph(GRAPH, fs, true);
    expect(g.nodes.every((n) => !n.links && !n.live)).toBe(true);
    expect(g.activity).toBeUndefined();
    expect(GRAPH.nodes[0].links).toBeDefined();
    expect(GRAPH.nodes.find((n) => n.id === "job")!.state).toBe("nominal");
  });
});

describe("priority and posture", () => {
  it("scales down dev-only, low-confidence and never-imported transitive findings, and up for imported ones", () => {
    const base = F("a", "p", "high");
    expect(priority({ ...base, detail: { dev: true } })).toBeLessThan(priority(base));
    expect(priority({ ...base, confidence: "low" })).toBeLessThan(priority(base));
    expect(priority({ ...base, detail: { direct: false, usedIn: [] } })).toBeLessThan(priority(base));
    expect(priority({ ...base, detail: { direct: true, usedIn: ["a.ts"] } })).toBeGreaterThan(priority(base));
  });
  it("orders by priority, then path, so the list is stable", () => {
    const a = F("1", "b", "high"), b = F("2", "a", "high"), c = F("3", "z", "critical");
    expect([a, b, c].sort(byPriority).map((f) => f.id)).toEqual(["3", "2", "1"]);
  });
  it("grades honestly: clean is A, and one critical can never grade above D", () => {
    expect(posture([]).grade).toBe("A");
    expect(posture([], true).headline).toMatch(/not that the software is proven secure/);
    expect(posture([], false).headline).toBe("Not scanned yet");
    const crit = posture([F("1", "p", "critical")]);
    expect(crit.score).toBe(75);
    expect(crit.grade).toBe("D");
    expect(posture([F("1", "p", "critical"), F("2", "p", "critical"), F("3", "p", "critical"), F("4", "p", "critical")]).grade).toBe("F");
    expect(posture([F("1", "p", "low"), F("2", "p", "low")]).grade).toBe("A");
    expect(posture([F("1", "p", "high"), F("2", "p", "high")]).headline).toBe("2 high-severity issues to fix");
  });
  it("counts by severity and category", () => {
    const p = posture([F("1", "p", "high"), F("2", "p", "low", { category: "secret" })]);
    expect(p.counts).toMatchObject({ high: 1, low: 1 });
    expect(p.byCategory).toMatchObject({ dependency: 1, secret: 1 });
  });
});

describe("findingsUnder", () => {
  it("lists a node's own findings and everything nested in it, worst first", () => {
    const fs = [F("lo", "apps/web/a", "low"), F("hi", ".github/workflows/ci.yml", "high"), F("md", ".github/workflows/ci.yml", "medium")];
    const home = mapFindings(GRAPH, fs);
    expect(findingsUnder(GRAPH, fs, home, "ci").map((f) => f.id)).toEqual(["hi", "md"]); // the block holds the workflow's findings
    expect(findingsUnder(GRAPH, fs, home, "job").map((f) => f.id)).toEqual(["hi", "md"]);
    expect(findingsUnder(GRAPH, fs, home, "web").map((f) => f.id)).toEqual(["lo"]);
    expect(findingsUnder(GRAPH, fs, home, "api")).toEqual([]);
  });
});

describe("what the simulation changes, and what it must not", () => {
  const sim = (verdict: "confirmed" | "mitigated" | "unreachable" | "not-reproduced") => ({ verdict, confidence: "medium" as const, summary: "s", reaches: [], steps: [1], source: { read: false }, runId: "r", head: "h", verifiedAt: 1 });
  const twin = (verdict?: Parameters<typeof sim>[0]) => F("x", "a.ts", "medium", { confidence: "medium", ...(verdict ? { simulation: sim(verdict) } : {}) });

  it("a confirmed finding outranks an otherwise identical one, and a likely false alarm or unreachable one ranks below it", () => {
    const base = F("p", "m.ts", "medium", { confidence: "medium" });
    const confirmed = { ...twin("confirmed"), id: "c", path: "z.ts" }, mitigated = { ...twin("mitigated"), id: "m", path: "a.ts" }, unreachable = { ...twin("unreachable"), id: "u", path: "b.ts" };
    // with no verdicts the tie is broken by path, so a.ts comes first; the verdicts must be what changes the order
    expect([{ ...base, path: "z.ts" }, { ...base, path: "a.ts" }].sort(byPriority).map((f) => f.path)).toEqual(["a.ts", "z.ts"]);
    expect([confirmed, mitigated, unreachable].sort(byPriority).map((f) => f.id)).toEqual(["c", "m", "u"]);
    expect(byPriority(confirmed, mitigated)).toBeLessThan(0);
    expect(byPriority(mitigated, { ...base, path: "a.ts" })).toBeGreaterThan(0);
  });
  it("a verdict that is neither (not reproduced) leaves the order alone", () => {
    const a = { ...twin("not-reproduced"), id: "a", path: "a.ts" }, b = { ...twin(), id: "b", path: "b.ts" };
    expect(byPriority(a, b)).toBeLessThan(0); // path order, as with no verdict at all
  });
  it("never moves the safety score or the grade: priority() ignores the verdict, and so does posture()", () => {
    const plain = [twin(), { ...twin(), id: "y", severity: "high" as const }];
    const judged = [twin("mitigated"), { ...twin("confirmed"), id: "y", severity: "high" as const }];
    expect(priority(judged[0])).toBe(priority(plain[0]));
    expect(posture(judged)).toEqual(posture(plain));
  });
  it("never changes a severity", () => { expect(twin("mitigated").severity).toBe("medium"); });
});
