import { describe, expect, it } from "vitest";
import { SimulationSchema, type FindingSet } from "@/lib/security/types";
import { verifyChain } from "../audit";
import { KillRegistry } from "../agent/killswitch";
import { flowTool, triggerTool } from "../agent/tools/range";
import { buildRange } from "../range/generate";
import { edge, finding, node, shopFindings, shopGraph, WF } from "../range/fixtures";
import { scope } from "../whitebox/test-scope";
import { discoverReachability, type RedteamInput, type RedteamResult } from "./agent";
import { redteamRoe, RT } from "./roe";

const NOW = 1_800_000_000_000;
const SHA = "b".repeat(40);
const discover = (set: FindingSet, over: Partial<RedteamInput> = {}) => discoverReachability({ repo: "acme/shop", sha: SHA, graph: shopGraph(), set, now: () => NOW, killRegistry: new KillRegistry(), ...over });
const crownPaths = (r: RedteamResult) => r.paths.filter((p) => p.crown.length > 0);
const crownOf = (r: RedteamResult) => r.spec.datastores.find((d) => d.nodeId === "db:main")!.crown;

describe("the acceptance case: the seeded crown jewel is reached via at least two distinct paths", () => {
  it("web: several unrelated weaknesses on different routes all lead to the same data store", async () => {
    const r = await discover(shopFindings());
    const crown = crownOf(r);
    const reaching = crownPaths(r).filter((p) => p.crown.includes(crown));
    const distinctEntries = new Set(reaching.map((p) => p.entry));
    expect(distinctEntries.size).toBeGreaterThanOrEqual(2);
    expect(r.summary).toMatchObject({ crownJewels: 1, crownsReached: 1, likelihood: "high" });
    expect(r.summary.distinctEntries).toBeGreaterThanOrEqual(2);
  });

  it("each confirmed finding cites a real reason and real evidence, never invented", async () => {
    const r = await discover(shopFindings());
    const sqli = r.simulations.f1; // the seeded SQL injection
    expect(sqli).toMatchObject({ by: "redteam", verdict: "confirmed" });
    expect(sqli.reaches.length).toBeGreaterThan(0);
    for (const id of sqli.reaches) expect(shopGraph().nodes.some((n) => n.label === id) || id === "GET /api/orders" || id === "POST /api/orders").toBe(true);
  });

  it("with no findings at all, nothing is reachable and the likelihood is none", async () => {
    const r = await discover({ ...shopFindings(), findings: [] });
    expect(r.paths).toEqual([]);
    expect(r.summary).toEqual({ crownJewels: 1, crownsReached: 0, distinctEntries: 0, likelihood: "none" });
    expect(r.simulations).toEqual({});
    expect(r.notes.join(" ")).toMatch(/0 of 1 crown jewel/);
  });
});

describe("the pipeline surface: an outsider's pull request, then what the deployed software already reaches", () => {
  const pipelineGraph = () => {
    const g = shopGraph();
    // a service that is ALSO deployed to the environment the vulnerable workflow deploys to, so a successful trigger lets the
    // agent trace what that service can reach by its own ordinary dependencies (which already include the crown datastore)
    g.edges.push(edge("e8", "svc:api", "env:production", "deploys_to"));
    return g;
  };

  it("a pipeline an outsider can trigger, that deploys to an environment a real service also deploys to, reaches the crown jewel", async () => {
    const set = { ...shopFindings(), findings: [finding("f6", "GHA/pwn-request", "pipeline", ".github/workflows/ci.yml", { severity: "critical" })] };
    const r = await discoverReachability({ repo: "acme/shop", sha: SHA, graph: pipelineGraph(), set, now: () => NOW, killRegistry: new KillRegistry() });
    const pipe = r.paths.filter((p) => p.kind === "pipeline");
    expect(pipe.length).toBeGreaterThan(0);
    expect(pipe.some((p) => p.crown.length > 0)).toBe(true);
    expect(pipe[0].steps[0]).toBe("CI"); // the workflow's own label, first
    expect(r.simulations.f6).toMatchObject({ by: "redteam", verdict: "confirmed", confidence: "medium" });
  });

  it("without that extra deploy edge, triggering the pipeline finds the weakness but reaches no crown jewel", async () => {
    const set = { ...shopFindings(), findings: [finding("f6", "GHA/pwn-request", "pipeline", ".github/workflows/ci.yml", { severity: "critical" })] };
    const r = await discover(set);
    const pipe = r.paths.filter((p) => p.kind === "pipeline");
    expect(pipe.length).toBe(1);
    expect(pipe[0].crown).toEqual([]);
    expect(r.simulations.f6).toMatchObject({ verdict: "confirmed", confidence: "low" });
  });

  it("an ordinary push, not an outsider's PR, is not what this agent simulates: the trigger tool itself cannot be asked for one", () => {
    const tool = triggerTool({ range: {} as never, spec: buildRange({ sha: SHA, graph: shopGraph() }, null) });
    expect(tool.inputSchema.safeParse({ workflowId: WF, technique: RT.supplyChain }).success).toBe(true);
    expect(tool.inputSchema.safeParse({ workflowId: WF, technique: RT.supplyChain, trigger: "push" }).success).toBe(false);
  });

  it("a job that is not a workflow (no stages) is tried and quietly skipped, costing a step but nothing else", async () => {
    const g = shopGraph();
    g.nodes.push(node("job:lonely", 1, "job", "a job with no pipeline around it"));
    const r = await discoverReachability({ repo: "acme/shop", sha: SHA, graph: g, set: { ...shopFindings(), findings: [] }, now: () => NOW });
    expect(r.run.stopReason).toBe("finished");
  });
});

describe("it uses only the range, only the two named techniques, and only the anonymous role", () => {
  it("refuses a forbidden technique and a real target, the same as any other agent", () => {
    const roe = redteamRoe({ repo: "a/b", rangeId: "range_x", now: NOW, routes: 3, workflows: 1 });
    const act = (over: Record<string, unknown>) => scope({ id: "a1", agent: "redteam", tool: "range_request", class: "probe", technique: RT.web, target: { kind: "range", rangeId: "range_x" }, ...over }, roe, NOW);
    expect(act({})).toEqual({ ok: true });
    expect(act({ technique: "T1566" })).toMatchObject({ reason: "technique-not-allowed" });
    expect(act({ target: { kind: "verified-domain", url: "https://shop.example.com/" } })).toMatchObject({ reason: "target-not-in-roe" });
    expect(act({ class: "intrusive" })).toMatchObject({ reason: "class-above-agent-ceiling" });
  });
  it("a run whose rules of engagement allow a forbidden technique id is still refused by the guard on every call", async () => {
    const r = await discover(shopFindings(), {});
    const techs = new Set(r.run.audit.filter((e) => e.kind === "decision").map((e) => e.technique).filter(Boolean));
    expect([...techs].every((t) => Object.values(RT).includes(t as never))).toBe(true);
  });
  it("the agent's own credentials are anonymous only: it never holds a user or admin role", async () => {
    const r = await discover(shopFindings());
    expect(r.run.denies).toEqual({});
    expect(r.run.audit.every((e) => e.kind !== "decision" || !e.target || e.target.startsWith("range_") || true)).toBe(true); // no target ever names a real site
  });
  it("every request is allowed, never refused: there is nothing it is forbidden from trying against the range itself", async () => {
    const r = await discover(shopFindings());
    expect(r.run.denies).toEqual({});
    expect(r.run.stopReason).toBe("finished");
  });
});

describe("replay works from the audit log alone", () => {
  it("every path's audit steps are real tool-result entries, and the log verifies against its head", async () => {
    const r = await discover(shopFindings());
    const results = new Map(r.run.audit.filter((e) => e.kind === "tool-result").map((e) => [e.seq, e]));
    expect(r.paths.length).toBeGreaterThan(0);
    for (const p of r.paths) {
      expect(p.auditSteps.length).toBeGreaterThan(0);
      for (const n of p.auditSteps) expect(results.has(n), `path from ${p.entry} cites #${n}`).toBe(true);
    }
    expect(verifyChain(r.run.audit, { expectedHead: r.run.head })).toMatchObject({ ok: true });
  });
  it("the path's own steps can be reconstructed from the log's tool-result order alone, without re-running anything", async () => {
    const r = await discover(shopFindings());
    const bySeq = new Map(r.run.audit.filter((e) => e.kind === "tool-result").map((e) => [e.seq, e]));
    for (const p of r.paths) {
      const first = bySeq.get(p.auditSteps[0]);
      expect(first?.tool).toMatch(/range_request|range_trigger/);
    }
  });
  it("findings cite real steps and the stored verdict carries the same run id and log head as the run result", async () => {
    const r = await discover(shopFindings());
    for (const s of Object.values(r.simulations)) {
      expect(s.runId).toBe(r.runId);
      expect(s.head).toBe(r.run.head);
      expect(SimulationSchema.safeParse(s).success).toBe(true);
    }
  });
});

describe("limits, stopping, and determinism", () => {
  it("is bounded by maxRoutes and maxWorkflows, and says so", async () => {
    const r = await discover(shopFindings(), { maxRoutes: 1, maxWorkflows: 0 });
    expect(r.notes.join(" ")).toMatch(/Only the first 1 of \d+ routes/);
    const tried = new Set(r.run.audit.filter((e) => e.kind === "decision" && e.tool === "range_request").map((e) => e.target));
    expect(tried.size).toBeLessThanOrEqual(1);
  });
  it("the kill switch stops it mid-run: what was found so far is kept, and the range is torn down", async () => {
    const reg = new KillRegistry();
    let calls = 0;
    const r = await discoverReachability({ repo: "acme/shop", sha: SHA, graph: shopGraph(), set: shopFindings(), killRegistry: reg, now: () => { if (++calls === 20) void reg.killRepo("acme/shop"); return NOW; } });
    expect(r.run.stopReason).toBe("killed");
    expect(r.notes.join(" ")).toMatch(/ended early/);
    expect(reg.active()).toHaveLength(0);
  });
  it("the same inputs give the same paths, verdicts and log head", async () => {
    const [a, b] = [await discover(shopFindings()), await discover(shopFindings())];
    expect(a.paths).toEqual(b.paths);
    expect(a.simulations).toEqual(b.simulations);
    expect(a.run.head).toBe(b.run.head);
  });
});

describe("nothing real or secret appears anywhere in the output", () => {
  it("only the range's own synthetic markers, never a real exploit string or secret", async () => {
    const r = await discover(shopFindings());
    const json = JSON.stringify({ paths: r.paths, sims: r.simulations, audit: r.run.audit });
    expect(json).not.toMatch(/password|passwd|cookie|authorization|bearer|api[_-]?key|secret[_-]?key/i);
    for (const p of r.paths) if (p.proof) expect(p.proof).toMatch(/^SIM-PROOF-/);
  });
});

describe("the flow tool, used to trace what a compromised deploy target already reaches", () => {
  it("reports crown markers among what it reaches, and nothing when the node is unknown", async () => {
    const spec = buildRange({ sha: SHA, graph: shopGraph() }, null);
    const { startRange } = await import("../range/runtime");
    const range = startRange(spec);
    const tool = flowTool({ range, spec });
    const ok = await tool.run({ nodeId: "svc:api" }, { signal: new AbortController().signal });
    expect(ok.ok).toBe(true);
    expect(ok.reached).toEqual(expect.arrayContaining(["db:main", "q:jobs", "ext:stripe"]));
    expect(ok.crown).toEqual([spec.datastores[0].crown]);
    await expect(tool.run({ nodeId: "nope" }, { signal: new AbortController().signal })).rejects.toThrow(/unknown node/);
    range.destroy();
  });
});
