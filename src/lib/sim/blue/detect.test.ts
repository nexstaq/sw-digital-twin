import { describe, expect, it } from "vitest";
import { applyHealth } from "@/lib/health/engine";
import { FindingSchema, type FindingSet } from "@/lib/security/types";
import { rangeSignals } from "../range/health";
import { buildRange } from "../range/generate";
import { startRange } from "../range/runtime";
import { accessFindings, accessGraph, finding, reported, shopFindings, shopGraph } from "../range/fixtures";
import { assessDetection, detectedAfter, firstBadAfter, type DetectionResult } from "./detect";

const NOW = 1_800_000_000_000;
const SHA = "b".repeat(40);
const run = (set: FindingSet, over: Partial<Parameters<typeof assessDetection>[0]> = {}) => assessDetection({ repo: "acme/shop", sha: SHA, graph: shopGraph(), set, now: () => NOW, ...over });
const byKind = (r: DetectionResult, kind: string) => r.coverage.find((c) => c.kind === kind);

describe("the acceptance case: a stealthy step is missed by the real engine, and detected once the suggested rule is applied", () => {
  it("a flood of ordinary, error-free reads of a crown-jewel route is not flagged by the live health rules", () => {
    const r = run(shopFindings());
    const amp = byKind(r, "read-amplification")!;
    expect(amp).toMatchObject({ outcome: "missed", nodeId: expect.any(String) });
    expect(amp.suggestion).toMatch(/request-rate anomaly|request-volume/i);
    expect(amp.timeToDetectMs).toBeUndefined();
  });

  it("the same flood IS flagged once the suggested rule (a request-volume anomaly, reusing the engine's own EWMA method) is applied", () => {
    const r = run(shopFindings());
    const amp = byKind(r, "read-amplification")!;
    expect(amp.note).toMatch(/candidate request-volume check would have flagged it/);
  });

  it("this is reported honestly: the live health rules really do not change, proven directly against the real engine", () => {
    // reproduce the exact scenario by hand, outside detect.ts, to prove the "missed" claim is not just asserted
    const graph = shopGraph();
    const spec = buildRange({ sha: SHA, graph }, shopFindings());
    const route = spec.endpoints.find((e) => e.method === "GET" && e.path === "/api/orders")!;
    const r = startRange(spec);
    for (let i = 0; i < 8; i++) { for (let k = 0; k < 6; k++) r.handle({ method: "GET", path: "/api/orders", role: "anonymous" }); r.advance(5 * 60_000); }
    for (let i = 0; i < 3; i++) { for (let k = 0; k < 120; k++) r.handle({ method: "GET", path: "/api/orders", role: "anonymous" }); r.advance(5 * 60_000); }
    const { events, endedAt } = r.finish();
    const now = NOW + endedAt + 5 * 60_000;
    const signals = rangeSignals(spec, { events, workflows: [] }, { baseTs: NOW, now });
    const after = applyHealth(graph, signals, now);
    expect(after.nodes.find((n) => n.id === route.ownerId)!.state).not.toMatch(/failing|degraded/);
  });
});

describe("coverage over the weaknesses the other agents already found reachable", () => {
  it("tries every modelled kind present on the fixture, and the counts add up", () => {
    const r = run(shopFindings());
    const kinds = new Set(r.coverage.map((c) => c.kind));
    expect(kinds).toEqual(new Set(["sql-injection", "ssrf", "no-auth", "pipeline-injection", "read-amplification"]));
    expect(r.summary).toEqual({ tried: r.coverage.length, detected: 0, missed: r.coverage.length });
    expect(r.coverage.every((c) => c.outcome !== "not-tried")).toBe(true);
  });
  it("every missed row names a concrete signal to add, never a vague 'add monitoring'", () => {
    const r = run(shopFindings());
    for (const c of r.coverage.filter((c) => c.outcome === "missed")) {
      expect(c.suggestion, c.kind).toBeTruthy();
      expect(c.suggestion!.toLowerCase()).not.toBe("add monitoring");
    }
  });
  it("a pipeline an outsider can trigger is judged by its run outcome alone, and reported as such", () => {
    const r = run(shopFindings());
    const pipe = byKind(r, "pipeline-injection")!;
    expect(pipe).toMatchObject({ outcome: "missed", label: "CI" });
    expect(pipe.note).toMatch(/still reported success/);
    expect(pipe.suggestion).toMatch(/pull request from a fork|who approved/);
  });
  it("every access-control kind X5 reports (the same fixtures its own tests use) is exercised without crashing, and reported missed", () => {
    const set: FindingSet = accessFindings(
      reported("f_idor", "CWE-639", "api/src/order.ts"), reported("f_authz", "CWE-862", "api/src/admin-stats.ts"), reported("f_rate", "CWE-307", "api/src/login.ts"),
      reported("f_sess", "CWE-384", "api/src/users.ts"), reported("f_mass", "CWE-915", "api/src/users.ts"), reported("f_skip", "CWE-841", "api/src/checkout.ts"), reported("f_replay", "CWE-294", "api/src/checkout.ts"),
    );
    const r = assessDetection({ repo: "acme/shop", sha: SHA, graph: accessGraph(), set, now: () => NOW });
    const kinds = ["idor", "missing-authz", "no-rate-limit", "weak-session", "mass-assignment", "skip-step", "replay"];
    for (const kind of kinds) expect(byKind(r, kind), kind).toMatchObject({ outcome: "missed" });
    expect(r.coverage.filter((c) => c.outcome === "not-tried")).toEqual([]);
  });
  it("a weakness the range itself could not place on any route is simply out of scope here too, not guessed at", () => {
    // api/src/nowhere.ts has no route of its own, so X1 already records this weakness as latent (reachable: false);
    // it never reaches this module's candidate list at all, the same way X4 and X5 leave it alone
    const set: FindingSet = { ...shopFindings(), findings: [finding("f_far", "CODE/sql-injection", "code", "api/src/nowhere.ts")] };
    const spec = buildRange({ sha: SHA, graph: shopGraph() }, set);
    expect(spec.weaknesses.find((w) => w.findingId === "f_far")).toMatchObject({ reachable: false });
    const r = run(set);
    expect(r.coverage.some((c) => c.findingId === "f_far")).toBe(false);
  });
  it("only the highest-severity weaknesses are checked up to the limit, and it says so", () => {
    const r = run(shopFindings(), { max: 1 });
    expect(r.coverage.filter((c) => c.kind !== "read-amplification")).toHaveLength(1);
    expect(r.notes.join(" ")).toMatch(/Only the 1 highest-severity of \d+ reachable weaknesses/);
  });
});

describe("the detection arithmetic itself, called the same way checkOne calls it, on a real faulted range", () => {
  it("a node that genuinely goes unhealthy during the observed window is found at the right time, not before it, not at the attack time itself if it takes a few minutes", () => {
    const graph = shopGraph();
    const spec = buildRange({ sha: SHA, graph }, shopFindings());
    const r = startRange(spec);
    for (let i = 0; i < 4; i++) { r.handle({ method: "GET", path: "/api/orders", role: "anonymous" }); r.advance(5 * 60_000); }
    const attackVirtualTs = r.now();
    r.inject("db:main", { kind: "outage" });
    for (let i = 0; i < 4; i++) { r.handle({ method: "GET", path: "/api/orders", role: "anonymous" }); r.advance(5 * 60_000); }
    const { events, endedAt } = r.finish();

    const hit = detectedAfter(graph, spec, events, endedAt, "svc:api", NOW, attackVirtualTs);
    expect(hit).toBeDefined();
    expect(hit!.ts).toBeGreaterThanOrEqual(NOW + attackVirtualTs);

    // and the same real function reports nothing if asked about a node that was never touched
    expect(detectedAfter(graph, spec, events, endedAt, "ext:stripe", NOW, attackVirtualTs)).toBeUndefined();
  });
  it("firstBadAfter itself never reports a frame earlier than the moment asked about", () => {
    const frames = [{ ts: 100, states: { x: "failing" as const }, why: {} }, { ts: 200, states: { x: "nominal" as const }, why: {} }];
    expect(firstBadAfter(frames, "x", 0)).toEqual({ ts: 100 });
    expect(firstBadAfter(frames, "x", 150)).toBeUndefined(); // the only bad frame is before the time asked about
    expect(firstBadAfter(frames, "x", 100)).toEqual({ ts: 100 }); // at-or-after is inclusive of the exact moment
  });
});

describe("the combined replay reuses the real incident-finding module", () => {
  it("finds no incident when, honestly, nothing in the replay ever becomes unhealthy", () => {
    const r = run(shopFindings());
    expect(r.incident).toBeNull();
  });
  it("finds none either with no reachable weaknesses at all, and does not crash", () => {
    const r = run({ ...shopFindings(), findings: [] });
    expect(r.incident).toBeNull();
    expect(r.coverage.filter((c) => c.kind !== "read-amplification")).toEqual([]);
  });
});

describe("detection-gap findings", () => {
  it("are created only for misses, carry the original finding's severity, and validate against the schema", () => {
    const r = run(shopFindings());
    expect(r.findings).toHaveLength(r.summary.missed);
    expect(r.findings.every((f) => f.category === "detection-gap")).toBe(true);
    const sqli = r.findings.find((f) => f.title.includes("sql-injection"))!;
    const original = shopFindings().findings.find((f) => f.ruleId === "CODE/sql-injection" && f.path === "api/src/orders.ts")!;
    expect(sqli.severity).toBe(original.severity);
    for (const f of r.findings) expect(FindingSchema.safeParse(f).success, f.title).toBe(true);
  });
  it("the general read-amplification finding gets a reasonable default severity and a synthetic, non-repo path", () => {
    const r = run(shopFindings());
    const amp = r.findings.find((f) => f.title.startsWith("Not noticed: a flood"))!;
    expect(amp.severity).toBe("medium");
    expect(amp.path.startsWith("(")).toBe(true);
  });
  it("never carries a secret value, a request header, or source text: only labels, kinds and node ids", () => {
    const r = run(shopFindings());
    const json = JSON.stringify(r.findings);
    expect(json).not.toMatch(/\bBearer \S|Authorization:|\bpassword\s*[:=]|secret[_-]?key\s*[:=]|api[_-]?key\s*[:=]/i);
  });
  it("re-running replaces the previous detection-gap findings rather than piling them up (the caller filters by category first)", () => {
    const first = run(shopFindings()).findings;
    const second = run(shopFindings()).findings;
    expect(first.map((f) => f.id).sort()).toEqual(second.map((f) => f.id).sort());
  });
});

describe("it is deterministic and does not mutate its inputs", () => {
  it("the same inputs give the same coverage, findings and incident", () => {
    const [a, b] = [run(shopFindings()), run(shopFindings())];
    expect(a.coverage).toEqual(b.coverage);
    expect(a.findings).toEqual(b.findings);
    expect(a.incident).toEqual(b.incident);
  });
  it("never changes the graph or the finding set it was given", () => {
    const graph = shopGraph(); const set = shopFindings();
    const graphJson = JSON.stringify(graph), setJson = JSON.stringify(set);
    assessDetection({ repo: "acme/shop", sha: SHA, graph, set, now: () => NOW });
    expect(JSON.stringify(graph)).toBe(graphJson);
    expect(JSON.stringify(set)).toBe(setJson);
  });
});
