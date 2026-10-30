import { describe, expect, it } from "vitest";
import type { TwinGraph, TwinNode } from "@/lib/graph/types";
import { applyHealth, envHealth, workflowHealth } from "./engine";
import type { DeploySignal, RunSignal, SignalSet } from "./signals";

const NOW = Date.parse("2026-10-29T12:00:00Z");
const mins = (m: number) => new Date(NOW - m * 60_000).toISOString();

let id = 1;
const run = (o: Partial<RunSignal> = {}): RunSignal => ({
  id: id++, workflowPath: ".github/workflows/ci.yml", workflowName: "CI", branch: "main", sha: `sha${id}aaaaaaa`, event: "push",
  status: "completed", conclusion: "success", attempt: 1, createdAt: mins(id), url: `https://github.com/a/b/actions/runs/${id}`, ...o,
});
const deploy = (o: Partial<DeploySignal> = {}): DeploySignal => ({
  id: id++, environment: "production", sha: `dep${id}aaaaaaa`, state: "success", createdAt: mins(id), url: `https://github.com/a/b/deployments/${id}`, ...o,
});
const node = (n: Partial<TwinNode> & Pick<TwinNode, "id" | "level" | "label">): TwinNode => ({
  kind: "job", summary: "", state: "unknown", score: 0.5, spark: [0.5, 0.5], reasons: [], evidence: [{ path: "x" }], criticality: 2, ...n,
});
const signals = (o: Partial<SignalSet> = {}): SignalSet => ({ repo: "a/b", defaultBranch: "main", fetchedAt: NOW, runs: [], deploys: [], ...o });

describe("workflowHealth", () => {
  it("is nominal when recent runs pass", () => {
    const p = workflowHealth([run({ createdAt: mins(5) }), run({ createdAt: mins(65) })], "main", NOW);
    expect(p.state).toBe("nominal");
    expect(p.reasons).toEqual([]);
  });

  it("fails on a failing latest run and names the failed step with a link", () => {
    const failed = run({
      createdAt: mins(2), conclusion: "failure", sha: "deadbeefcafe",
      jobs: [{ name: "test", status: "completed", conclusion: "failure", failedStep: "Run vitest", url: "https://github.com/a/b/job/9" }],
    });
    const p = workflowHealth([failed, run({ createdAt: mins(90) })], "main", NOW);
    expect(p.state).toBe("failing");
    expect(p.reasons.join(" ")).toContain("deadbee");
    expect(p.reasons).toContain('test: step "Run vitest" failed');
    expect(p.links?.map((l) => l.url)).toContain("https://github.com/a/b/job/9");
  });

  it("recovers as soon as the latest run passes (but notes a low pass rate)", () => {
    const runs = [run({ createdAt: mins(1) }), ...Array.from({ length: 6 }, (_, i) => run({ createdAt: mins(10 + i), conclusion: "failure" }))];
    const p = workflowHealth(runs, "main", NOW);
    expect(p.state).toBe("degraded");
    expect(p.reasons.some((r) => r.startsWith("Passed 1 of 7"))).toBe(true);
  });

  it("flags flakiness when one commit both passed and failed", () => {
    const p = workflowHealth([run({ createdAt: mins(1), sha: "s1" }), run({ createdAt: mins(3), sha: "s1", conclusion: "failure" }), ...Array.from({ length: 8 }, (_, i) => run({ createdAt: mins(20 + i) }))], "main", NOW);
    expect(p.state).toBe("degraded");
    expect(p.reasons.some((r) => r.startsWith("Flaky"))).toBe(true);
  });

  it("ignores other branches, cancelled and skipped runs", () => {
    const p = workflowHealth([
      run({ branch: "feature", conclusion: "failure", createdAt: mins(1) }),
      run({ conclusion: "cancelled", createdAt: mins(2) }),
      run({ conclusion: "skipped", createdAt: mins(3) }),
      run({ createdAt: mins(4) }),
    ], "main", NOW);
    expect(p.state).toBe("nominal");
  });

  it("is unknown (never green) with no finished runs, and shows in-flight work", () => {
    expect(workflowHealth([], "main", NOW).state).toBe("unknown");
    const p = workflowHealth([run({ status: "in_progress", conclusion: null, createdAt: mins(1) })], "main", NOW);
    expect(p.state).toBe("unknown");
    expect(p.live).toBe(true);
  });

  it("marks live while a run is in flight but keeps the last result", () => {
    const p = workflowHealth([run({ status: "in_progress", conclusion: null, createdAt: mins(1) }), run({ createdAt: mins(30) })], "main", NOW);
    expect(p.state).toBe("nominal");
    expect(p.live).toBe(true);
    expect(p.reasons).toContain("Running now");
  });

  it("notes staleness without changing state", () => {
    const p = workflowHealth([run({ createdAt: new Date(NOW - 60 * 86_400_000).toISOString() })], "main", NOW);
    expect(p.state).toBe("nominal");
    expect(p.reasons[0]).toMatch(/No runs in 60 days/);
  });
});

describe("envHealth", () => {
  it("fails when the latest deploy failed and passes when it succeeded", () => {
    expect(envHealth([deploy({ createdAt: mins(5), state: "failure" }), deploy({ createdAt: mins(60) })], NOW).state).toBe("failing");
    expect(envHealth([deploy({ createdAt: mins(5) }), deploy({ createdAt: mins(60), state: "failure" })], NOW).state).toBe("degraded");
    expect(envHealth([deploy({ createdAt: mins(5) }), deploy({ createdAt: mins(60) })], NOW).state).toBe("nominal");
  });
  it("in-flight deploys do not change the verdict", () => {
    const p = envHealth([deploy({ createdAt: mins(1), state: "in_progress" }), deploy({ createdAt: mins(60) })], NOW);
    expect(p.state).toBe("nominal");
    expect(p.live).toBe(true);
  });
});

const graph = (): TwinGraph => ({
  repo: "a/b",
  nodes: [
    node({ id: "cl:ci", level: 0, label: "CI" }),
    node({ id: "wf:.github/workflows/ci.yml", level: 1, parentId: "cl:ci", label: "CI" }),
    node({ id: "job:.github/workflows/ci.yml:test", level: 2, parentId: "wf:.github/workflows/ci.yml", label: "test" }),
    node({ id: "job:.github/workflows/ci.yml:lint", level: 2, parentId: "wf:.github/workflows/ci.yml", label: "lint" }),
    node({ id: "env:production", level: 1, parentId: "cl:ci", kind: "env", label: "production environment" }),
    node({ id: "svc", level: 0, label: "Web", kind: "service" }),
  ],
  edges: [{ id: "e1", from: "job:.github/workflows/ci.yml:test", to: "env:production", kind: "triggers", throughput: 0.5, errorRate: 0 }],
  deploys: [],
});

describe("applyHealth", () => {
  const failedRun = run({
    createdAt: mins(3), conclusion: "failure",
    jobs: [
      { name: "test", status: "completed", conclusion: "failure", failedStep: "Run vitest", url: "https://x/j1" },
      { name: "lint", status: "completed", conclusion: "success", url: "https://x/j2" },
    ],
  });

  it("turns the failing job red, its workflow and block red, and leaves unrelated nodes unknown", () => {
    const g = applyHealth(graph(), signals({ runs: [failedRun] }), NOW);
    const by = (i: string) => g.nodes.find((n) => n.id === i)!;
    expect(by("job:.github/workflows/ci.yml:test").state).toBe("failing");
    expect(by("job:.github/workflows/ci.yml:lint").state).toBe("nominal");
    expect(by("wf:.github/workflows/ci.yml").state).toBe("failing");
    expect(by("cl:ci").state).toBe("failing");
    expect(by("svc").state).toBe("unknown");
  });

  it("explains why, with the failing step and a run link, on the workflow", () => {
    const g = applyHealth(graph(), signals({ runs: [failedRun] }), NOW);
    const wf = g.nodes.find((n) => n.id === "wf:.github/workflows/ci.yml")!;
    expect(wf.reasons.join("\n")).toContain('test: step "Run vitest" failed');
    expect(wf.links?.some((l) => l.url === failedRun.url)).toBe(true);
  });

  it("keeps the workflow verdict when its jobs have no signal", () => {
    const g = applyHealth(graph(), signals({ runs: [run({ createdAt: mins(3), conclusion: "failure" })] }), NOW);
    expect(g.nodes.find((n) => n.id === "wf:.github/workflows/ci.yml")!.state).toBe("failing");
  });

  it("makes outgoing edges of failing nodes flicker", () => {
    const g = applyHealth(graph(), signals({ runs: [failedRun] }), NOW);
    expect(g.edges[0].errorRate).toBeGreaterThan(0.05);
  });

  it("maps deployments onto environments and the timeline", () => {
    const g = applyHealth(graph(), signals({ deploys: [deploy({ createdAt: mins(30), state: "failure" })] }), NOW);
    expect(g.nodes.find((n) => n.id === "env:production")!.state).toBe("failing");
    expect(g.deploys).toHaveLength(1);
    expect(g.deploys[0].ok).toBe(false);
    expect(g.deploys[0].hoursAgo).toBeCloseTo(0.5, 1);
  });

  it("falls back to deploy-style workflows for the timeline when there are no Deployments", () => {
    const g = applyHealth(graph(), signals({ runs: [
      run({ workflowName: "Release", workflowPath: ".github/workflows/release.yml", createdAt: mins(30), conclusion: "failure" }),
      run({ workflowName: "CI", createdAt: mins(10) }),
    ] }), NOW);
    expect(g.deploys).toHaveLength(1);
    expect(g.deploys[0]).toMatchObject({ ok: false });
    expect(g.deploys[0].label).toMatch(/^Release /);
  });

  it("counts running and queued work and the oldest start", () => {
    const g = applyHealth(graph(), signals({
      runs: [run({ status: "in_progress", conclusion: null, createdAt: mins(2) }), run({ status: "queued", conclusion: null, createdAt: mins(1) }), run({ status: "in_progress", conclusion: null, branch: "feature" })],
      deploys: [deploy({ state: "in_progress", createdAt: mins(5) })],
    }), NOW);
    expect(g.activity).toEqual({ running: 2, queued: 1, since: mins(5) });
  });

  it("is idempotent and does not mutate its input", () => {
    const input = graph();
    const snapshot = JSON.stringify(input);
    const s = signals({ runs: [failedRun] });
    const once = applyHealth(input, s, NOW);
    expect(JSON.stringify(input)).toBe(snapshot);
    expect(applyHealth(once, s, NOW)).toEqual(once);
  });

  it("clears red when a passing run arrives (the fix lands)", () => {
    const red = applyHealth(graph(), signals({ runs: [failedRun] }), NOW);
    const fixed = applyHealth(red, signals({ runs: [run({ createdAt: mins(1), jobs: [{ name: "test", status: "completed", conclusion: "success", url: "u" }, { name: "lint", status: "completed", conclusion: "success", url: "u" }] }), failedRun] }), NOW);
    expect(fixed.nodes.find((n) => n.id === "cl:ci")!.state).not.toBe("failing");
    expect(fixed.edges[0].errorRate).toBe(0);
  });
});
