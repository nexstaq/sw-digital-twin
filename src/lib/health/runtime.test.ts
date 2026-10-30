import { describe, expect, it } from "vitest";
import { applyHealth } from "./engine";
import { ewmaAnomaly } from "./anomaly";
import { runtimeHealth } from "./runtime";
import { signalsAt } from "./at";
import type { RuntimeBucket, SignalSet } from "./signals";
import type { TwinGraph, TwinNode } from "@/lib/graph/types";

const T = Date.parse("2026-10-29T12:00:00Z");
const STEP = 5 * 60_000;
/** n buckets ending at T, oldest first */
const series = (n: number, f: (i: number) => Partial<RuntimeBucket>, key = "svc"): RuntimeBucket[] =>
  Array.from({ length: n }, (_, i) => ({ source: "otlp", key, ts: T - (n - 1 - i) * STEP, ...f(i) }));

describe("ewmaAnomaly", () => {
  const calm = Array.from({ length: 20 }, (_, i) => 10 + (i % 3) * 0.2);
  it("needs enough baseline", () => expect(ewmaAnomaly([1, 2, 3])).toBeNull());
  it("ignores a normal wiggle and a single blip", () => {
    expect(ewmaAnomaly([...calm, 10.2, 10.1])?.anomalous).toBe(false);
    expect(ewmaAnomaly([...calm, 10, 40])?.anomalous).toBe(false); // hold=2: one point is not enough
  });
  it("flags a sustained spike and the spike cannot raise its own baseline", () => {
    const a = ewmaAnomaly([...calm, 40, 42])!;
    expect(a.anomalous).toBe(true);
    expect(a.mean).toBeLessThan(11);
    expect(a.ratio).toBeGreaterThan(3.5);
  });
  it("a sustained spike stays anomalous; the baseline does not absorb it", () => {
    const long = [...calm, ...Array(30).fill(40)];
    const a = ewmaAnomaly(long)!;
    expect(a.anomalous).toBe(true);
    expect(a.mean).toBeLessThan(11);
  });
  it("a flat baseline does not make every wiggle infinite sigma (floor)", () => {
    expect(ewmaAnomaly([...Array(20).fill(100), 101, 101], { floor: 5 })?.anomalous).toBe(false);
  });
});

describe("runtimeHealth", () => {
  it("is null (unknown) without recent data", () => {
    expect(runtimeHealth([], T)).toBeNull();
    expect(runtimeHealth(series(20, () => ({ errors: 1, requests: 100 })), T + 2 * 3_600_000)).toBeNull();
  });
  it("is nominal for a steady service", () => {
    expect(runtimeHealth(series(30, (i) => ({ errors: 1, requests: 100 + (i % 4), p95Ms: 40 + (i % 3) })), T)!.state).toBe("nominal");
  });
  it("fails on a sustained error rate and says what is normal", () => {
    const v = runtimeHealth(series(30, (i) => ({ errors: i >= 28 ? 18 : 0.4, requests: 100, p95Ms: 40 })), T)!;
    expect(v.state).toBe("failing");
    expect(v.reasons[0]).toMatch(/Error rate 18% \(normally 0\.\d%\)/);
  });
  it("one bad bucket is not an incident", () => {
    expect(runtimeHealth(series(30, (i) => ({ errors: i === 29 ? 30 : 0.4, requests: 100 })), T)!.state).toBe("nominal");
  });
  it("catches a latency regression before any error shows up", () => {
    const v = runtimeHealth(series(30, (i) => ({ errors: 0.2, requests: 100, p95Ms: i >= 28 ? 900 : 40 + (i % 3) })), T)!;
    expect(v.state).toBe("failing");
    expect(v.reasons[0]).toMatch(/p95 latency 900ms \(normally 4\dms\)/);
  });
  it("modest slowdown is degraded, not failing", () => {
    const v = runtimeHealth(series(30, (i) => ({ errors: 0.2, requests: 100, p95Ms: i >= 28 ? 90 : 40 + (i % 3) })), T)!;
    expect(v.state).toBe("degraded");
  });
  it("works with error counts only (Sentry has no request volume)", () => {
    const v = runtimeHealth(series(30, (i) => ({ source: "sentry", errors: i >= 28 ? 40 : 2 + (i % 2), top: i === 29 ? [{ title: "TimeoutError", count: 40, url: "https://sentry.io/i/1" }] : undefined })), T)!;
    expect(v.state).toBe("failing");
    expect(v.reasons[0]).toMatch(/40 errors\/min \(normally 2\.\d\)/);
    expect(v.links[0].url).toBe("https://sentry.io/i/1");
  });
});

const node = (n: Partial<TwinNode> & Pick<TwinNode, "id" | "level" | "label">): TwinNode => ({
  kind: "service", summary: "", state: "unknown", score: 0.5, spark: [0.5, 0.5], reasons: [], evidence: [{ path: "x" }], criticality: 2, ...n,
});
const graph: TwinGraph = { repo: "a/b", nodes: [node({ id: "pay", level: 0, label: "Payments" }), node({ id: "web", level: 0, label: "Web" })], edges: [], deploys: [] };
const sig = (runtime: RuntimeBucket[]): SignalSet => ({ repo: "a/b", defaultBranch: "main", fetchedAt: T, runs: [], deploys: [], runtime, mappings: { "otlp:svc": "pay" } });

describe("applyHealth with runtime signals", () => {
  it("lights only mapped nodes; unmapped stay unknown", () => {
    const g = applyHealth(graph, sig(series(30, (i) => ({ errors: i >= 28 ? 20 : 0.3, requests: 100 }))), T);
    expect(g.nodes.find((n) => n.id === "pay")!.state).toBe("failing");
    expect(g.nodes.find((n) => n.id === "web")!.state).toBe("unknown");
  });
  it("ignores a mapping to a node that no longer exists", () => {
    const g = applyHealth(graph, { ...sig(series(30, () => ({ errors: 20, requests: 100 }))), mappings: { "otlp:svc": "gone" } }, T);
    expect(g.nodes.every((n) => n.state === "unknown")).toBe(true);
  });
  it("two sources for one node: the worse one wins and both explain", () => {
    const s = sig([...series(30, (i) => ({ errors: i >= 28 ? 20 : 0.3, requests: 100 })), ...series(30, (i) => ({ source: "sentry", key: "p", errors: i >= 28 ? 50 : 2 }), "p")]);
    const g = applyHealth(graph, { ...s, mappings: { "otlp:svc": "pay", "sentry:p": "pay" } }, T);
    expect(g.nodes.find((n) => n.id === "pay")!.reasons.length).toBe(2);
  });
});

describe("signalsAt (time travel)", () => {
  const base: SignalSet = {
    repo: "a/b", defaultBranch: "main", fetchedAt: T,
    runs: [
      { id: 1, workflowPath: "w", workflowName: "W", branch: "main", sha: "a", event: "push", status: "completed", conclusion: "success", attempt: 1, createdAt: new Date(T - 3 * 3.6e6).toISOString(), completedAt: new Date(T - 3 * 3.6e6 + 60_000).toISOString(), url: "u" },
      { id: 2, workflowPath: "w", workflowName: "W", branch: "main", sha: "b", event: "push", status: "completed", conclusion: "failure", attempt: 1, createdAt: new Date(T - 1 * 3.6e6).toISOString(), completedAt: new Date(T - 1 * 3.6e6 + 600_000).toISOString(), url: "u" },
    ],
    deploys: [{ id: 1, environment: "prod", sha: "b", state: "success", createdAt: new Date(T - 1 * 3.6e6).toISOString(), url: "u" }],
    runtime: series(10, () => ({ errors: 1 })),
  };
  it("hides the future and shows unfinished runs as in progress", () => {
    expect(signalsAt(base, T - 2 * 3.6e6).runs.map((r) => r.id)).toEqual([1]);
    const mid = signalsAt(base, T - 1 * 3.6e6 + 120_000);
    expect(mid.runs.find((r) => r.id === 2)).toMatchObject({ status: "in_progress", conclusion: null });
    expect(signalsAt(base, T).runs.find((r) => r.id === 2)!.conclusion).toBe("failure");
    expect(signalsAt(base, T - 2 * 3.6e6).deploys).toEqual([]);
    expect(signalsAt(base, T - 20 * 60_000).runtime!.every((b) => b.ts <= T - 20 * 60_000)).toBe(true);
  });
  it("is a pure view: input untouched", () => {
    const snap = JSON.stringify(base);
    signalsAt(base, T - 2 * 3.6e6);
    expect(JSON.stringify(base)).toBe(snap);
  });
});
