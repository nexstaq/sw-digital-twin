import { describe, expect, it } from "vitest";
import type { TwinGraph, TwinNode } from "@/lib/graph/types";
import { findIncident, sampleFrames } from "./incident";
import type { RuntimeBucket, SignalSet } from "./signals";

const NOW = Date.parse("2026-10-29T12:00:00Z");
const STEP = 5 * 60_000;
const H = 3_600_000;
const node = (id: string, label: string): TwinNode => ({ id, level: 0, kind: "service", label, summary: "", state: "unknown", score: 0.5, spark: [0.5, 0.5], reasons: [], evidence: [{ path: "x" }], criticality: 2 });
// web -> api -> pay -> db  (calls: a failure in db takes down everything above it)
const graph: TwinGraph = {
  repo: "a/b", deploys: [],
  nodes: [node("web", "Web"), node("api", "API"), node("pay", "Payments"), node("db", "Database"), node("other", "Other")],
  edges: [["web", "api"], ["api", "pay"], ["pay", "db"]].map(([f, t], i) => ({ id: `e${i}`, from: f, to: t, kind: "calls" as const, throughput: 0.5, errorRate: 0 })),
};

/** 48h of 5-minute buckets, healthy except where `bad(ts)` says otherwise */
function feed(key: string, bad: (ts: number) => Partial<RuntimeBucket> | null): RuntimeBucket[] {
  const out: RuntimeBucket[] = [];
  for (let ts = NOW - 48 * H, i = 0; ts <= NOW; ts += STEP, i++) {
    out.push({ source: "otlp", key, ts, errors: 0.3 + (i % 3) * 0.1, requests: 100, p95Ms: 40 + (i % 4), ...(bad(ts) ?? {}) });
  }
  return out;
}
const t0 = NOW - 5 * H; // incident starts here
const win = (from: number, to: number) => (ts: number) => ts >= t0 + from * 60_000 && ts < t0 + to * 60_000;

function scenario(): SignalSet {
  return {
    repo: "a/b", defaultBranch: "main", fetchedAt: NOW, runs: [], deploys: [],
    mappings: { "otlp:db": "db", "otlp:pay": "pay", "otlp:api": "api", "otlp:web": "web", "otlp:other": "other" },
    runtime: [
      ...feed("db", (ts) => (win(0, 60)(ts) ? { p95Ms: 900 } : null)), // slow first, no errors at all
      ...feed("pay", (ts) => (win(10, 65)(ts) ? { errors: 20 } : null)),
      ...feed("api", (ts) => (win(20, 70)(ts) ? { errors: 9 } : null)),
      ...feed("web", (ts) => (win(30, 75)(ts) ? { errors: 8 } : null)),
      ...feed("other", () => null),
    ],
  };
}

describe("incident detection", () => {
  const frames = sampleFrames(graph, scenario(), { to: NOW, hours: 48, stepMs: STEP });
  const inc = findIncident(graph, frames)!;

  it("samples 48h of frames", () => expect(frames).toHaveLength(48 * 12 + 1));

  it("finds the incident window and that it recovered", () => {
    expect(inc).toBeTruthy();
    expect(inc.startTs).toBeGreaterThanOrEqual(t0);
    expect(inc.startTs).toBeLessThanOrEqual(t0 + 15 * 60_000);
    expect(inc.endTs).toBeGreaterThan(t0 + 60 * 60_000);
    expect(inc.endTs).toBeLessThan(t0 + 90 * 60_000);
  });

  it("patient zero is the part that went bad first, even though it only got slow (no errors)", () => {
    expect(inc.first.nodeId).toBe("db");
    expect(inc.first.reason).toMatch(/p95 latency/);
  });

  it("orders the spread and keeps only what depends on patient zero in the path", () => {
    expect(inc.sequence.map((s) => s.nodeId)).toEqual(["db", "pay", "api", "web"]);
    expect(inc.path.map((s) => s.nodeId)).toEqual(["db", "pay", "api", "web"]);
    expect(inc.sequence.map((s) => s.ts)).toEqual([...inc.sequence.map((s) => s.ts)].sort((a, b) => a - b));
    expect(inc.sequence.some((s) => s.nodeId === "other")).toBe(false);
    expect(inc.worst).toBe("failing");
  });

  it("returns null for a calm system", () => {
    const calm: SignalSet = { ...scenario(), runtime: feed("db", () => null) };
    expect(findIncident(graph, sampleFrames(graph, calm, { to: NOW, stepMs: STEP }))).toBeNull();
  });

  it("ignores chronic problems and still finds the real incident", () => {
    const s = scenario();
    s.runtime = [...s.runtime!.filter((b) => b.key !== "other"), ...feed("other", () => ({ errors: 30 }))]; // permanently bad
    const f = findIncident(graph, sampleFrames(graph, s, { to: NOW, stepMs: STEP }))!;
    expect(f.first.nodeId).toBe("db");
    expect(f.sequence.some((x) => x.nodeId === "other")).toBe(false);
  });

  it("reports an ongoing incident with no end", () => {
    const s = scenario();
    s.runtime = [...feed("db", (ts) => (ts >= t0 ? { p95Ms: 900 } : null)), ...s.runtime!.filter((b) => b.key !== "db")];
    expect(findIncident(graph, sampleFrames(graph, s, { to: NOW, stepMs: STEP }))!.endTs).toBeUndefined();
  });
});

describe("incident across levels", () => {
  // db is a top-level block; payments is a top-level block containing a leaf "pay-api"
  const g: TwinGraph = {
    repo: "a/b", deploys: [],
    nodes: [node("api", "API"), node("pay", "Payments"), { ...node("pay-api", "Payments API"), level: 1, parentId: "pay" }, node("db", "Database")],
    edges: [["api", "pay"], ["pay", "db"]].map(([f, t], i) => ({ id: `e${i}`, from: f, to: t, kind: "calls" as const, throughput: 0.5, errorRate: 0 })),
  };
  it("counts a nested failing part as downstream of the block it lives in", () => {
    const s: SignalSet = {
      repo: "a/b", defaultBranch: "main", fetchedAt: NOW, runs: [], deploys: [],
      mappings: { "otlp:db": "db", "otlp:pay": "pay-api", "otlp:api": "api" },
      runtime: [...feed("db", (ts) => (win(0, 60)(ts) ? { p95Ms: 900 } : null)), ...feed("pay", (ts) => (win(10, 65)(ts) ? { errors: 20 } : null)), ...feed("api", (ts) => (win(20, 70)(ts) ? { errors: 9 } : null))],
    };
    const inc = findIncident(g, sampleFrames(g, s, { to: NOW, stepMs: STEP }))!;
    expect(inc.first.nodeId).toBe("db");
    expect(inc.path.map((p) => p.nodeId)).toEqual(["db", "pay-api", "api"]);
  });
});
