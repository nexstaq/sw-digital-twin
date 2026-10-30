import { describe, expect, it } from "vitest";
import { applyHealth } from "@/lib/health/engine";
import { signalsAt } from "@/lib/health/at";
import { findIncident, sampleFrames } from "@/lib/health/incident";
import { validateGraph } from "@/lib/graph/integrity";
import { scenarioGraph, scenarioSignals } from "./incident";

const ANCHOR = Date.parse("2026-10-29T12:00:00Z");
const H = 3_600_000;

describe("seeded incident scenario", () => {
  const g = scenarioGraph();
  const s = scenarioSignals(ANCHOR);

  it("is a valid graph and is deterministic", () => {
    expect(validateGraph(g)).toEqual([]);
    expect(JSON.stringify(scenarioSignals(ANCHOR))).toBe(JSON.stringify(s));
  });

  it("is healthy now and healthy before the incident", () => {
    const now = applyHealth(g, s, ANCHOR);
    expect(now.nodes.filter((n) => !n.parentId).every((n) => n.state !== "failing")).toBe(true);
    const before = applyHealth(g, signalsAt(s, ANCHOR - 4 * H), ANCHOR - 4 * H);
    expect(before.nodes.find((n) => n.id === "db")!.state).toBe("nominal");
  });

  it("is red in the middle of the incident, with the database named as slow", () => {
    const t = ANCHOR - 2.4 * H;
    const mid = applyHealth(g, signalsAt(s, t), t);
    expect(mid.nodes.find((n) => n.id === "db")!.state).toBe("failing");
    expect(mid.nodes.find((n) => n.id === "db")!.reasons[0]).toMatch(/p95 latency \d+ms \(normally 4\dms\)/);
    expect(mid.nodes.find((n) => n.id === "pay")!.state).toBe("failing");
    expect(mid.nodes.find((n) => n.id === "web")!.state).toBe("failing");
  });

  it("the incident finder tells the story: database first, then payments, api, web", () => {
    const inc = findIncident(g, sampleFrames(g, s, { to: ANCHOR, stepMs: 5 * 60_000 }))!;
    expect(inc).toBeTruthy();
    expect(inc.first.nodeId).toBe("db");
    const order = inc.path.map((p) => p.nodeId);
    expect(order[0]).toBe("db");
    expect(order.indexOf("pay-api")).toBeLessThan(order.indexOf("api"));
    expect(order.indexOf("api")).toBeLessThan(order.indexOf("web"));
    expect(order).toContain("pay-hooks");
    expect(inc.endTs).toBeDefined();
    const startedHoursAgo = (ANCHOR - inc.first.ts) / H;
    expect(startedHoursAgo).toBeGreaterThan(2.9);
    expect(startedHoursAgo).toBeLessThan(3.2);
  });
});
