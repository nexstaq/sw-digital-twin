import { rollup } from "@/lib/graph/rollup";
import type { NodeKind, TwinEdge, TwinGraph, TwinNode } from "@/lib/graph/types";
import type { RunSignal, RuntimeBucket, SignalSet } from "@/lib/health/signals";

/**
 * A seeded incident for the demo, built from the SAME signal types a live repo produces, so replaying it exercises
 * the real engine, anomaly detection and incident finder end to end. Fully synthetic and deterministic.
 *
 *   T-3h12m  Release deploy succeeds
 *   T-3h00m  Database p95 latency jumps 40ms -> ~900ms (no errors yet: a slow query / lock after the deploy)
 *   T-2h52m  Payments API starts timing out (errors)
 *   T-2h42m  API Gateway error rate rises
 *   T-2h35m  Web Storefront errors, Payments Webhooks fail
 *   T-2h10m  Rollback deploy
 *   T-2h05m  Database recovers; the rest follow
 */
const H = 3_600_000, M = 60_000, STEP = 5 * M;
export const SCENARIO_REPO = "acme/shop-incident";

function rng(seed: number) { let s = seed; return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 4294967296); }

const node = (id: string, level: 0 | 1 | 2, parentId: string | undefined, kind: NodeKind, label: string, summary: string, crit: 1 | 2 | 3 = 2): TwinNode => ({
  id, level, parentId, kind, label, summary, state: "unknown", score: 0.5, spark: [0.5, 0.5], reasons: [], evidence: [{ path: id }], criticality: crit,
});
const edge = (from: string, to: string, kind: TwinEdge["kind"] = "calls"): TwinEdge => ({ id: `${from}>${to}`, from, to, kind, throughput: 0.6, errorRate: 0 });

export function scenarioGraph(): TwinGraph {
  return {
    repo: SCENARIO_REPO, deploys: [],
    nodes: rollup([
      node("web", 0, undefined, "service", "Web Storefront", "Customer-facing site."),
      node("api", 0, undefined, "service", "API Gateway", "Single entry point for the apps.", 3),
      node("pay", 0, undefined, "service", "Payments", "Charges cards and handles Stripe webhooks.", 3),
      node("pay-api", 1, "pay", "service", "Payments API", "Charge and refund endpoints.", 3),
      node("pay-hooks", 1, "pay", "service", "Payments Webhooks", "Receives Stripe events."),
      node("db", 0, undefined, "datastore", "Primary Database", "Orders, customers and payments.", 3),
      node("cl:ci", 0, undefined, "job", "CI & Release", "Tests and ships every change."),
      node("wf:.github/workflows/ci.yml", 1, "cl:ci", "job", "CI", "Runs tests on every push."),
      node("wf:.github/workflows/release.yml", 1, "cl:ci", "job", "Release", "Deploys to production."),
    ]),
    edges: [edge("web", "api"), edge("api", "pay"), edge("api", "db", "reads"), edge("pay", "db", "reads")],
  };
}

/** Mappings a user would confirm once in the Sources panel. */
export const scenarioMappings: Record<string, string> = {
  "otlp:postgres": "db", "otlp:payments-api": "pay-api", "otlp:payments-webhooks": "pay-hooks", "otlp:api-gateway": "api", "otlp:storefront": "web",
};

export function scenarioSignals(anchor: number): SignalSet {
  const t0 = anchor - 3 * H; // the incident begins
  const rand = rng(42);
  const feed = (key: string, base: { errors: number; requests: number; p95: number }, hit?: { from: number; to: number; errors?: number; p95?: number }): RuntimeBucket[] => {
    const out: RuntimeBucket[] = [];
    for (let ts = Math.floor((anchor - 48 * H) / STEP) * STEP; ts <= anchor; ts += STEP) {
      const inHit = hit && ts >= t0 + hit.from * M && ts < t0 + hit.to * M;
      out.push({
        source: "otlp", key, ts,
        requests: base.requests * (0.9 + rand() * 0.2),
        errors: inHit && hit.errors !== undefined ? hit.errors * (0.9 + rand() * 0.2) : base.errors * (0.5 + rand()),
        p95Ms: inHit && hit.p95 !== undefined ? hit.p95 * (0.9 + rand() * 0.2) : base.p95 * (0.95 + rand() * 0.1),
      });
    }
    return out;
  };

  const run = (id: number, wf: "ci" | "release", minsAgo: number, conclusion: "success" | "failure" = "success"): RunSignal => ({
    id, workflowPath: `.github/workflows/${wf}.yml`, workflowName: wf === "ci" ? "CI" : "Release", branch: "main", sha: `${(id * 2654435761 >>> 0).toString(16).padStart(8, "0")}c0ffee`.slice(0, 40),
    event: "push", status: "completed", conclusion, attempt: 1, createdAt: new Date(anchor - minsAgo * M).toISOString(), completedAt: new Date(anchor - minsAgo * M + 4 * M).toISOString(), url: `https://github.com/${SCENARIO_REPO}/actions/runs/${id}`,
  });
  const runs: RunSignal[] = [
    ...Array.from({ length: 20 }, (_, i) => run(100 + i, "ci", 20 + i * 150)),
    run(200, "release", 3 * 60 + 12), // the deploy just before it all started
    run(201, "release", 2 * 60 + 10), // the rollback
    run(202, "release", 30 * 60),
  ];

  return {
    repo: SCENARIO_REPO, defaultBranch: "main", fetchedAt: anchor, runs, deploys: [], mappings: scenarioMappings,
    runtime: [
      // database: latency only, no errors. Only an anomaly detector sees this first.
      ...feed("postgres", { errors: 0.1, requests: 220, p95: 40 }, { from: 0, to: 55, p95: 900 }),
      ...feed("payments-api", { errors: 0.4, requests: 80, p95: 120 }, { from: 8, to: 60, errors: 14, p95: 2400 }),
      ...feed("payments-webhooks", { errors: 0.2, requests: 30, p95: 90 }, { from: 35, to: 65, errors: 9 }),
      ...feed("api-gateway", { errors: 0.8, requests: 400, p95: 85 }, { from: 18, to: 62, errors: 30 }),
      ...feed("storefront", { errors: 0.6, requests: 600, p95: 150 }, { from: 25, to: 70, errors: 40 }),
    ],
  };
}
