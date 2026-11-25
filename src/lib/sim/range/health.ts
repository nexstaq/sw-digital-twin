import type { DeploySignal, JobSignal, RunSignal, RuntimeBucket, SignalSet } from "@/lib/health/signals";
import type { RangeEvent, RangeSpec, WorkflowResult } from "./types";

/**
 * Turns what happened inside the range into the same signals the real connectors produce, so the existing health engine lights up
 * the map exactly as it would for a real system: `applyHealth(graph, rangeSignals(...), now)`.
 * Pure. Virtual times are shifted by `baseTs` into real epoch milliseconds so the engine's freshness rules apply.
 */

const BUCKET_MS = 5 * 60_000;
const iso = (ms: number) => new Date(ms).toISOString();

const p95 = (xs: number[]) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil(s.length * 0.95) - 1)];
};

export function rangeSignals(spec: RangeSpec, feed: { events: readonly RangeEvent[]; workflows: readonly WorkflowResult[] }, o: { baseTs: number; now: number }): SignalSet {
  const groups = new Map<string, { nodeId: string; ts: number; ms: number[]; errors: number }>();
  // The engine reads CI health from `wf:` / `job:` / `env:` ids. A map with other ids (the demo, hand-made graphs) gets its CI health
  // through the runtime path instead, so a failed job or deploy still turns its node red.
  const engineCi = (id: string) => /^(wf|job|env):/.test(id);
  for (const e of feed.events) {
    const counted = e.kind === "request" || e.kind === "visit" || ((e.kind === "job" || e.kind === "deploy") && !engineCi(e.nodeId) && e.note !== "skipped");
    if (!counted) continue;
    const ts = Math.floor((o.baseTs + e.t) / BUCKET_MS) * BUCKET_MS;
    const k = `${e.nodeId}@${ts}`;
    const g = groups.get(k) ?? { nodeId: e.nodeId, ts, ms: [], errors: 0 };
    g.ms.push(e.ms);
    if (!e.ok) g.errors++;
    groups.set(k, g);
  }
  const runtime: RuntimeBucket[] = [...groups.values()].sort((a, b) => a.ts - b.ts || a.nodeId.localeCompare(b.nodeId)).map((g) => ({
    source: "range", key: g.nodeId, ts: g.ts, requests: g.ms.length / 5, errors: g.errors / 5, p95Ms: p95(g.ms),
  }));
  const mappings: Record<string, string> = {};
  for (const g of groups.values()) mappings[`range:${g.nodeId}`] = g.nodeId;

  const label = new Map(spec.emulators.map((e) => [e.nodeId, e.label]));
  const runs: RunSignal[] = feed.workflows.map((w) => ({
    id: w.runId, workflowPath: w.workflowId.slice(3), workflowName: label.get(w.workflowId) ?? w.workflowId, branch: "main", sha: w.sha, event: w.trigger,
    status: "completed", conclusion: w.conclusion, attempt: 1, createdAt: iso(o.baseTs + w.startedAt), completedAt: iso(o.baseTs + w.endedAt), url: "#",
    jobs: w.jobs.map((j): JobSignal => ({ name: j.label, status: "completed", conclusion: j.conclusion, ...(j.failedStep ? { failedStep: j.failedStep } : {}), url: "#" })),
  }));
  let id = 0;
  const deploys: DeploySignal[] = feed.workflows.flatMap((w) => w.deploys.map((d): DeploySignal => ({
    id: ++id, environment: d.envId.slice(4), sha: d.sha, state: d.state, createdAt: iso(o.baseTs + w.endedAt), url: "#",
  })));

  return { repo: spec.repo, defaultBranch: "main", fetchedAt: o.now, runs, deploys, runtime, mappings };
}
