import { rollup } from "@/lib/graph/rollup";
import type { DeployMarker, Status, TwinGraph, TwinNode } from "@/lib/graph/types";
import { slug } from "@/lib/ingest/util";
import { runtimeHealth } from "./runtime";
import type { DeploySignal, JobSignal, RunSignal, RuntimeBucket, SignalSet } from "./signals";

const DAY = 86_400_000;
const WINDOW = 20; // completed runs / deploys considered per node
const STALE_DAYS = 30;
const DEPLOY_LIKE = /deploy|release|publish|ship/i;
const FAILED = new Set(["failure", "timed_out", "startup_failure"]);
const counted = (r: RunSignal) => r.status === "completed" && (r.conclusion === "success" || FAILED.has(r.conclusion ?? ""));
const isFail = (r: RunSignal) => FAILED.has(r.conclusion ?? "");
const short = (sha: string) => sha.slice(0, 7);
const ago = (iso: string, now: number) => {
  const m = Math.max(0, Math.round((now - Date.parse(iso)) / 60_000));
  return m < 60 ? `${m}m ago` : m < 1440 ? `${Math.round(m / 60)}h ago` : `${Math.round(m / 1440)}d ago`;
};
const byNewest = <T extends { createdAt: string }>(a: T, b: T) => Date.parse(b.createdAt) - Date.parse(a.createdAt);
const sparkOf = (bad: boolean[]) => {
  const s = bad.slice(-12).map((b) => (b ? 0.9 : 0.05));
  return s.length >= 2 ? s : [s[0] ?? 0.5, s[0] ?? 0.5];
};

type Patch = Partial<Pick<TwinNode, "state" | "score" | "reasons" | "spark" | "links" | "live">>;
type Verdict = Patch & Pick<TwinNode, "state" | "reasons">;

/** Health of one workflow from its runs on the default branch. */
export function workflowHealth(runs: RunSignal[], defaultBranch: string, now: number): Verdict {
  const mine = runs.filter((r) => r.branch === defaultBranch).sort(byNewest);
  const done = mine.filter(counted);
  const live = mine.some((r) => r.status === "in_progress" || r.status === "queued");
  if (!done.length) {
    return { state: "unknown", live, reasons: [live ? "First run in progress" : `No finished runs on ${defaultBranch} yet`] };
  }
  const recent = done.slice(0, WINDOW);
  const latest = recent[0];
  const passRate = recent.filter((r) => !isFail(r)).length / recent.length;
  const flaky = recent.some((r) => {
    const sameSha = recent.filter((o) => o.sha === r.sha);
    return sameSha.some((o) => isFail(o)) && sameSha.some((o) => !isFail(o));
  });
  const stale = now - Date.parse(latest.createdAt) > STALE_DAYS * DAY;

  const state: Status = isFail(latest) ? "failing" : flaky || passRate < 0.8 ? "degraded" : "nominal";
  const score = isFail(latest) ? Math.min(0.4, passRate * 0.5) : Math.max(0.5, 0.6 + 0.4 * passRate - (flaky ? 0.15 : 0));

  const reasons: string[] = [];
  const links: NonNullable<TwinNode["links"]> = [{ label: `Run #${latest.id} · ${short(latest.sha)}`, url: latest.url, ok: !isFail(latest) }];
  if (live) reasons.push("Running now");
  if (isFail(latest)) {
    reasons.push(`Latest run failed on ${defaultBranch} (${short(latest.sha)}, ${ago(latest.createdAt, now)})`);
    for (const j of latest.jobs?.filter((j) => FAILED.has(j.conclusion ?? "")) ?? []) {
      reasons.push(j.failedStep ? `${j.name}: step "${j.failedStep}" failed` : `${j.name} failed`);
      links.push({ label: j.name, url: j.url, ok: false });
    }
  }
  if (flaky) reasons.push("Flaky: the same commit both passed and failed");
  if (passRate < 0.8) reasons.push(`Passed ${recent.filter((r) => !isFail(r)).length} of ${recent.length} recent runs`);
  if (stale) reasons.push(`No runs in ${Math.round((now - Date.parse(latest.createdAt)) / DAY)} days`);
  return { state, score, reasons, links, live, spark: sparkOf([...recent].reverse().map(isFail)) };
}

const jobMatches = (node: TwinNode, j: JobSignal) => j.name === node.label || j.name.startsWith(`${node.label} (`); // matrix jobs: "test (ubuntu)"

/** Health of one job from the jobs of its workflow's latest finished run. */
export function jobHealth(node: TwinNode, jobs: JobSignal[]): Patch | null {
  const hits = jobs.filter((j) => jobMatches(node, j));
  if (!hits.length) return null;
  const bad = hits.filter((j) => FAILED.has(j.conclusion ?? ""));
  if (bad.length) {
    const j = bad[0];
    return {
      state: "failing", score: 0.15, spark: sparkOf([true]),
      reasons: [j.failedStep ? `Step "${j.failedStep}" failed` : "Job failed", ...(bad.length > 1 ? [`${bad.length} of ${hits.length} matrix legs failed`] : [])],
      links: [{ label: j.name, url: j.url, ok: false }],
    };
  }
  if (hits.every((j) => j.conclusion === "success")) return { state: "nominal", score: 0.97, spark: sparkOf([false]), reasons: [], links: [{ label: hits[0].name, url: hits[0].url, ok: true }] };
  return null; // skipped / cancelled / still running: no signal
}

export function envHealth(deploys: DeploySignal[], now: number): Verdict {
  const mine = [...deploys].sort(byNewest);
  const live = mine.some((d) => d.state === "in_progress" || d.state === "queued" || d.state === "pending");
  const done = mine.filter((d) => d.state === "success" || d.state === "failure" || d.state === "error").slice(0, WINDOW);
  if (!done.length) return { state: "unknown", live, reasons: [live ? "First deployment in progress" : "No finished deployments yet"] };
  const bad = (d: DeploySignal) => d.state !== "success";
  const latest = done[0];
  const rate = done.filter((d) => !bad(d)).length / done.length;
  const state: Status = bad(latest) ? "failing" : rate < 0.7 ? "degraded" : "nominal";
  const reasons: string[] = [];
  if (live) reasons.push("Deploying now");
  if (bad(latest)) reasons.push(`Latest deploy ${latest.state === "error" ? "errored" : "failed"} (${short(latest.sha)}, ${ago(latest.createdAt, now)})`);
  if (rate < 0.7) reasons.push(`${done.filter((d) => !bad(d)).length} of ${done.length} recent deploys succeeded`);
  return {
    state, live, reasons, score: bad(latest) ? Math.min(0.4, rate * 0.5) : 0.6 + 0.4 * rate,
    spark: sparkOf([...done].reverse().map(bad)),
    links: [{ label: `Deploy ${short(latest.sha)}`, url: latest.url, ok: !bad(latest) }],
  };
}

const SOURCE_NAME: Record<string, string> = { otlp: "OTel", sentry: "Sentry", vercel: "Vercel" };
const RANK: Record<Status, number> = { failing: 3, degraded: 2, nominal: 1, unknown: 0 };

/** Runtime verdicts per node: every mapped (source, service) series, worst one wins, reasons from all unhealthy ones. */
function runtimePatches(signals: SignalSet, now: number, ids: Set<string>): Map<string, Verdict> {
  const out = new Map<string, Verdict>();
  const series = new Map<string, RuntimeBucket[]>();
  for (const b of signals.runtime ?? []) { const k = `${b.source}:${b.key}`; (series.get(k) ?? series.set(k, []).get(k)!).push(b); }
  for (const [key, nodeId] of Object.entries(signals.mappings ?? {})) {
    if (!ids.has(nodeId)) continue;
    const v = runtimeHealth(series.get(key) ?? [], now);
    if (!v) continue;
    const prev = out.get(nodeId);
    const label = SOURCE_NAME[key.split(":")[0]] ?? key.split(":")[0];
    const reasons = v.reasons.map((r) => (v.state === "nominal" ? r : `${r} · ${label}`));
    if (!prev) out.set(nodeId, { state: v.state, score: v.score, reasons, spark: v.spark, links: v.links });
    else out.set(nodeId, {
      state: RANK[v.state] > RANK[prev.state] ? v.state : prev.state, score: Math.min(prev.score ?? 1, v.score),
      reasons: [...prev.reasons, ...reasons], spark: RANK[v.state] > RANK[prev.state] ? v.spark : prev.spark, links: [...(prev.links ?? []), ...v.links],
    });
  }
  return out;
}

/**
 * Pure: graph + signals + clock => graph with live health. Safe to re-run on every update; the same inputs always give the same output.
 * Nodes with no matching signal stay "unknown" (never guessed green).
 */
export function applyHealth(graph: TwinGraph, signals: SignalSet, now = Date.now()): TwinGraph {
  const hasKids = new Set(graph.nodes.map((n) => n.parentId).filter(Boolean));
  const own = new Map<string, Patch>();
  const nodes = graph.nodes.map((n) => ({ ...n }));
  const runtime = runtimePatches(signals, now, new Set(nodes.map((n) => n.id)));

  for (const n of nodes) {
    let patch: Patch | null = null;
    if (n.id.startsWith("wf:")) {
      const path = n.id.slice(3);
      patch = workflowHealth(signals.runs.filter((r) => r.workflowPath === path), signals.defaultBranch, now);
    } else if (n.id.startsWith("job:")) {
      const wfPath = n.id.slice(4).split(":")[0];
      const latestDone = signals.runs.filter((r) => r.workflowPath === wfPath && r.branch === signals.defaultBranch && counted(r) && r.jobs).sort(byNewest)[0];
      patch = latestDone?.jobs ? jobHealth(n, latestDone.jobs) : null;
    } else if (n.id.startsWith("env:")) {
      const deploys = signals.deploys.filter((d) => `env:${slug(d.environment)}` === n.id);
      if (deploys.length) patch = envHealth(deploys, now);
    }
    const rt = runtime.get(n.id);
    if (rt) {
      // GitHub and runtime both speak about this node: the worse one decides, and both explain themselves
      if (!patch || patch.state === "unknown" || RANK[rt.state] >= RANK[patch.state ?? "unknown"]) {
        patch = { ...rt, reasons: [...rt.reasons, ...(patch?.reasons ?? [])], links: [...(rt.links ?? []), ...(patch?.links ?? [])], live: patch?.live };
      } else patch = { ...patch, reasons: [...(patch.reasons ?? []), ...rt.reasons], links: [...(patch.links ?? []), ...(rt.links ?? [])] };
    }
    if (patch) { own.set(n.id, patch); Object.assign(n, patch); }
    else if (!hasKids.has(n.id)) { n.state = "unknown"; n.score = 0.5; n.reasons = []; n.spark = n.spark.length ? n.spark : [0.5, 0.5]; n.links = undefined; n.live = undefined; }
    if (hasKids.has(n.id)) n.reasons = []; // parents are re-derived from children below
  }

  const rolled = rollup(nodes).map((n) => {
    const mine = own.get(n.id);
    // a workflow whose jobs gave no signal keeps what its own runs say
    if (mine && n.state === "unknown" && mine.state !== "unknown") return { ...n, ...mine };
    // a workflow's own run-level reasons and links (with run URLs) beat synthesised ones
    if (mine && hasKids.has(n.id) && mine.reasons?.length) return { ...n, reasons: mine.reasons, links: mine.links, live: mine.live };
    return n;
  });

  // roll the "live" flag up so an L0 block pulses when anything inside it is running
  const byId = new Map(rolled.map((n) => [n.id, n]));
  for (const n of rolled) if (n.live) for (let p = n.parentId; p; p = byId.get(p)?.parentId) { const pn = byId.get(p); if (pn) pn.live = true; }

  const failingNode = new Set(rolled.filter((n) => n.state === "failing").map((n) => n.id));
  const edges = graph.edges.map((e) => ({ ...e, errorRate: failingNode.has(e.from) ? 0.4 : 0 }));
  const hoursAgo = (iso: string) => Math.max(0, (now - Date.parse(iso)) / 3_600_000);
  let deploys: DeployMarker[] = signals.deploys
    .filter((d) => d.state === "success" || d.state === "failure" || d.state === "error")
    .map((d) => ({ hoursAgo: hoursAgo(d.createdAt), label: `${d.environment} ${short(d.sha)}`, ok: d.state === "success" }));
  // most repos never use the Deployments API; their "deploy" is a workflow named deploy / release / publish
  if (!deploys.length) {
    deploys = signals.runs
      .filter((r) => r.branch === signals.defaultBranch && counted(r) && DEPLOY_LIKE.test(`${r.workflowName} ${r.workflowPath}`))
      .map((r) => ({ hoursAgo: hoursAgo(r.createdAt), label: `${r.workflowName} ${short(r.sha)}`, ok: !isFail(r) }));
  }
  deploys = deploys.filter((d) => d.hoursAgo <= 48).sort((a, b) => a.hoursAgo - b.hoursAgo);

  const inFlight = [
    ...signals.runs.filter((r) => r.branch === signals.defaultBranch && r.status !== "completed").map((r) => ({ queued: r.status === "queued" || r.status === "waiting" || r.status === "pending", at: r.createdAt })),
    ...signals.deploys.filter((d) => ["in_progress", "queued", "pending"].includes(d.state)).map((d) => ({ queued: d.state !== "in_progress", at: d.createdAt })),
  ];
  const running = inFlight.filter((i) => !i.queued);
  const activity = {
    running: running.length, queued: inFlight.length - running.length,
    since: running.map((r) => r.at).sort()[0],
  };

  return { ...graph, nodes: rolled, edges, deploys, activity };
}
