import type { SignalSet } from "./signals";

/**
 * The signals as they stood at time `t` (epoch ms): the basis of time travel. Pure, so replay is just
 * `applyHealth(graph, signalsAt(signals, t), t)`.
 *  - runs that had not started yet are removed; runs that finished after `t` were still in progress then
 *  - deployments after `t` are removed; runtime buckets after `t` are removed
 */
export function signalsAt(s: SignalSet, t: number): SignalSet {
  return {
    ...s,
    fetchedAt: t,
    runs: s.runs
      .filter((r) => Date.parse(r.createdAt) <= t)
      .map((r) => {
        const done = Date.parse(r.completedAt ?? r.createdAt);
        return r.status !== "completed" || done <= t ? r : { ...r, status: "in_progress", conclusion: null, jobs: undefined };
      }),
    deploys: s.deploys.filter((d) => Date.parse(d.createdAt) <= t),
    runtime: s.runtime?.filter((b) => b.ts <= t),
  };
}
