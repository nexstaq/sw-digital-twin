import { impactOf } from "@/lib/ask/query";
import { ancestry } from "@/lib/graph/nav";
import type { Status, TwinGraph } from "@/lib/graph/types";
import { applyHealth } from "./engine";
import { signalsAt } from "./at";
import type { SignalSet } from "./signals";

export interface Frame {
  ts: number;
  states: Record<string, Status>;
  /** first reason for every unhealthy node */
  why: Record<string, string>;
}

/** Health of the whole map at evenly spaced moments. Same pure engine as live; only the clock moves. */
export function sampleFrames(graph: TwinGraph, signals: SignalSet, o: { to?: number; hours?: number; stepMs?: number } = {}): Frame[] {
  const { to = Date.now(), hours = 48, stepMs = 10 * 60_000 } = o;
  const frames: Frame[] = [];
  for (let ts = to - hours * 3_600_000; ts <= to; ts += stepMs) {
    const g = applyHealth(graph, signalsAt(signals, ts), ts);
    const states: Record<string, Status> = {};
    const why: Record<string, string> = {};
    for (const n of g.nodes) { states[n.id] = n.state; if ((n.state === "failing" || n.state === "degraded") && n.reasons[0]) why[n.id] = n.reasons[0]; }
    frames.push({ ts, states, why });
  }
  return frames;
}

export interface IncidentStep { nodeId: string; ts: number; state: "failing" | "degraded"; reason?: string }
export interface Incident {
  startTs: number;
  /** when everything recovered; undefined while it is still going on */
  endTs?: number;
  first: IncidentStep;
  /** every part that went bad, in the order it did */
  sequence: IncidentStep[];
  /** the subset of `sequence` that depends on `first`: how the failure travelled */
  path: IncidentStep[];
  worst: "failing" | "degraded";
}

const bad = (s: Status | undefined) => s === "failing" || s === "degraded";

/**
 * Finds the most serious incident in the frames: the stretch where a top-level block was unhealthy, the part that
 * went bad FIRST (patient zero), and the order the rest followed. Chronic problems (bad for nearly the whole window)
 * are not incidents and are ignored, otherwise one flaky job would hide everything else.
 */
export function findIncident(graph: TwinGraph, frames: Frame[]): Incident | null {
  if (frames.length < 3) return null;
  const hasKids = new Set(graph.nodes.map((n) => n.parentId).filter(Boolean) as string[]);
  const tops = graph.nodes.filter((n) => !n.parentId).map((n) => n.id);
  const leaves = graph.nodes.filter((n) => !hasKids.has(n.id)).map((n) => n.id);

  const chronic = new Set(leaves.filter((id) => frames.filter((f) => bad(f.states[id])).length >= frames.length * 0.9));
  const topBad = (f: Frame) => tops.some((id) => bad(f.states[id]) && !chronic.has(id)) && leaves.some((id) => bad(f.states[id]) && !chronic.has(id));

  // split into stretches of consecutive unhealthy frames
  const segs: [number, number][] = [];
  for (let i = 0; i < frames.length; i++) {
    if (!topBad(frames[i])) continue;
    let j = i;
    while (j + 1 < frames.length && topBad(frames[j + 1])) j++;
    segs.push([i, j]);
    i = j;
  }
  if (!segs.length) return null;

  const severity = ([a, b]: [number, number]) => Math.max(...frames.slice(a, b + 1).map((f) => leaves.filter((id) => f.states[id] === "failing" && !chronic.has(id)).length * 10 + leaves.filter((id) => f.states[id] === "degraded" && !chronic.has(id)).length));
  const [a, b] = segs.reduce((best, s) => (severity(s) >= severity(best) ? s : best));

  const firstSeen = new Map<string, IncidentStep>();
  const worst = new Map<string, "failing" | "degraded">();
  for (const f of frames.slice(a, b + 1)) {
    for (const id of leaves) {
      const st = f.states[id];
      if (!bad(st) || chronic.has(id)) continue;
      if (!firstSeen.has(id)) firstSeen.set(id, { nodeId: id, ts: f.ts, state: st as "failing" | "degraded", reason: f.why[id] });
      if (st === "failing") worst.set(id, "failing");
    }
  }
  const reach = new Map<string, number>();
  for (const id of firstSeen.keys()) reach.set(id, impactOf(graph, id).length);
  const sequence = [...firstSeen.values()]
    .map((s) => ({ ...s, state: worst.get(s.nodeId) ?? s.state }))
    .sort((x, y) => x.ts - y.ts || reach.get(y.nodeId)! - reach.get(x.nodeId)!);
  if (!sequence.length) return null;

  const first = sequence[0];
  // impact is computed per level, so a part one level down counts if any block containing it is downstream
  const downstream = new Set(impactOf(graph, first.nodeId));
  const dependsOnFirst = (id: string) => downstream.has(id) || ancestry(graph, id).some((a) => downstream.has(a));
  const path = sequence.filter((s) => s.nodeId === first.nodeId || dependsOnFirst(s.nodeId));
  return {
    startTs: frames[a].ts,
    endTs: b + 1 < frames.length ? frames[b + 1].ts : undefined,
    first, sequence, path,
    worst: sequence.some((s) => s.state === "failing") ? "failing" : "degraded",
  };
}
