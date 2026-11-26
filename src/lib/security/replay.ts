import type { TwinGraph } from "@/lib/graph/types";
import { mapFindings } from "./map";
import type { Finding, FindingSet } from "./types";

/**
 * Turns a scan's red-team reachability verdicts and the blue observer's full coverage (not just the misses that also became
 * findings) into one ordered, replayable list. Pure, so the Simulation page can replay it without re-running anything, and
 * so it is testable without a live range.
 */
export interface ReplayStep {
  id: string;
  kind: "reachability" | "detection";
  /** "crown": a reachability path that reaches a protected data store. "path": one that does not. "detected"/"missed": whether the health engine would have noticed. */
  icon: "crown" | "path" | "detected" | "missed";
  title: string;
  detail: string;
  /** node ids to highlight on the map, focus (the entry point) first */
  nodeIds: string[];
}

type Coverage = NonNullable<NonNullable<FindingSet["simulated"]>["blue"]>["coverage"][number];

export function buildReplaySteps(graph: TwinGraph, findings: readonly Finding[], coverage: readonly Coverage[] = []): ReplayStep[] {
  const home = mapFindings(graph, findings as Finding[]);
  const byLabel = new Map(graph.nodes.map((n) => [n.label, n.id]));
  const steps: ReplayStep[] = [];

  for (const f of findings) {
    if (f.simulation?.by !== "redteam") continue;
    const entry = home.get(f.id);
    const reached = f.simulation.reaches.map((l) => byLabel.get(l)).filter((x): x is string => !!x && x !== entry);
    steps.push({
      id: f.id, kind: "reachability", icon: f.simulation.confidence === "medium" ? "crown" : "path",
      title: f.title, detail: f.simulation.summary, nodeIds: [...(entry ? [entry] : []), ...reached],
    });
  }
  for (const c of coverage) {
    if (c.outcome === "not-tried") continue;
    steps.push({
      id: `blue:${c.nodeId}:${c.kind}`, kind: "detection", icon: c.outcome, nodeIds: graph.nodes.some((n) => n.id === c.nodeId) ? [c.nodeId] : [],
      title: `${c.outcome === "detected" ? "Noticed" : "Not noticed"}: ${c.kind === "read-amplification" ? "a flood of reads on" : c.kind} ${c.label}`,
      detail: c.outcome === "detected" ? `The health engine caught this, about ${Math.round((c.timeToDetectMs ?? 0) / 60_000)} minute(s) after.` : (c.suggestion ?? "The health engine did not catch this."),
    });
  }
  return steps;
}
