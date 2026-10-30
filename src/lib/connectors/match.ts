import { rankNodes } from "@/lib/ask/query";
import type { TwinGraph, TwinNode } from "@/lib/graph/types";
import type { Target } from "./types";

export interface Proposal {
  /** "source:key", the mapping key the engine reads */
  id: string;
  target: Target;
  nodeId: string;
  nodeLabel: string;
  confidence: "high" | "medium" | "low";
  /** the user already confirmed this one */
  confirmed: boolean;
}

/** Things a running service can plausibly be: not files, endpoints or workflow jobs. */
const MAPPABLE = new Set<TwinNode["kind"]>(["service", "package", "datastore", "external", "queue", "env"]);

/**
 * Auto-match tools' services to nodes by name. Proposals only: nothing is used until the user confirms it once.
 * Two targets never silently share a node unless the user says so.
 */
export function proposeMappings(graph: TwinGraph, targets: Target[], confirmed: Record<string, string> = {}): Proposal[] {
  const live = new Set(graph.nodes.map((n) => n.id));
  const out: Proposal[] = [];
  for (const t of targets) {
    const id = `${t.source}:${t.key}`;
    const known = confirmed[id];
    if (known && live.has(known)) { out.push({ id, target: t, nodeId: known, nodeLabel: graph.nodes.find((n) => n.id === known)!.label, confidence: "high", confirmed: true }); continue; }
    const best = [...rankNodes(graph, `${t.key} ${t.name}`.trim(), 20), ...rankNodes(graph, t.key, 20)]
      .filter((r) => MAPPABLE.has(r.node.kind))
      .sort((a, b) => b.score - a.score || a.node.level - b.node.level)[0];
    if (!best) continue;
    out.push({ id, target: t, nodeId: best.node.id, nodeLabel: best.node.label, confidence: best.score >= 100 ? "high" : best.score >= 80 ? "medium" : "low", confirmed: false });
  }
  return out;
}
