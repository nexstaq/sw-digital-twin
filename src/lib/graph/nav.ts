import type { TwinGraph, TwinNode } from "./types";

/** Zoom path that shows `id` among its siblings: the ids of its ancestors, root first. */
export function ancestry(graph: TwinGraph, id: string): string[] {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const out: string[] = [];
  const seen = new Set([id]);
  for (let p = byId.get(id)?.parentId; p && !seen.has(p); p = byId.get(p)?.parentId) { out.unshift(p); seen.add(p); }
  return out;
}

/** Deepest unhealthy nodes: the culprits, not the blocks that merely contain them. Failing first, then degraded. */
export function culprits(graph: TwinGraph, states: TwinNode["state"][] = ["failing", "degraded"]): TwinNode[] {
  const bad = new Set(states);
  const hasBadKid = new Set<string>();
  for (const n of graph.nodes) if (bad.has(n.state) && n.parentId) hasBadKid.add(n.parentId);
  return graph.nodes
    .filter((n) => bad.has(n.state) && !hasBadKid.has(n.id))
    .sort((a, b) => states.indexOf(a.state) - states.indexOf(b.state) || b.criticality - a.criticality || a.level - b.level);
}
