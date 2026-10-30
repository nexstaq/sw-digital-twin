import type { TwinEdge } from "./types";

/** Edge kinds where `from` needs `to` to work: if `to` fails, `from` suffers. */
const DEPENDENCY: ReadonlySet<TwinEdge["kind"]> = new Set(["calls", "reads", "depends_on"]);

export interface Impact {
  nodes: Set<string>;
  edges: Set<string>;
}

/**
 * "What breaks if `id` fails?" Walks the given edges (one level of the graph).
 *  - calls/reads/depends_on: callers are impacted (walk against the arrow).
 *  - triggers/deploys_to/publishes: downstream is impacted (walk with the arrow).
 * The failing node itself is not included in `nodes`.
 */
export function blastRadius(edges: TwinEdge[], id: string): Impact {
  const nodes = new Set<string>();
  const hit = new Set<string>();
  const queue = [id];
  const seen = new Set([id]);

  while (queue.length) {
    const cur = queue.shift()!;
    for (const e of edges) {
      const next = DEPENDENCY.has(e.kind) ? (e.to === cur ? e.from : null) : e.from === cur ? e.to : null;
      if (!next) continue;
      hit.add(e.id);
      if (seen.has(next)) continue;
      seen.add(next);
      nodes.add(next);
      queue.push(next);
    }
  }
  return { nodes, edges: hit };
}
