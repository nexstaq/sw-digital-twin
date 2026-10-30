import type { Story, TourStep, TwinGraph, TwinNode } from "@/lib/graph/types";

const KIND_RANK: Record<string, number> = { job: 0, env: 0, service: 1, package: 2, endpoint: 1, datastore: 3, queue: 3, external: 4, file: 1 };

/** Left-to-right order from the links (delivery before what it ships, callers before what they call), ties by kind. */
export function flowOrder(graph: TwinGraph): string[] {
  const l0 = graph.nodes.filter((n) => n.level === 0);
  const ids = new Set(l0.map((n) => n.id));
  const indeg = new Map(l0.map((n) => [n.id, 0]));
  const out = new Map<string, string[]>();
  for (const e of graph.edges) {
    if (!ids.has(e.from) || !ids.has(e.to)) continue;
    // dependency edges point from user to used; flow reads user first, so keep direction as drawn
    out.set(e.from, [...(out.get(e.from) ?? []), e.to]);
    indeg.set(e.to, (indeg.get(e.to) ?? 0) + 1);
  }
  const rank = (id: string) => KIND_RANK[l0.find((n) => n.id === id)!.kind] ?? 2;
  const ready = l0.filter((n) => indeg.get(n.id) === 0).map((n) => n.id).sort((a, b) => rank(a) - rank(b));
  const order: string[] = [];
  while (ready.length) {
    const id = ready.shift()!;
    order.push(id);
    for (const t of out.get(id) ?? []) {
      indeg.set(t, indeg.get(t)! - 1);
      if (indeg.get(t) === 0) { ready.push(t); ready.sort((a, b) => rank(a) - rank(b)); }
    }
  }
  for (const n of l0) if (!order.includes(n.id)) order.push(n.id); // cycles
  return order;
}

const describe = (n: TwinNode, graph: TwinGraph) => {
  const kids = graph.nodes.filter((k) => k.parentId === n.id).length;
  return `${n.summary}${kids ? ` It has ${kids} inner part${kids === 1 ? "" : "s"} you can open.` : ""}`;
};

/** Tour that needs no model: one step per top-level node, in flow order, captions from the analysis. */
export function ruleStory(graph: TwinGraph): Story {
  const order = flowOrder(graph);
  const tour: TourStep[] = order.slice(0, 10).map((id) => {
    const n = graph.nodes.find((x) => x.id === id)!;
    return { nodeId: id, title: n.narrative?.name ?? n.label, caption: n.narrative?.exec ?? describe(n, graph) };
  });
  const l0 = graph.nodes.filter((n) => n.level === 0).length;
  return { headline: `${graph.repo}: ${l0} main building block${l0 === 1 ? "" : "s"}.`, source: "rules", tour };
}
