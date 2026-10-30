import type { Narrative, TourStep, TwinGraph } from "@/lib/graph/types";
import type { LlmNarrative } from "./schema";
import type { Ref } from "./prompt";

const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1).trimEnd()}…` : s);
const clean = (s: string) => s.replace(/\s+/g, " ").trim();

export interface Validated {
  narratives: Map<string, Narrative>;
  flow: string[];
  tour: TourStep[];
  headline: string;
  stats: { accepted: number; downgraded: number; dropped: number };
}

/**
 * The model may only describe what the graph can back up.
 *  - citations must be refs we sent, belonging to the node itself or one of its children
 *  - a node with no valid citation is dropped (the deterministic label stays)
 *  - a node with some invalid citations is kept but loses a confidence level
 * Unknown node ids, duplicate ids and over-long text are discarded or trimmed.
 */
export function validate(out: LlmNarrative, graph: TwinGraph, refs: Map<string, Ref>): Validated {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const inSubtree = (id: string, root: string) => {
    for (let cur: string | undefined = id, i = 0; cur && i < 4; cur = byId.get(cur)?.parentId, i++) if (cur === root) return true;
    return false;
  };

  const narratives = new Map<string, Narrative>();
  const usedNames = new Set<string>();
  const stats = { accepted: 0, downgraded: 0, dropped: 0 };

  for (const item of out.nodes) {
    const node = byId.get(item.id);
    if (!node || narratives.has(item.id)) { stats.dropped++; continue; }

    const good: string[] = [];
    let bad = 0;
    for (const id of new Set(item.citations)) {
      const r = refs.get(id);
      if (r && inSubtree(r.nodeId, node.id)) good.push(`${r.path}${r.lines ? `:${r.lines}` : ""}`);
      else bad++;
    }
    if (good.length === 0) { stats.dropped++; continue; }

    let confidence = item.confidence;
    if (bad > 0) {
      confidence = confidence === "high" ? "medium" : "low";
      stats.downgraded++;
    } else stats.accepted++;

    let name = clip(clean(item.name), 40) || node.label;
    if (usedNames.has(name.toLowerCase())) name = node.label;
    usedNames.add(name.toLowerCase());

    narratives.set(item.id, {
      name, purpose: clip(clean(item.purpose), 160), exec: clip(clean(item.exec), 360),
      engineer: clip(clean(item.engineer), 360), security: clip(clean(item.security), 360),
      confidence, citations: good.slice(0, 5),
    });
  }

  const l0 = graph.nodes.filter((n) => n.level === 0).map((n) => n.id);
  const flow = [...new Set(out.flow.filter((id) => l0.includes(id)))];
  for (const id of l0) if (!flow.includes(id)) flow.push(id);
  flow.forEach((id, i) => { const nar = narratives.get(id); if (nar) nar.order = i; });

  const seen = new Set<string>();
  const tour: TourStep[] = [];
  for (const s of out.tour) {
    if (!l0.includes(s.nodeId) || seen.has(s.nodeId)) continue;
    seen.add(s.nodeId);
    tour.push({ nodeId: s.nodeId, title: clip(clean(s.title), 60), caption: clip(clean(s.caption), 280) });
  }

  return { narratives, flow, tour, headline: clip(clean(out.headline), 200), stats };
}
