import { z } from "zod";
import type { TwinGraph } from "./types";

/**
 * "Correct this node": human edits that win over the analysis and survive re-scans. They are keyed by node id, which is
 * derived from what the node is (path/name), so an override keeps applying for as long as that thing exists, and
 * quietly does nothing once it is gone.
 */
export const OverrideSchema = z.object({
  label: z.string().trim().min(1).max(80).optional(),
  summary: z.string().trim().min(1).max(400).optional(),
  /** drop a false positive (and everything nested in it) from the map */
  hidden: z.boolean().optional(),
});
export type Override = z.infer<typeof OverrideSchema>;

export const OverridesSchema = z.record(z.string().max(300), OverrideSchema).refine((o) => Object.keys(o).length <= 500, "too many overrides");
export type Overrides = z.infer<typeof OverridesSchema>;

/** Pure. Renames/re-describes nodes, removes hidden ones with their descendants, and drops edges that touch a removed node. */
export function applyOverrides(graph: TwinGraph, overrides: Overrides): TwinGraph {
  if (Object.keys(overrides).length === 0) return graph;
  const hidden = new Set<string>();
  const byParent = new Map<string, string[]>();
  for (const n of graph.nodes) if (n.parentId) (byParent.get(n.parentId) ?? byParent.set(n.parentId, []).get(n.parentId)!).push(n.id);
  const hide = (id: string) => {
    if (hidden.has(id)) return;
    hidden.add(id);
    for (const kid of byParent.get(id) ?? []) hide(kid);
  };
  for (const n of graph.nodes) if (overrides[n.id]?.hidden) hide(n.id);

  return {
    ...graph,
    nodes: graph.nodes
      .filter((n) => !hidden.has(n.id))
      .map((n) => {
        const o = overrides[n.id];
        return o && (o.label || o.summary) ? { ...n, ...(o.label ? { label: o.label } : {}), ...(o.summary ? { summary: o.summary } : {}) } : n;
      }),
    edges: graph.edges.filter((e) => !hidden.has(e.from) && !hidden.has(e.to)),
  };
}

/** Merge one node's edit into the set; an edit that says nothing removes the entry. */
export function setOverride(all: Overrides, id: string, o: Override): Overrides {
  const next = { ...all };
  const clean: Override = {};
  if (o.label) clean.label = o.label;
  if (o.summary) clean.summary = o.summary;
  if (o.hidden) clean.hidden = true;
  if (Object.keys(clean).length) next[id] = clean; else delete next[id];
  return next;
}
