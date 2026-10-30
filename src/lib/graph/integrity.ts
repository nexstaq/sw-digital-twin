import { GraphSchema } from "./schemas";
import type { TwinGraph } from "./types";

/**
 * Structural validation beyond what Zod can express: referential integrity,
 * level consistency, and the "every claim has evidence" rule.
 * Returns human-readable problems; empty means the graph is sound.
 */
export function validateGraph(input: unknown): string[] {
  const parsed = GraphSchema.safeParse(input);
  if (!parsed.success) return parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`);

  const g: TwinGraph = parsed.data;
  const problems: string[] = [];
  const byId = new Map(g.nodes.map((n) => [n.id, n]));
  if (byId.size !== g.nodes.length) problems.push("duplicate node ids");

  for (const n of g.nodes) {
    if (n.level === 0 && n.parentId) problems.push(`${n.id}: level 0 node has a parent`);
    if (n.level > 0) {
      const p = n.parentId ? byId.get(n.parentId) : undefined;
      if (!p) problems.push(`${n.id}: parent "${n.parentId}" not found`);
      else if (p.level !== n.level - 1) problems.push(`${n.id}: level ${n.level} but parent is level ${p.level}`);
    }
    if (n.evidence.length === 0) problems.push(`${n.id}: no evidence`);
  }
  for (const e of g.edges) {
    const a = byId.get(e.from);
    const b = byId.get(e.to);
    if (!a || !b) problems.push(`${e.id}: dangling endpoint`);
    else if (a.parentId !== b.parentId) problems.push(`${e.id}: connects nodes with different parents`);
  }
  return problems;
}
