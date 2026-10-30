import { z } from "zod";
import type { TwinGraph, TwinNode } from "@/lib/graph/types";

/**
 * The graph lives in the browser, so questions send a compact digest. It carries names, health and structure only:
 * no source code, no evidence paths. The server rebuilds a TwinGraph from it to reuse the same graph functions.
 */
const MAX_NODES = 1500;
const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

export const DigestSchema = z.object({
  repo: z.string().max(200),
  nodes: z.array(z.object({
    id: z.string().max(300), level: z.union([z.literal(0), z.literal(1), z.literal(2)]), parentId: z.string().max(300).optional(),
    kind: z.enum(["service", "job", "package", "datastore", "queue", "external", "endpoint", "file", "env"]),
    label: z.string().max(200), name: z.string().max(200).optional(), summary: z.string().max(300),
    state: z.enum(["nominal", "degraded", "failing", "unknown"]), reasons: z.array(z.string().max(300)).max(4),
    owners: z.array(z.string().max(100)).max(5).optional(), criticality: z.union([z.literal(1), z.literal(2), z.literal(3)]),
  })).max(MAX_NODES),
  edges: z.array(z.object({ id: z.string().max(300), from: z.string().max(300), to: z.string().max(300), kind: z.enum(["calls", "triggers", "deploys_to", "depends_on", "publishes", "reads"]) })).max(MAX_NODES * 4),
  deploys: z.array(z.object({ hoursAgo: z.number(), label: z.string().max(200), ok: z.boolean() })).max(60),
});
export type Digest = z.infer<typeof DigestSchema>;

export function toDigest(g: TwinGraph): Digest {
  return {
    repo: g.repo,
    nodes: g.nodes.slice(0, MAX_NODES).map((n) => ({
      id: n.id, level: n.level, parentId: n.parentId, kind: n.kind, label: n.label, name: n.narrative?.name,
      summary: clip(n.summary, 200), state: n.state, reasons: n.reasons.slice(0, 3).map((r) => clip(r, 200)), owners: n.owners?.slice(0, 5), criticality: n.criticality,
    })),
    edges: g.edges.slice(0, MAX_NODES * 4).map((e) => ({ id: e.id, from: e.from, to: e.to, kind: e.kind })),
    deploys: g.deploys.slice(0, 60),
  };
}

export function fromDigest(d: Digest): TwinGraph {
  const ids = new Set(d.nodes.map((n) => n.id));
  return {
    repo: d.repo, deploys: d.deploys,
    nodes: d.nodes.map((n): TwinNode => ({
      id: n.id, level: n.level, parentId: n.parentId && ids.has(n.parentId) ? n.parentId : undefined, kind: n.kind, label: n.label, summary: n.summary,
      state: n.state, score: 0.5, spark: [], reasons: n.reasons, evidence: [], owners: n.owners, criticality: n.criticality,
      narrative: n.name ? { name: n.name, purpose: "", exec: "", engineer: "", security: "", confidence: "low", citations: [] } : undefined,
    })),
    edges: d.edges.filter((e) => ids.has(e.from) && ids.has(e.to)).map((e) => ({ ...e, throughput: 0.5, errorRate: 0 })),
  };
}
