import { rollup } from "@/lib/graph/rollup";
import type { Evidence, TwinEdge, TwinGraph, TwinNode } from "@/lib/graph/types";
import type { Group, RawEdge, RawGraph, RawNode } from "./types";
import { globToRegExp } from "./util";

const CLUSTERS: Record<Exclude<Group, "service">, { id: string; label: string; summary: string; kind: TwinNode["kind"] }> = {
  ci: { id: "cl:ci", label: "CI/CD pipelines", summary: "Workflows that build, test and ship the code.", kind: "job" },
  infra: { id: "cl:infra", label: "Infrastructure", summary: "Containers, orchestration and cloud resources that run the system.", kind: "env" },
  data: { id: "cl:data", label: "Data & messaging", summary: "Databases, caches, object storage and queues.", kind: "datastore" },
  external: { id: "cl:external", label: "External services", summary: "Third-party services this code depends on.", kind: "external" },
};

const MAX_DEPTH = 2;
const MAX_L1_PER_PARENT = 60;

/** Merge duplicate raw nodes (same id) from different detectors: first non-empty wins, evidence unions. */
export function mergeRaw(parts: Partial<RawGraph>[]): RawGraph {
  const byId = new Map<string, RawNode>();
  const edges = new Map<string, RawEdge>();
  for (const p of parts) {
    for (const n of p.nodes ?? []) {
      const prev = byId.get(n.id);
      if (!prev) { byId.set(n.id, { ...n, evidence: [...n.evidence] }); continue; }
      const seen = new Set(prev.evidence.map((e) => `${e.path}:${e.lines ?? ""}`));
      for (const e of n.evidence) if (!seen.has(`${e.path}:${e.lines ?? ""}`) && prev.evidence.length < 5) prev.evidence.push(e);
      prev.parent ??= n.parent;
    }
    for (const e of p.edges ?? []) edges.set(`${e.from}>${e.to}>${e.kind}`, e);
  }
  return { nodes: [...byId.values()], edges: [...edges.values()] };
}

/** CODEOWNERS: last matching rule wins. */
export function parseCodeowners(text: string): { re: RegExp; owners: string[] }[] {
  return text.split("\n").map((l) => l.replace(/#.*/, "").trim()).filter(Boolean).map((l) => {
    const [pat, ...owners] = l.split(/\s+/);
    return { re: globToRegExp(pat), owners };
  }).filter((r) => r.owners.length);
}

export function enrich(nodes: RawNode[], opts: { codeowners?: string | null; churn?: Map<string, number> }) {
  const rules = opts.codeowners ? parseCodeowners(opts.codeowners) : [];
  const max = opts.churn ? Math.max(1, ...opts.churn.values()) : 1;
  for (const n of nodes) {
    const p = n.evidence[0]?.path;
    if (!p) continue;
    for (const r of rules) if (r.re.test(p)) n.owners = r.owners;
    const c = opts.churn?.get(p);
    // churn of a manifest says nothing about the component, so only credit nodes that ARE a source file or workflow
    if (c && c >= 5 && (n.kind === "file" || n.kind === "endpoint" || n.id.startsWith("wf:"))) {
      n.hotness = c / max;
      n.summary += ` This file changed in ${c} of the last 100 commits.`;
    }
  }
}

/**
 * Turns the raw hierarchy into the canonical L0/L1/L2 graph.
 *  - services are L0; ci/infra/data/external roots are grouped under one synthetic cluster each
 *  - anything deeper than L2 is dropped (counted by the caller via warnings)
 *  - edges between different parents are lifted to the nearest common-parent siblings
 *  - nothing here has live signal yet, so every node is "unknown"
 */
export function buildGraph(raw: RawGraph, repo: string): TwinGraph {
  const byId = new Map(raw.nodes.map((n) => [n.id, n]));
  const ancestors = (id: string) => { const chain: string[] = []; let cur: string | undefined = id; const guard = new Set<string>(); while (cur && !guard.has(cur)) { guard.add(cur); chain.unshift(cur); cur = byId.get(cur)?.parent; } return chain; };

  // synthetic clusters, only for groups that have content
  const usedGroups = new Set<Exclude<Group, "service">>();
  for (const n of raw.nodes) if (n.group !== "service" && !n.parent) usedGroups.add(n.group);
  const clusterEvidence = (g: Group): Evidence[] => {
    const ev = raw.nodes.filter((n) => n.group === g && !n.parent).flatMap((n) => n.evidence).slice(0, 3);
    return ev.length ? ev : [{ path: "." }];
  };

  const all: RawNode[] = [...raw.nodes];
  for (const g of usedGroups) {
    const c = CLUSTERS[g];
    all.push({ id: c.id, kind: c.kind, label: c.label, summary: c.summary, evidence: clusterEvidence(g), group: g });
  }
  const parentOf = (n: RawNode): string | undefined => {
    if (n.parent && byId.has(n.parent)) return n.parent;
    if (n.group === "service" || n.id === CLUSTERS[n.group].id) return undefined; // services and the clusters themselves are L0
    return CLUSTERS[n.group].id;
  };

  const pmap = new Map(all.map((n) => [n.id, n]));
  const depth = (id: string): number => { let d = 0; let cur = pmap.get(id); const guard = new Set<string>(); while (cur && !guard.has(cur.id)) { guard.add(cur.id); const p = parentOf(cur); if (!p) break; d++; cur = pmap.get(p); } return d; };

  // keep L0..L2, cap fan-out at L1 so one huge folder can't bury the map
  const kept: RawNode[] = [];
  const childCount = new Map<string, number>();
  for (const n of all) {
    const d = depth(n.id);
    if (d > MAX_DEPTH) continue;
    const p = parentOf(n);
    if (d === 1 && p) {
      const c = childCount.get(p) ?? 0;
      if (c >= MAX_L1_PER_PARENT) continue;
      childCount.set(p, c + 1);
    }
    kept.push(n);
  }
  const keptIds = new Set(kept.map((n) => n.id));
  const keptParent = (n: RawNode) => { const p = parentOf(n); return p && keptIds.has(p) ? p : undefined; };

  const nodes: TwinNode[] = kept
    .filter((n) => depth(n.id) === 0 || keptParent(n))
    .map((n) => {
      const level = depth(n.id) as 0 | 1 | 2;
      return {
        id: n.id, level, parentId: level === 0 ? undefined : keptParent(n), kind: n.kind, label: n.label, summary: n.summary,
        state: "unknown" as const, score: 0.5, spark: [], reasons: ["No health signal connected yet."],
        evidence: n.evidence.length ? n.evidence : [{ path: "." }], owners: n.owners, criticality: 2 as const,
      };
    });
  const finalIds = new Set(nodes.map((n) => n.id));
  const parentMap = new Map(nodes.map((n) => [n.id, n.parentId]));
  const chain = (id: string) => { const c: string[] = []; let cur: string | undefined = id; while (cur) { c.unshift(cur); cur = parentMap.get(cur); } return c; };

  // lift edges to sibling level
  const lifted = new Map<string, { from: string; to: string; kind: TwinEdge["kind"]; n: number }>();
  for (const e of raw.edges) {
    // an edge to a dropped (too-deep) node attaches to its nearest kept ancestor
    const keep = (id: string) => ancestors(id).reverse().find((x) => finalIds.has(x));
    const a = keep(e.from), b = keep(e.to);
    if (!a || !b || a === b) continue;
    const ca = chain(a), cb = chain(b);
    let i = 0;
    while (i < ca.length && i < cb.length && ca[i] === cb[i]) i++;
    if (i >= ca.length || i >= cb.length) continue; // one contains the other
    const key = `${ca[i]}>${cb[i]}>${e.kind}`;
    const prev = lifted.get(key);
    if (prev) prev.n++; else lifted.set(key, { from: ca[i], to: cb[i], kind: e.kind, n: 1 });
  }
  const edges: TwinEdge[] = [...lifted.values()].map((l, i) => ({
    id: `e${i}`, from: l.from, to: l.to, kind: l.kind, throughput: Math.min(1, 0.25 + 0.15 * l.n), errorRate: 0,
  }));

  // fallback so even an empty repo renders something truthful
  return { repo, nodes: rollup(nodes), edges, deploys: [] };
}
