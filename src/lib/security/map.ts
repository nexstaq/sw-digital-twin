import type { TwinGraph, TwinNode } from "@/lib/graph/types";
import { SEVERITIES, SEVERITY_RANK, SEVERITY_WEIGHT, worse, type Category, type Finding, type Severity } from "./types";

const dirOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
/** Nodes that OWN code: a package or service. A datastore or external service merely cites a file as proof it is used. */
const OWNER_KINDS = new Set<TwinNode["kind"]>(["package", "service"]);
const MANIFEST = /(^|\/)(package(-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|requirements[^/]*\.txt|poetry\.lock|pyproject\.toml|Pipfile(\.lock)?|go\.(mod|sum)|Cargo\.(toml|lock))$/;

/**
 * The graph node a finding belongs to, or null.
 *  1. A node that cites that exact file. For a dependency manifest the OWNING package/service wins (the database and Stripe nodes
 *     also cite package.json, but a vulnerable library is the package's problem); otherwise the deepest (a job beats its
 *     workflow beats its block).
 *  2. Otherwise the package/service whose folder encloses the file (code belongs to the package that contains it).
 *  3. Otherwise any node whose cited file is in an enclosing folder.
 */
export function nodeFor(graph: TwinGraph, f: Pick<Finding, "path">): string | null {
  if (/^https?:\/\//.test(f.path) || f.path.startsWith("(")) return null; // a live-test URL, or "location not provided": not a file in the repository
  const fileDir = dirOf(f.path);
  const deepest = (a: TwinNode | null, n: TwinNode) => (!a || n.level > a.level ? n : a);
  let exact: TwinNode | null = null, exactOwner: TwinNode | null = null;
  let owner: { n: TwinNode; dirLen: number } | null = null, near: { n: TwinNode; dirLen: number } | null = null;
  for (const n of graph.nodes) {
    for (const e of n.evidence) {
      if (e.path === f.path) { exact = deepest(exact, n); if (OWNER_KINDS.has(n.kind)) exactOwner = deepest(exactOwner, n); continue; }
      const d = dirOf(e.path);
      if (!(d === "" || fileDir === d || fileDir.startsWith(`${d}/`))) continue;
      const better = (c: { n: TwinNode; dirLen: number } | null) => !c || d.length > c.dirLen || (d.length === c.dirLen && n.level > c.n.level);
      if (OWNER_KINDS.has(n.kind) && MANIFEST.test(e.path) && better(owner)) owner = { n, dirLen: d.length };
      if (better(near)) near = { n, dirLen: d.length };
    }
  }
  return ((MANIFEST.test(f.path) ? exactOwner : null) ?? exact ?? owner?.n ?? near?.n)?.id ?? null;
}

/** finding id -> node id (only those that found a home) */
export function mapFindings(graph: TwinGraph, findings: Finding[]): Map<string, string> {
  const m = new Map<string, string>();
  for (const f of findings) { const id = nodeFor(graph, f); if (id) m.set(f.id, id); }
  return m;
}

export interface NodeRisk { worst: Severity | null; counts: Record<Severity, number>; total: number }
const empty = (): NodeRisk => ({ worst: null, counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, total: 0 });

/** Per node, the findings in it AND in everything nested inside it, so a block glows if any part of it is at risk. */
export function rollup(graph: TwinGraph, findings: Finding[], map: Map<string, string>): Map<string, NodeRisk> {
  const parent = new Map(graph.nodes.map((n) => [n.id, n.parentId]));
  const out = new Map<string, NodeRisk>();
  for (const f of findings) {
    const home = map.get(f.id);
    if (!home) continue;
    const seen = new Set<string>();
    for (let id: string | undefined = home; id && !seen.has(id); id = parent.get(id)) {
      seen.add(id);
      const r = out.get(id) ?? out.set(id, empty()).get(id)!;
      r.counts[f.severity]++; r.total++; r.worst = worse(r.worst, f.severity);
    }
  }
  return out;
}

/** Ranking: severity, scaled down when the evidence says it is less likely to matter (low confidence, dev-only, never imported). */
export function priority(f: Finding): number {
  let p = SEVERITY_WEIGHT[f.severity];
  if (f.confidence === "low") p *= 0.5; else if (f.confidence === "medium") p *= 0.75;
  if (f.detail.dev) p *= 0.5;
  else if (f.category === "dependency" && !f.detail.direct && f.detail.usedIn?.length === 0) p *= 0.75;
  if (f.category === "dependency" && f.detail.usedIn?.length) p *= 1.25; // imported by your code: reachable
  return p;
}
export const byPriority = (a: Finding, b: Finding) => priority(b) - priority(a) || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.path.localeCompare(b.path) || (a.line ?? 0) - (b.line ?? 0);

export interface Posture {
  /** 0..100, higher is safer */
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  counts: Record<Severity, number>;
  byCategory: Record<Category, number>;
  total: number;
  /** one sentence a non-specialist can read */
  headline: string;
}

export function posture(findings: Finding[], scanned = true): Posture {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  const byCategory: Record<Category, number> = { dependency: 0, secret: 0, pipeline: 0, container: 0, code: 0, runtime: 0 };
  let penalty = 0;
  for (const f of findings) { counts[f.severity]++; byCategory[f.category]++; penalty += priority(f); }
  const score = Math.max(0, Math.round(100 - Math.min(100, penalty)));
  // a critical finding caps the grade no matter how much else is clean: one open door is enough
  const grade = counts.critical > 0 ? (score >= 60 ? "D" : "F") : score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  const headline = !scanned ? "Not scanned yet"
    : findings.length === 0 ? "Nothing found. That means these checks passed, not that the software is proven secure."
    : counts.critical ? `${counts.critical} critical issue${counts.critical > 1 ? "s" : ""} to fix first${counts.high ? `, then ${counts.high} high` : ""}`
    : counts.high ? `${counts.high} high-severity issue${counts.high > 1 ? "s" : ""} to fix`
    : `${findings.length} lower-severity issue${findings.length > 1 ? "s" : ""}`;
  return { score, grade, counts, byCategory, total: findings.length, headline };
}

const STATE: Record<Severity, TwinNode["state"]> = { critical: "failing", high: "failing", medium: "degraded", low: "nominal", info: "nominal" };

/**
 * The same map, coloured by security instead of health. The canvas needs no change: it already knows how to show
 * failing / degraded / nominal / unknown. Health-only decorations (run links, live pulse, deploy markers) are dropped.
 */
export function securityGraph(graph: TwinGraph, findings: Finding[], scanned: boolean): TwinGraph {
  const home = mapFindings(graph, findings);
  const risk = rollup(graph, findings, home);

  return {
    ...graph,
    deploys: [], activity: undefined,
    nodes: graph.nodes.map((n): TwinNode => {
      const r = risk.get(n.id);
      // a block leads with the worst thing anywhere inside it, not only what sits directly on the block
      const under = r?.total ? findingsUnder(graph, findings, home, n.id) : [];
      const top = under.slice(0, 3);
      const weight = r ? SEVERITIES.reduce((s, k) => s + r.counts[k] * SEVERITY_WEIGHT[k], 0) : 0;
      return {
        ...n, links: undefined, live: false, narrative: undefined,
        state: !scanned ? "unknown" : r?.worst ? STATE[r.worst] : "nominal",
        score: !scanned ? 0.5 : Math.max(0, 1 - Math.min(weight, 50) / 50),
        spark: [],
        reasons: !scanned ? ["Not scanned yet"]
          : r?.total ? [...top.map((f) => f.title), ...(under.length > top.length ? [`${under.length - top.length} more in this part`] : [])]
          : ["No findings in this part"],
      };
    }),
  };
}

/** Findings that live in `nodeId` or anywhere nested inside it, worst first. */
export function findingsUnder(graph: TwinGraph, findings: Finding[], home: Map<string, string>, nodeId: string): Finding[] {
  const parent = new Map(graph.nodes.map((n) => [n.id, n.parentId]));
  const inside = (id: string | undefined) => { for (const seen = new Set<string>(); id && !seen.has(id); id = parent.get(id)) { if (id === nodeId) return true; seen.add(id); } return false; };
  return findings.filter((f) => inside(home.get(f.id))).sort(byPriority);
}
