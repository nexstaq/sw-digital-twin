import type { TwinGraph, TwinNode } from "@/lib/graph/types";
import { findingsUnder, priority } from "./map";
import { SEVERITY_RANK, worse, type Finding, type FindingSet, type Severity } from "./types";

export interface AttackPath {
  id: string;
  kind: "web" | "pipeline";
  /** node ids from the foothold to the asset, in order */
  nodes: string[];
  entry: string;
  target: string;
  /** the endpoints behind the foothold (web paths) */
  endpoints: number;
  /** of those, files that accept writes with no authentication check in sight */
  unauthenticated: number;
  findings: string[];
  worst: Severity | null;
  /** higher is worse; only for ordering */
  risk: number;
  /** plain-English bullets for a human */
  facts: string[];
}

/**
 * Edges an attacker can walk. From a public endpoint that means data and calls (`calls`, `reads`, `publishes`). `deploys_to` only
 * says where something is hosted, so it is NOT a route from an endpoint, but it IS what a compromised pipeline does.
 * `depends_on` is a build-time relation, never walked (it only adds exposure).
 */
const WEB_FLOW = new Set(["calls", "reads", "publishes"]);
const PIPELINE_FLOW = new Set(["triggers", "deploys_to", "calls"]);
const ASSET_KINDS = new Set<TwinNode["kind"]>(["datastore", "external", "queue", "env"]);
const MAX_DEPTH = 4;
const RISKY_PIPELINE_RULES = new Set(["GHA/pwn-request", "GHA/script-injection"]);

const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;

/**
 * Walks from where an outsider can knock (a service with public endpoints, or a pipeline an outsider can trigger) along the
 * map's real edges to the things worth stealing (datastores, external services, queues, environments), and adds up what is wrong
 * on the way. It answers "if this endpoint is abused, what can it reach?", which is what makes a finding urgent or not.
 *
 * It only reasons from edges the map actually contains, so a missing edge means a missing path, not a safe one.
 */
export function attackPaths(graph: TwinGraph, findings: Finding[], home: Map<string, string>, exposure?: FindingSet["exposure"]): AttackPath[] {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const parent = new Map(graph.nodes.map((n) => [n.id, n.parentId]));
  const kids = new Map<string, string[]>();
  for (const n of graph.nodes) if (n.parentId) (kids.get(n.parentId) ?? kids.set(n.parentId, []).get(n.parentId)!).push(n.id);
  const adjacency = (kinds: Set<string>) => {
    const m = new Map<string, { to: string; kind: string }[]>();
    for (const e of graph.edges) if (kinds.has(e.kind)) (m.get(e.from) ?? m.set(e.from, []).get(e.from)!).push({ to: e.to, kind: e.kind });
    return m;
  };
  const webOut = adjacency(WEB_FLOW), pipeOut = adjacency(PIPELINE_FLOW);
  const dependsOn = new Map<string, string[]>();
  for (const e of graph.edges) if (e.kind === "depends_on") (dependsOn.get(e.from) ?? dependsOn.set(e.from, []).get(e.from)!).push(e.to);

  const descendants = (id: string): string[] => { const r: string[] = []; for (const stack = [...(kids.get(id) ?? [])]; stack.length; ) { const c = stack.pop()!; r.push(c); stack.push(...(kids.get(c) ?? [])); } return r; };
  const isAsset = (id: string) => ASSET_KINDS.has(byId.get(id)!.kind) || descendants(id).some((d) => ASSET_KINDS.has(byId.get(d)!.kind));
  const unauth = new Set(exposure?.unauthenticatedWrites ?? []);

  /** shortest flow path from `start` to each asset, depth-limited */
  const search = (start: string, out: Map<string, { to: string; kind: string }[]>) => {
    const prev = new Map<string, { from: string; kind: string }>();
    const depth = new Map([[start, 0]]);
    const found: string[] = [];
    for (const queue = [start]; queue.length; ) {
      const id = queue.shift()!;
      if (id !== start && isAsset(id)) { found.push(id); continue; } // reaching an asset ends that branch: it is the prize
      if ((depth.get(id) ?? 0) >= MAX_DEPTH) continue;
      for (const { to, kind } of out.get(id) ?? []) if (!depth.has(to) && byId.has(to)) { depth.set(to, (depth.get(id) ?? 0) + 1); prev.set(to, { from: id, kind }); queue.push(to); }
    }
    return found.map((t) => { const nodes = [t]; const kinds: string[] = []; for (let c = t; prev.has(c); c = prev.get(c)!.from) { nodes.unshift(prev.get(c)!.from); kinds.unshift(prev.get(c)!.kind); } return { target: t, nodes, kinds }; });
  };

  const paths: AttackPath[] = [];
  const addPaths = (kind: AttackPath["kind"], entry: string, endpoints: string[], extraFindings: Finding[]) => {
    for (const p of search(entry, kind === "web" ? webOut : pipeOut)) {
      const onPath = new Map<string, Finding>();
      for (const id of p.nodes) for (const f of findingsUnder(graph, findings, home, id)) onPath.set(f.id, f);
      for (const f of extraFindings) onPath.set(f.id, f);
      // supply chain: what the entry point's own code depends on (a vulnerable shared package) is part of its exposure
      for (const d of dependsOn.get(entry) ?? []) for (const f of findingsUnder(graph, findings, home, d)) onPath.set(f.id, f);
      const list = [...onPath.values()].sort((a, b) => priority(b) - priority(a));
      const unauthN = endpoints.filter((e) => (byId.get(e)?.evidence ?? []).some((ev) => unauth.has(ev.path))).length;
      if (list.length === 0 && unauthN === 0) continue; // an exposed route to an asset with nothing wrong on it is not a finding

      const worst = list.reduce<Severity | null>((w, f) => worse(w, f.severity), null);
      const tgt = byId.get(p.target)!, ent = byId.get(entry)!;
      const facts: string[] = [];
      facts.push(kind === "web"
        ? `${plural(endpoints.length, "public endpoint")} in ${ent.label}${unauthN ? `, ${unauthN} of which ${unauthN === 1 ? "accepts" : "accept"} writes with no authentication check` : ""}`
        : `${ent.label} can be triggered from outside, and runs with the repository's secrets`);
      facts.push(`Reaches ${tgt.label} (${[...new Set(p.kinds)].join(", ")})`);
      if (list.length) facts.push(`${plural(list.length, "finding")} along the way, worst: ${list[0].severity} (${list[0].title})`);

      paths.push({
        id: `${entry}>${p.target}`, kind, nodes: p.nodes, entry, target: p.target, endpoints: endpoints.length, unauthenticated: unauthN,
        findings: list.map((f) => f.id), worst, facts,
        risk: list.reduce((s, f) => s + priority(f), 0) + Math.min(unauthN, 3) * 8 + (kind === "pipeline" ? 12 : 0) + p.nodes.length * -1,
      });
    }
  };

  // 1) web: group every endpoint under its nearest ancestor that has somewhere to go
  const footholds = new Map<string, string[]>();
  for (const n of graph.nodes) {
    if (n.kind !== "endpoint") continue;
    for (let a = parent.get(n.id); a; a = parent.get(a)) if (webOut.has(a)) { (footholds.get(a) ?? footholds.set(a, []).get(a)!).push(n.id); break; }
  }
  for (const [entry, endpoints] of footholds) addPaths("web", entry, endpoints, []);

  // 2) pipelines an outsider can trigger (a pull request from a fork, an issue title…)
  const riskyPipelines = new Set<string>();
  for (const f of findings) if (RISKY_PIPELINE_RULES.has(f.ruleId) && home.get(f.id)) riskyPipelines.add(home.get(f.id)!);
  for (const entry of riskyPipelines) addPaths("pipeline", entry, [], findings.filter((f) => RISKY_PIPELINE_RULES.has(f.ruleId) && home.get(f.id) === entry));

  return paths.sort((a, b) => b.risk - a.risk || (SEVERITY_RANK[b.worst ?? "info"] - SEVERITY_RANK[a.worst ?? "info"]) || a.id.localeCompare(b.id));
}

/** Node ids to light up for a path, as the canvas's "impact" highlight: the foothold fails, the rest is what it reaches. */
export function pathHighlight(p: AttackPath, graph: TwinGraph) {
  const label = (id: string) => graph.nodes.find((n) => n.id === id)?.label ?? id;
  return {
    title: `Attack path: ${label(p.entry)} → ${label(p.target)}`,
    detail: p.facts.join(" · "),
    mode: "impact" as const,
    focusId: p.entry,
    ids: p.nodes.slice(1),
    path: [] as string[],
    source: "rules" as const,
  };
}
