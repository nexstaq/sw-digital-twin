import { blastRadius } from "@/lib/graph/blast";
import { ancestry, culprits } from "@/lib/graph/nav";
import type { TwinGraph, TwinNode } from "@/lib/graph/types";
import type { AskResult, Highlight } from "./types";

const STOP = new Set(["the", "a", "an", "of", "for", "on", "to", "is", "are", "was", "were", "in", "my", "our", "and", "service", "services", "show", "me", "go", "open", "find", "where", "what", "which", "who", "whats", "that", "this", "all", "any", "does", "do", "it", "its"]);
const DOWN = new Set(["down", "fails", "fail", "failed", "failing", "broken", "break", "breaks", "broke", "out", "offline", "unavailable", "goes", "go", "crashes", "crash", "dies", "died", "unreachable", "slow", "gets", "get", "has", "stops", "stop"]);

const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
const stem = (t: string) => (t.length > 3 && t.endsWith("s") ? t.slice(0, -1) : t);
const tokens = (s: string) => norm(s).split(" ").filter(Boolean).map(stem);

/** How well does `phrase` name this node? 0 = not at all. Prefers important (shallower) nodes on ties. */
function score(n: TwinNode, phrase: string): number {
  const want = tokens(phrase).filter((t) => !STOP.has(t));
  if (!want.length) return 0;
  const names = [n.label, n.narrative?.name, n.id.split(/[:/]/).at(-1) ?? ""].filter(Boolean) as string[];
  let best = 0;
  for (const name of names) {
    const have = tokens(name);
    if (!have.length) continue;
    const a = want.join(" "), b = have.join(" ");
    if (a === b) best = Math.max(best, 100);
    else if (b.length >= 3 && (a.includes(b) || b.includes(a))) best = Math.max(best, 80);
    else {
      const hit = want.filter((t) => have.some((h) => h === t || (t.length >= 4 && (h.startsWith(t) || t.startsWith(h) && h.length >= 4)))).length;
      if (hit / want.length >= 0.6) best = Math.max(best, 40 + 40 * (hit / want.length));
    }
  }
  return best ? best + (3 - n.level) : 0;
}

/** Best-matching nodes with their match score (100 = exact name, 80 = contains, lower = partial). */
export function rankNodes(graph: TwinGraph, q: string, limit = 8): { node: TwinNode; score: number }[] {
  return graph.nodes.map((node) => ({ node, score: score(node, q) })).filter((x) => x.score > 0).sort((a, b) => b.score - a.score).slice(0, limit);
}

export function searchNodes(graph: TwinGraph, q: string, limit = 8): TwinNode[] {
  return rankNodes(graph, q, limit).map((x) => x.node);
}

const resolve = (graph: TwinGraph, phrase: string) => searchNodes(graph, phrase, 1)[0];

/** Everything that goes down with `id`, at its own level and at every level above it. */
export function impactOf(graph: TwinGraph, id: string): string[] {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const hit = new Set<string>();
  for (const cur of [...ancestry(graph, id), id]) {
    const me = byId.get(cur)!;
    const sibs = new Set(graph.nodes.filter((n) => n.parentId === me.parentId).map((n) => n.id));
    const edges = graph.edges.filter((e) => sibs.has(e.from) && sibs.has(e.to));
    for (const x of blastRadius(edges, cur).nodes) hit.add(x);
  }
  hit.delete(id);
  return [...hit];
}

const commonPrefix = (paths: string[][]) => {
  const first = paths[0] ?? [];
  let i = 0;
  while (i < first.length && paths.every((p) => p[i] === first[i])) i++;
  return first.slice(0, i);
};
const lab = (graph: TwinGraph, ids: string[], max = 5) => {
  const names = ids.map((i) => graph.nodes.find((n) => n.id === i)?.label ?? i);
  return names.slice(0, max).join(", ") + (names.length > max ? ` +${names.length - max} more` : "");
};
const mins = (h: number) => (h < 1 ? `${Math.max(1, Math.round(h * 60))}m` : h < 24 ? `${Math.round(h)}h` : `${Math.round(h / 24)}d`);

const set = (graph: TwinGraph, title: string, ids: string[], detail?: string): AskResult => ({
  ok: true,
  highlight: { title, detail, mode: "set", ids, path: commonPrefix(ids.map((i) => ancestry(graph, i))), source: "rules" },
});

function entityAfter(text: string, re: RegExp): string {
  const m = re.exec(text);
  let toks = norm(m ? text.slice(m.index + m[0].length) : text).split(" ").filter(Boolean);
  while (toks.length && DOWN.has(toks.at(-1)!)) toks.pop();
  toks = toks.filter((t, i) => !(i === 0 && t === "the"));
  return toks.join(" ");
}

/** Answers the common control-room questions with no model. Returns `unrecognised` when it has no idea, so an AI fallback can try. */
export function answerLocal(graph: TwinGraph, question: string): AskResult {
  const q = norm(question);
  if (!q) return { ok: false, message: "Ask about your system, or type a name to jump to it." };

  // "what breaks if X is down", "blast radius of X", "what depends on X"
  const impactRe = /\b(?:if|when|blast radius (?:of|for)|impact of|depends? on|depend on|affected by)\b/;
  if (impactRe.test(q) && /\b(break|breaks|affect|affected|impact|impacted|depend|depends|blast|fail|fails|down|go down)\b/.test(q)) {
    const phrase = entityAfter(q, impactRe);
    const node = phrase ? resolve(graph, phrase) : undefined;
    if (!node) return { ok: false, message: phrase ? `I couldn't find anything called “${phrase}”.` : "Which part? Try “what breaks if payments is down”.", unrecognised: !phrase };
    const ids = impactOf(graph, node.id);
    const h: Highlight = {
      mode: "impact", focusId: node.id, ids, path: ancestry(graph, node.id), source: "rules",
      title: ids.length ? `If ${node.label} is down, ${ids.length} other part${ids.length > 1 ? "s" : ""} are affected` : `If ${node.label} is down, nothing else is affected`,
      detail: ids.length ? lab(graph, ids) : undefined,
    };
    return { ok: true, highlight: h };
  }

  if (/\b(who owns|owner|owners|owned by|responsible|on call for)\b/.test(q)) {
    const node = resolve(graph, q.replace(/\b(who owns|owner of|owners of|owner|owners|owned by|responsible for|responsible|on call for)\b/g, " "));
    if (!node) return { ok: false, message: "Which part do you mean? Try “who owns payments”." };
    return { ok: true, highlight: { mode: "info", ids: [node.id], focusId: node.id, path: ancestry(graph, node.id), source: "rules", title: node.label, detail: node.owners?.length ? `Owned by ${node.owners.join(", ")}` : "No owner on record (no CODEOWNERS entry matches)." } };
  }

  if (/\b(deploy\w*|release\w*|shipped|ship|what changed|latest change|last change|recent change)\b/.test(q)) {
    const ids = graph.nodes.filter((n) => n.kind === "env" || n.live || /deploy|release|publish/i.test(n.label)).filter((n) => n.level > 0 || n.live).map((n) => n.id);
    const last = graph.deploys[0];
    const bits = [last && `Last ${last.ok ? "successful" : "FAILED"} deploy: ${last.label}, ${mins(last.hoursAgo)} ago`, graph.activity?.running ? `${graph.activity.running} running now` : undefined, graph.activity?.queued ? `${graph.activity.queued} queued` : undefined].filter(Boolean);
    if (!ids.length && !last) return { ok: false, message: "No deployments or release workflows found for this repo yet." };
    return ids.length ? set(graph, "Deploy & release", ids, bits.join(" · ") || undefined) : { ok: true, highlight: { mode: "info", ids: [], path: [], source: "rules", title: "Deploy & release", detail: bits.join(" · ") } };
  }

  if (/\b(unknown|blind|unmonitored|no data|cant see|not monitored|no signal|grey|gray)\b/.test(q)) {
    const ids = graph.nodes.filter((n) => !n.parentId && n.state === "unknown").map((n) => n.id);
    return ids.length ? set(graph, `${ids.length} block${ids.length > 1 ? "s" : ""} with no live signal`, ids, "Connect a source to see these.") : { ok: false, message: "Every top-level block reports a signal." };
  }

  if (/\b(degraded|flaky|warning|warnings|at risk|unstable)\b/.test(q)) {
    const c = culprits(graph, ["degraded"]);
    return c.length ? set(graph, `${c.length} degraded`, c.map((n) => n.id), lab(graph, c.map((n) => n.id))) : { ok: false, message: "Nothing is degraded right now." };
  }

  if (/\b(fail\w*|broken|broke|red|errors?|unhealthy|problems?|issues?|wrong|bad|outage|incident|not working|breaking|down|needs? attention|attention)\b/.test(q)) {
    const c = culprits(graph, ["failing"]);
    if (!c.length) {
      const d = culprits(graph, ["degraded"]);
      return d.length ? set(graph, `Nothing is failing, ${d.length} degraded`, d.map((n) => n.id), lab(graph, d.map((n) => n.id))) : { ok: false, message: graph.nodes.every((n) => n.state === "unknown") ? "No live signal is connected yet, so I can't say what's failing." : "Nothing is failing. All monitored parts are healthy." };
    }
    return set(graph, `${c.length} thing${c.length > 1 ? "s" : ""} failing`, c.map((n) => n.id), c[0].reasons[0] ? `${c[0].label}: ${c[0].reasons[0]}` : lab(graph, c.map((n) => n.id)));
  }

  // anything else that names a node is "take me there"
  const node = resolve(graph, q);
  if (node) return { ok: true, highlight: { mode: "info", ids: [node.id], focusId: node.id, path: ancestry(graph, node.id), source: "rules", title: node.label, detail: node.summary } };
  return { ok: false, message: "I didn't recognise that.", unrecognised: true };
}
