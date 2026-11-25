import type { TwinGraph } from "@/lib/graph/types";
import type { RangeRequest, RangeSpec } from "../range/types";

/**
 * What to run when someone selects a block. "Select any block" has to mean something for every block, so each kind maps to the
 * most useful thing that block takes part in:
 *  a route          -> one request through it
 *  a service        -> a request reaching it, and everything it then calls
 *  data / queue / outside service -> the first service that uses it, so you see it in context
 *  a pipeline       -> a change going through its jobs to a deploy (also for a single job or environment inside one)
 *  a grouping block -> the most connected thing inside it
 * Anything that is only code structure (a package, a file) has nothing that runs, and says so.
 */

export type ScenarioKind = "request" | "flow" | "workflow";

export interface Scenario {
  kind: ScenarioKind;
  /** the block the person picked */
  focusId: string;
  /** where the run starts: a route, a service, or a workflow */
  entryId: string;
  title: string;
  blurb: string;
  request?: RangeRequest;
}
export type ScenarioResult = { ok: true; scenario: Scenario } | { ok: false; reason: string };

const WEB_FLOW = new Set(["calls", "reads", "publishes"]);
const isParam = (seg: string) => seg.startsWith(":") || (seg.startsWith("[") && seg.endsWith("]")) || (seg.startsWith("{") && seg.endsWith("}"));

export function scenarioFor(spec: RangeSpec, graph: TwinGraph, nodeId: string): ScenarioResult {
  const node = graph.nodes.find((n) => n.id === nodeId);
  if (!node) return { ok: false, reason: "That block is not on the map." };
  const emu = new Map(spec.emulators.map((e) => [e.nodeId, e]));
  const label = (id: string) => graph.nodes.find((n) => n.id === id)?.label ?? id;
  const kids = (id: string) => spec.emulators.filter((e) => e.parentId === id);
  const isWorkflow = (id: string) => emu.get(id)?.kind === "job" && kids(id).some((k) => k.kind === "job" || k.kind === "env");
  const into = (id: string) => spec.edges.filter((e) => e.to === id && WEB_FLOW.has(e.kind) && emu.has(e.from)).sort((a, b) => a.id.localeCompare(b.id));
  const reach = (id: string) => {
    const seen = new Set([id]); const q = [id];
    for (let i = 0; i < q.length; i++) for (const e of spec.edges) if (e.from === q[i] && WEB_FLOW.has(e.kind) && emu.has(e.to) && !seen.has(e.to)) { seen.add(e.to); q.push(e.to); }
    return seen.size - 1;
  };

  const make = (kind: ScenarioKind, entryId: string, title: string, blurb: string, request?: RangeRequest): ScenarioResult =>
    ({ ok: true, scenario: { kind, focusId: nodeId, entryId, title, blurb, ...(request ? { request } : {}) } });

  const route = spec.endpoints.find((e) => e.nodeId === nodeId);
  if (route) {
    const path = "/" + route.segments.map((s) => (isParam(s) ? "1" : s)).join("/");
    return make("request", nodeId, `A request to ${node.label}`,
      `A signed-in user calls ${node.label}. Watch it reach the service behind it and everything that service depends on.`,
      { method: route.method === "PAGE" || route.method === "ALL" ? "GET" : route.method, path, role: "user" });
  }

  const e = emu.get(nodeId);
  if (e) {
    if (isWorkflow(nodeId)) return make("workflow", nodeId, `A change going through ${node.label}`, `A change is pushed. Watch ${node.label} run its steps in order and, if they pass, release.`);
    if (e.parentId && isWorkflow(e.parentId) && (e.kind === "job" || e.kind === "env")) {
      return make("workflow", e.parentId, `${node.label} inside ${label(e.parentId)}`, `${node.label} is one step of ${label(e.parentId)}. Watch the whole pipeline run to see where it fits.`);
    }
    if (e.kind === "env") {
      const via = spec.edges.find((x) => x.kind === "deploys_to" && x.to === nodeId && emu.get(x.from)?.parentId && isWorkflow(emu.get(x.from)!.parentId!));
      if (via) return make("workflow", emu.get(via.from)!.parentId!, `A release reaching ${node.label}`, `A change is pushed and released. Watch it arrive in ${node.label}.`);
      return { ok: false, reason: `${node.label} is a place software is released to, and nothing in the map releases to it yet.` };
    }
    if (e.kind === "job") return { ok: false, reason: `${node.label} is a pipeline step with no pipeline around it on the map.` };
    if (e.kind === "datastore" || e.kind === "queue" || e.kind === "external") {
      const caller = into(nodeId)[0];
      if (caller) return make("flow", caller.from, `How ${node.label} is used`, `Watch ${label(caller.from)} do its work and reach ${node.label} on the way.`);
      return make("flow", nodeId, `${node.label} on its own`, `Nothing on the map calls ${node.label}, so this shows only ${node.label} itself.`);
    }
    return make("flow", nodeId, `A request reaching ${node.label}`, `Work arrives at ${node.label}. Watch it call each thing it depends on, in order.`);
  }

  if (node.kind === "package" || node.kind === "file") return { ok: false, reason: `${node.label} is part of the code's structure, not something that runs, so there is nothing to simulate.` };

  // a grouping block: simulate the best thing inside it
  const inside = new Set<string>();
  const walk = (id: string) => { for (const n of graph.nodes) if (n.parentId === id) { inside.add(n.id); walk(n.id); } };
  walk(nodeId);
  const cands = spec.emulators.filter((x) => inside.has(x.nodeId) && !spec.endpoints.some((r) => r.nodeId === x.nodeId));
  const rank = (x: (typeof cands)[number]) => (isWorkflow(x.nodeId) ? 5 : x.kind === "service" || x.kind === "endpoint" ? 4 : x.kind === "queue" ? 3 : x.kind === "datastore" ? 2 : x.kind === "external" ? 1 : 0);
  const best = [...cands].sort((a, b) => rank(b) - rank(a) || reach(b.nodeId) - reach(a.nodeId) || a.nodeId.localeCompare(b.nodeId))[0];
  if (!best || rank(best) === 0) return { ok: false, reason: `There is nothing inside ${node.label} that runs, so there is nothing to simulate. Open it and pick a part.` };
  const r = scenarioFor(spec, graph, best.nodeId);
  if (!r.ok) return r;
  return { ok: true, scenario: { ...r.scenario, focusId: nodeId, title: `${node.label}: ${r.scenario.title.charAt(0).toLowerCase()}${r.scenario.title.slice(1)}` } };
}

/**
 * A few good blocks to try first, so an empty Simulate lens is never a blank page: a pipeline, the best-connected service,
 * and a queue, when the map has them. Only blocks that have a scenario are suggested.
 */
export function suggest(spec: RangeSpec, graph: TwinGraph): string[] {
  const out: string[] = [];
  const emu = new Set(spec.emulators.map((e) => e.nodeId));
  const out_ = (id: string) => spec.edges.filter((e) => e.from === id && WEB_FLOW.has(e.kind) && emu.has(e.to)).length;
  const workflow = spec.emulators.filter((e) => e.kind === "job" && spec.emulators.some((k) => k.parentId === e.nodeId && (k.kind === "job" || k.kind === "env"))).sort((a, b) => a.nodeId.localeCompare(b.nodeId))[0];
  const service = [...spec.emulators].filter((e) => e.kind === "service" && out_(e.nodeId) > 0).sort((a, b) => out_(b.nodeId) - out_(a.nodeId) || a.nodeId.localeCompare(b.nodeId))[0];
  const queue = spec.emulators.filter((e) => e.kind === "queue").sort((a, b) => a.nodeId.localeCompare(b.nodeId))[0];
  for (const e of [service, queue, workflow]) if (e && scenarioFor(spec, graph, e.nodeId).ok) out.push(e.nodeId);
  return out;
}
