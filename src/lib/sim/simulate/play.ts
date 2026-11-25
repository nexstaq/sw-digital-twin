import type { TwinGraph, TwinNode } from "@/lib/graph/types";
import { startRange, type RangeInstance } from "../range/runtime";
import type { EndpointSpec, Fault, RangeEvent, RangeSpec, WorkflowResult } from "../range/types";
import type { Scenario } from "./scenario";

/**
 * Turns a scenario into steps a person can follow. Every step comes from something the range actually did (an event or a
 * workflow result), is written in three voices, and names only the blocks it is about (`refs`), all of which are on the map.
 * No model writes any of it: it is the same words every time for the same run.
 */

export const PERSONAS = ["exec", "engineer", "security"] as const;
export type Persona = (typeof PERSONAS)[number];
export const PERSONA_LABEL: Record<Persona, string> = { exec: "Plain English", engineer: "Engineer", security: "Security" };

export interface SimStep {
  index: number;
  kind: "trigger" | "request" | "visit" | "job" | "deploy";
  nodeId: string;
  from?: string;
  /** the map edge this step travelled along, if any */
  via?: string;
  ok: boolean;
  ms: number;
  note?: string;
  text: Record<Persona, string>;
  /** every block this step talks about; each exists on the map */
  refs: string[];
  /** "path:lines" of the code or config behind the blocks, from the map's own evidence */
  evidence: string[];
}

export interface SimRun {
  scenario: Scenario;
  steps: SimStep[];
  ok: boolean;
  totalMs: number;
  failedAt?: string;
  /** blocks and edges the run touched */
  nodes: string[];
  edges: string[];
}

/** Starts a step's pass through the range and returns what it needs afterwards. Shared with the health simulation so both do the same thing. */
export function execute(r: RangeInstance, sc: Scenario): { ok: boolean; ms: number; failedAt?: string; workflow?: WorkflowResult } {
  if (sc.kind === "request") { const res = r.handle(sc.request!); return { ok: res.status < 500, ms: res.ms }; }
  if (sc.kind === "flow") { const f = r.flow(sc.entryId); return { ok: f.ok, ms: f.ms, failedAt: f.failedAt }; }
  const w = r.runWorkflow(sc.entryId, { sha: "0".repeat(40) });
  const failed = w.jobs.find((j) => j.conclusion === "failure");
  return { ok: w.conclusion === "success", ms: w.endedAt - w.startedAt, failedAt: failed?.nodeId, workflow: w };
}

const secs = (ms: number) => (ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.round(ms)}ms`);
const AUTH_TEXT: Record<EndpointSpec["auth"], string> = {
  required: "treated as needing a signed-in user",
  "public-read": "treated as open to anyone, because it only reads",
  none: "open to anyone, and the scan found that it changes data",
};

interface Ctx { node: TwinNode; parent?: TwinNode; ev: RangeEvent | { kind: SimStep["kind"]; ok: boolean; ms: number; note?: string }; route?: EndpointSpec }

const name = (p: Persona, n: TwinNode) => (p === "exec" ? n.narrative?.name ?? n.label : n.label);

function words(c: Ctx): Record<Persona, string> {
  const { node: n, parent: p, ev, route } = c;
  const kind = n.kind;
  const t = (persona: Persona) => name(persona, n);
  const from = (persona: Persona) => (p ? name(persona, p) : "");
  const ms = secs(ev.ms);

  if (ev.kind === "trigger") return {
    exec: `A change is made to the software. The automatic checks and release for ${t("exec")} start.`,
    engineer: `A push triggers ${t("engineer")}. Its jobs run in the order their dependencies allow.`,
    security: `${t("security")} starts from a code change and runs with the pipeline's permissions, so what it runs is trusted.`,
  };
  if (ev.kind === "request" && route) {
    const how = AUTH_TEXT[route.auth];
    return {
      exec: ev.ok ? `A customer's request arrives at ${t("exec")}.` : `A customer's request arrives at ${t("exec")}, but it cannot be completed.`,
      engineer: `${route.method} ${route.path} arrives at ${t("engineer")}${ev.ok ? "" : " and fails further down"}. Total ${ms}.`,
      security: `This is an entry point from outside: ${t("security")} is ${how}${route.authSource === "assumed" ? " (an assumption; the map does not record it)" : ""}.`,
    };
  }
  if (ev.kind === "job") {
    if (ev.note === "skipped") return {
      exec: `${t("exec")} did not run, because a step before it did not pass.`,
      engineer: `${t("engineer")} skipped: a job it needs did not succeed.`,
      security: `${t("security")} did not run, so nothing it would have changed happened.`,
    };
    return ev.ok ? {
      exec: `${t("exec")} ran and passed.`,
      engineer: `${t("engineer")} succeeded in ${ms}.`,
      security: `${t("security")} ran with the pipeline's permissions and finished without error.`,
    } : {
      exec: `${t("exec")} failed, so the change cannot go any further.`,
      engineer: `${t("engineer")} failed${ev.note ? ` at ${ev.note}` : ""} after ${ms}. Everything that needs it is skipped.`,
      security: `A failure in ${t("security")} stops the release. That blocks a bad change, and it also blocks a fix until this is resolved.`,
    };
  }
  if (ev.kind === "deploy") {
    if (ev.note === "skipped") return { exec: `The release to ${t("exec")} did not happen.`, engineer: `Deploy to ${t("engineer")} skipped; an earlier step failed.`, security: `Nothing reached ${t("security")}.` };
    return ev.ok ? {
      exec: `The new version goes live in ${t("exec")}.`,
      engineer: `Deploy to ${t("engineer")} succeeded.`,
      security: `What was just built is now running in ${t("security")}; this is where a mistake would reach real users.`,
    } : {
      exec: `The release to ${t("exec")} failed, so customers still have the old version.`,
      engineer: `Deploy to ${t("engineer")} failed${ev.note ? ` (${ev.note})` : ""}.`,
      security: `The release to ${t("security")} failed. The old version keeps running, including any weakness it has.`,
    };
  }

  // a visit: something is called, read or published to
  const failed = !ev.ok;
  // The range's note for a failed dependency names the other block; that block has its own step, so here we say only that
  // something below failed, and never name a block this step is not about.
  const why = ev.note?.startsWith("a dependency failed") ? "something it depends on failed" : ev.note;
  if (failed) return {
    exec: `${t("exec")} does not answer, so the work stops here and the request fails.`,
    engineer: `${t("engineer")} failed${why ? ` (${why})` : ""}${p ? `; ${from("engineer")} fails with it` : ""}.`,
    security: `${t("security")} being unavailable takes down whatever depends on it. Anything that must keep working should have a fallback.`,
  };
  switch (kind) {
    case "datastore": return {
      exec: `${p ? `${from("exec")} looks` : "The system looks"} up the information in ${t("exec")}.`,
      engineer: `${p ? `${from("engineer")} reads` : "Read"} from ${t("engineer")} (${ms}).`,
      security: `${t("security")} is where the data worth protecting lives. Whoever can reach this can read it.`,
    };
    case "queue": return {
      exec: `${p ? `${from("exec")} hands` : "A job is handed"} a job to ${t("exec")}, to be done later.`,
      engineer: `${p ? `${from("engineer")} publishes` : "Publish"} a message to ${t("engineer")} (${ms}). It will be picked up asynchronously.`,
      security: `Whatever goes onto ${t("security")} is trusted by the part that picks it up, so what is put there matters.`,
    };
    case "external": return {
      exec: `${p ? `${from("exec")} contacts` : "The system contacts"} ${t("exec")}, an outside service.`,
      engineer: `${p ? `${from("engineer")} calls` : "Call"} the external service ${t("engineer")} (${ms}).`,
      security: `Data leaves your systems here, to ${t("security")}. It is outside your control, and its availability is outside it too.`,
    };
    case "env": return {
      exec: `The work reaches ${t("exec")}.`, engineer: `Reaches ${t("engineer")}.`, security: `${t("security")} is where released software runs.`,
    };
    default: return {
      exec: p ? `${from("exec")} asks ${t("exec")} to do part of the work.` : `${t("exec")} starts working on the request.`,
      engineer: p ? `${from("engineer")} calls ${t("engineer")} (${ms}).` : `${t("engineer")} receives the work (${ms} including everything it calls).`,
      security: p ? `A call crosses from ${from("security")} to ${t("security")}. Each such boundary should check who is asking.` : `${t("security")} is where outside work first lands.`,
    };
  }
}

function evidenceOf(graph: TwinGraph, ids: string[]): string[] {
  const out: string[] = [];
  for (const id of ids) {
    const n = graph.nodes.find((x) => x.id === id);
    for (const e of n?.evidence ?? []) { if (e.path === ".") continue; const s = e.lines ? `${e.path}:${e.lines}` : e.path; if (!out.includes(s)) out.push(s); if (out.length >= 3) return out; }
  }
  return out;
}

/** parents before children, siblings in the order they ran */
function preorder(events: readonly RangeEvent[]): RangeEvent[] {
  const kids = new Map<string, RangeEvent[]>();
  const roots: RangeEvent[] = [];
  for (const e of events) { if (e.from) (kids.get(e.from) ?? kids.set(e.from, []).get(e.from)!).push(e); else roots.push(e); }
  const out: RangeEvent[] = [];
  const walk = (e: RangeEvent) => { out.push(e); for (const k of (kids.get(e.nodeId) ?? []).sort((a, b) => a.seq - b.seq)) walk(k); };
  for (const r of roots.sort((a, b) => a.seq - b.seq)) walk(r);
  return out;
}

export function runScenario(spec: RangeSpec, graph: TwinGraph, sc: Scenario, o: { fault?: { nodeId: string; fault: Fault } } = {}): SimRun {
  const r = startRange(spec);
  if (o.fault) r.inject(o.fault.nodeId, o.fault.fault);
  const res = execute(r, sc);
  const events = r.events();
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const routes = new Map(spec.endpoints.map((e) => [e.nodeId, e]));
  const steps: SimStep[] = [];
  const add = (kind: SimStep["kind"], nodeId: string, from: string | undefined, via: string | undefined, ok: boolean, ms: number, note: string | undefined) => {
    const node = byId.get(nodeId);
    if (!node) return; // the range is built from this map, so this cannot happen; never narrate a block that is not on it
    const parent = from ? byId.get(from) : undefined;
    const ev = { kind, ok, ms, note };
    const refs = [nodeId, ...(parent ? [parent.id] : [])];
    steps.push({ index: steps.length, kind, nodeId, ...(from ? { from } : {}), ...(via ? { via } : {}), ok, ms, ...(note ? { note } : {}), text: words({ node, parent, ev, route: routes.get(nodeId) }), refs, evidence: evidenceOf(graph, [nodeId]) });
  };

  if (sc.kind === "workflow") {
    const w = res.workflow!;
    add("trigger", w.workflowId, undefined, undefined, true, 0, undefined);
    for (const j of w.jobs) add(j.stage === "env" ? "deploy" : "job", j.nodeId, undefined, undefined, j.conclusion !== "failure", j.endedAt - j.startedAt, j.conclusion === "skipped" ? "skipped" : j.failedStep);
    for (const d of w.deploys) if (!w.jobs.some((j) => j.nodeId === d.envId)) add("deploy", d.envId, undefined, undefined, d.state === "success", 0, undefined);
  } else {
    for (const e of preorder(events)) add(e.kind === "request" ? "request" : "visit", e.nodeId, e.from, e.via, e.ok, e.ms, e.note);
  }
  r.finish();

  const nodes = [...new Set(steps.map((s) => s.nodeId))];
  const edges = [...new Set(steps.map((s) => s.via).filter((x): x is string => !!x))];
  return { scenario: sc, steps, ok: res.ok, totalMs: res.ms, ...(res.failedAt ? { failedAt: res.failedAt } : {}), nodes, edges };
}
