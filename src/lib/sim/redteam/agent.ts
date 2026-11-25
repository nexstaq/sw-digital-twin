import type { TwinGraph } from "@/lib/graph/types";
import type { FindingSet, Simulation } from "@/lib/security/types";
import type { KillRegistry } from "../agent/killswitch";
import { runPlan, type AgentRunResult, type CallResult, type Run } from "../agent/runtime";
import type { AnyTool } from "../agent/tools";
import { flowTool, inspectTool, requestTool, ROLES_FOR, triggerTool } from "../agent/tools/range";
import { buildRange } from "../range/generate";
import { startRange, type RangeInstance } from "../range/runtime";
import { PAYLOAD_CLASSES, type RangeSpec } from "../range/types";
import { redteamRoe, RT } from "./roe";

/**
 * The red-team agent: a reachability check, not a staged attack. It starts with nothing but the public surface of the range (it
 * calls as `anonymous` only, see `ROLES_FOR.redteam`) and asks one question, deterministically: from out here, with no
 * credentials at all, is there any way at all to reach the crown jewels — the data stores the map's `crown` markers protect —
 * and how likely is that, given what was found?
 *
 * It tries every modelled weakness class on every public route (the exact payload classes the range understands, never free-text
 * exploit code), and, separately, whether a pipeline can be triggered by an outsider's pull request; if a pipeline deploys
 * somewhere, it traces what the software running there could *already*, by its own ordinary dependencies, reach — that capability
 * is inherited from the map, never invented by this agent. Every call goes through the same guarded path as every other agent
 * (X3): checked against the rules of engagement, logged, and counted. A "success" is the range's own harmless marker, never a
 * working exploit against real software, and nothing here is wired to a real network (X9 is where any real target could enter,
 * and it does not touch this agent).
 *
 * What it can and cannot say. Like the white-box and gray-box agents, this reproduces what the scanner's and imported findings
 * already claim; it does not discover new weaknesses. What it adds is a single, honest answer to "how exposed are the crown
 * jewels to someone with nothing": a reachability count and a likelihood, with the exact path and the audit-log evidence
 * for each.
 */

export interface ReachPath {
  kind: "web" | "pipeline";
  /** the route or pipeline block this path starts from */
  entry: string;
  technique: string;
  proof?: string;
  findingId?: string;
  /** block labels this path passes through, entry first */
  steps: string[];
  /** crown markers of data stores this path reaches */
  crown: string[];
  /** audit-log steps this path's claim rests on */
  auditSteps: number[];
}

export interface ReachSummary {
  /** data stores on the map that carry a crown marker at all */
  crownJewels: number;
  /** of those, how many were reached by at least one path */
  crownsReached: number;
  /** distinct entry points (routes or pipelines) that reach a crown jewel */
  distinctEntries: number;
  likelihood: "none" | "low" | "medium" | "high";
}

export interface RedteamInput {
  repo: string; sha: string; graph: TwinGraph; set: FindingSet;
  /** at most this many routes are tried, in path order */
  maxRoutes?: number;
  /** at most this many pipeline blocks are tried */
  maxWorkflows?: number;
  now?: () => number;
  killRegistry?: KillRegistry;
}

export interface RedteamResult {
  paths: ReachPath[];
  summary: ReachSummary;
  /** verdicts for the findings a path actually reached, by their proof marker */
  simulations: Record<string, Simulation>;
  run: AgentRunResult;
  runId: string;
  spec: RangeSpec;
  counts: Record<string, number>;
  notes: string[];
}

const isParam = (seg: string) => seg.startsWith(":") || (seg.startsWith("[") && seg.endsWith("]")) || (seg.startsWith("{") && seg.endsWith("}"));
const concrete = (path: string, id: "1") => `/${path.split("/").filter(Boolean).map((s) => (isParam(s) ? id : s)).join("/")}`;

interface BlindRoute { id: string; method: string; path: string }
interface BlindBlock { id: string; label: string; kind: string }

export async function discoverReachability(input: RedteamInput): Promise<RedteamResult> {
  const now = input.now ?? Date.now;
  const spec = buildRange({ sha: input.sha, graph: input.graph }, input.set);
  const range: RangeInstance = startRange(spec);
  const notes: string[] = [];
  const paths: ReachPath[] = [];

  const maxRoutes = input.maxRoutes ?? 15;
  const maxWorkflows = input.maxWorkflows ?? 10;
  const jobBlocks = spec.emulators.filter((e) => e.kind === "job");
  if (spec.endpoints.length > maxRoutes) notes.push(`Only the first ${maxRoutes} of ${spec.endpoints.length} routes were tried.`);
  if (jobBlocks.length > maxWorkflows) notes.push(`Only the first ${maxWorkflows} of ${jobBlocks.length} pipeline blocks were tried.`);

  const roe = redteamRoe({ repo: input.repo, rangeId: spec.id, now: now(), routes: Math.min(maxRoutes, spec.endpoints.length), workflows: Math.min(maxWorkflows, jobBlocks.length) });
  const tools = [inspectTool({ spec, blind: true }), requestTool({ range, spec, roles: ROLES_FOR.redteam }), triggerTool({ range, spec }), flowTool({ range, spec })] as unknown as AnyTool[];

  const label = (id: string) => input.graph.nodes.find((n) => n.id === id)?.label ?? id;
  const byProof = new Map(spec.weaknesses.map((w) => [w.proof, w]));
  const serviceDeploys = spec.edges.filter((e) => e.kind === "deploys_to");

  const run = await runPlan({ roe, agent: "redteam", tools, now, killRegistry: input.killRegistry, teardown: [() => range.destroy()] }, async (r: Run) => {
    const inspect = await r.call("range_inspect", {});
    if (!inspect.ok) { notes.push("Could not inspect the range, so nothing could be tried."); return; }
    const data = (inspect.result as { data?: { routes?: unknown; blocks?: unknown } }).data ?? {};
    const routes = (Array.isArray(data.routes) ? (data.routes as BlindRoute[]) : []).slice(0, maxRoutes);
    const blocks = Array.isArray(data.blocks) ? (data.blocks as BlindBlock[]) : [];

    const record = (res: CallResult, entry: string) => {
      if (!res.ok) return;
      const d = (res.result as { data?: { status?: number; proof?: string; reached?: string[]; crown?: string[] } }).data ?? {};
      if (d.status !== 200 || !d.proof) return;
      const w = byProof.get(d.proof);
      const reached = (d.reached ?? []).map(label);
      paths.push({ kind: "web", entry, technique: RT.web, proof: d.proof, findingId: w?.findingId, steps: [entry, ...reached], crown: d.crown ?? [], auditSteps: [res.step] });
    };

    // ---- web surface: every modelled payload class, anonymous, on every public route; a plain anonymous call catches an open write ----
    for (const rt of routes) {
      if (!r.active()) { notes.push("The run was stopped before every route was tried."); break; }
      const method = rt.method === "PAGE" || rt.method === "ALL" ? "GET" : rt.method;
      const path = concrete(rt.path, "1");
      const entry = `${rt.method} ${rt.path}`;
      record(await r.call("range_request", { method, path, role: "anonymous", technique: RT.web }), entry);
      for (const cls of PAYLOAD_CLASSES) {
        if (!r.active()) break;
        record(await r.call("range_request", { method, path, role: "anonymous", payloadClass: cls, technique: RT.web }), entry);
      }
    }

    // ---- pipeline surface: can an outsider's pull request trigger it, and if it deploys, what can the deployed software already reach ----
    let tried = 0;
    for (const b of blocks.filter((x) => x.kind === "job")) {
      if (tried >= maxWorkflows || !r.active()) break;
      tried++;
      const res = await r.call("range_trigger", { workflowId: b.id, technique: RT.supplyChain });
      if (!res.ok) continue; // not a workflow, or refused: a blind attacker learns this the same way, by trying
      const d = (res.result as { data?: { deploys?: { envId: string; state: string }[]; proofs?: string[] } }).data ?? {};
      if (!d.proofs?.length) continue;
      const envs = (d.deploys ?? []).filter((x) => x.state === "success").map((x) => x.envId);
      if (!envs.length) { for (const proof of d.proofs) paths.push({ kind: "pipeline", entry: b.label, technique: RT.supplyChain, proof, findingId: byProof.get(proof)?.findingId, steps: [b.label], crown: [], auditSteps: [res.step] }); continue; }
      const services = [...new Set(envs.flatMap((envId) => serviceDeploys.filter((e) => e.to === envId).map((e) => e.from)))];
      for (const svc of services) {
        if (!r.active()) break;
        const flow = await r.call("range_flow", { nodeId: svc });
        if (!flow.ok) continue;
        const fd = (flow.result as { data?: { ok?: boolean; reached?: string[]; crown?: string[] } }).data ?? {};
        if (!fd.ok) continue;
        for (const proof of d.proofs) {
          paths.push({ kind: "pipeline", entry: b.label, technique: RT.supplyChain, proof, findingId: byProof.get(proof)?.findingId, steps: [b.label, label(svc), ...(fd.reached ?? []).map(label)], crown: fd.crown ?? [], auditSteps: [res.step, flow.step] });
        }
      }
    }
  });

  // ---- from paths to a verdict per finding they reached, and the overall summary ----
  const simulations: Record<string, Simulation> = {};
  const verifiedAt = now();
  const byFinding = new Map<string, ReachPath[]>();
  for (const p of paths) if (p.findingId) (byFinding.get(p.findingId) ?? byFinding.set(p.findingId, []).get(p.findingId)!).push(p);
  for (const [findingId, ps] of byFinding) {
    const crown = [...new Set(ps.flatMap((p) => p.crown))];
    const reaches = [...new Set(ps.flatMap((p) => p.steps))].slice(0, 12);
    simulations[findingId] = {
      by: "redteam", verdict: "confirmed", confidence: crown.length ? "medium" : "low", reaches,
      steps: [...new Set(ps.flatMap((p) => p.auditSteps))].sort((a, b) => a - b), source: { read: false }, runId: roe.runId, head: run.head, verifiedAt,
      summary: crown.length
        ? `Reachable with no credentials at all, from the public surface, via ${ps.length === 1 ? "one path" : `${ps.length} distinct paths`}; at least one of them reaches a protected data store. Found by probing the public surface only, with no knowledge of where the weaknesses were seeded.`
        : "Reachable with no credentials, but no path from it was found to reach a protected data store in this map.",
    };
  }

  const crownJewels = spec.datastores.length;
  const crownsReached = new Set(paths.flatMap((p) => p.crown)).size;
  const distinctEntries = new Set(paths.filter((p) => p.crown.length > 0).map((p) => p.entry)).size;
  const likelihood: ReachSummary["likelihood"] = crownJewels === 0 ? "none" : crownsReached === 0 ? "none" : distinctEntries >= 2 ? "high" : "medium";
  const summary: ReachSummary = { crownJewels, crownsReached, distinctEntries, likelihood };

  if (crownJewels === 0) notes.push("This map has no data store, so reachability to a crown jewel could not be assessed.");
  else notes.push(`Reachability from the public surface, with no credentials: ${crownsReached} of ${crownJewels} crown jewel${crownJewels === 1 ? "" : "s"} reached (${likelihood} likelihood), via ${distinctEntries} distinct entry point${distinctEntries === 1 ? "" : "s"}.`);
  if (!run.ok && run.stopReason !== "finished") notes.push(`The run ended early (${run.stopReason}${run.refusal ? `: ${run.refusal}` : ""}).`);

  const counts: Record<string, number> = {};
  for (const s of Object.values(simulations)) counts[s.verdict] = (counts[s.verdict] ?? 0) + 1;
  return { paths, summary, simulations, run, runId: roe.runId, spec, counts, notes };
}
