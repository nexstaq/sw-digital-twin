import type { TwinGraph } from "@/lib/graph/types";
import { byPriority } from "@/lib/security/map";
import type { Finding, FindingSet, Simulation } from "@/lib/security/types";
import type { KillRegistry } from "../agent/killswitch";
import { runPlan, type AgentRunResult, type CallResult, type Run } from "../agent/runtime";
import type { AnyTool } from "../agent/tools";
import { inspectTool, requestTool, ROLES_FOR } from "../agent/tools/range";
import { buildRange } from "../range/generate";
import { startRange, type RangeInstance } from "../range/runtime";
import { PAYLOAD_CLASSES, type PayloadClass, type RangeRequest, type RangeSpec, type Role, type Weakness } from "../range/types";
import { whiteboxRoe, WHITEBOX_TECHNIQUE } from "./roe";
import { checkMitigation, proposePatch, type Excerpt, type Patch } from "./source";

/**
 * The white-box agent. It is deterministic: no model is called. For each finding that the range models, it writes an exploit TEST (a
 * short, replayable request sequence), runs it against the range through the same guarded path every agent uses (so every step is
 * checked, logged and counted), and turns the outcome into a verdict a person can act on.
 *
 * What a verdict does and does not say. The range is built FROM the scanner's findings, so exploiting it cannot independently prove
 * the code is vulnerable. What the simulation adds is: can an outside request actually reach this weakness through the modelled
 * architecture and its sign-in rules, what does it then reach, and a test that can be run again. With source (only if the owner
 * allowed it) it also looks for a visible mitigation, which is how a false alarm gets downgraded. A patch is proposed as a diff, never
 * applied, and "re-run against a copy without the weakness" shows the TEST discriminates; it does not prove the diff is right.
 */

export interface VerifyInput {
  repo: string;
  sha: string;
  graph: TwinGraph;
  set: FindingSet;
  /** present only when the repository owner allowed source to be read; returns the lines around a finding */
  excerpt?: (f: Finding) => Promise<Excerpt | null>;
  /** only these findings */
  only?: string[];
  /** at most this many findings are exercised, highest priority first */
  max?: number;
  now?: () => number;
  killRegistry?: KillRegistry;
}

export interface VerifyResult {
  simulations: Record<string, Simulation>;
  /** proposed diffs, in memory only. They contain source, so they are never stored. */
  patches: Record<string, Patch>;
  run: AgentRunResult;
  runId: string;
  spec: RangeSpec;
  counts: Record<string, number>;
  notes: string[];
}

const WEAKNESS_NAME: Record<string, string> = {
  "sql-injection": "SQL injection", "command-injection": "command injection", "code-injection": "code injection", "path-traversal": "path traversal",
  ssrf: "server-side request forgery", xss: "cross-site scripting", "open-redirect": "open redirect", "no-auth": "unauthenticated write",
};
const isParam = (seg: string) => seg.startsWith(":") || (seg.startsWith("[") && seg.endsWith("]")) || (seg.startsWith("{") && seg.endsWith("}"));

type Data = { status?: number; proof?: string; reached?: string[]; crown?: string[] };
const dataOf = (r: CallResult): Data | undefined => (r.ok ? ((r.result as { data?: Data }).data ?? undefined) : undefined);
const stepOf = (r: CallResult) => (r.ok ? [r.step] : []);
const refusedWhy = (r: CallResult) => (r.ok ? "" : (r as { reason?: string }).reason ?? "stopped");

export async function verifyFindings(input: VerifyInput): Promise<VerifyResult> {
  const now = input.now ?? Date.now;
  const spec = buildRange({ sha: input.sha, graph: input.graph }, input.set);
  const range = startRange(spec);
  const ranges: RangeInstance[] = [range];
  let active: RangeInstance = range;
  const holder = { handle: (r: RangeRequest) => active.handle(r) } as unknown as RangeInstance; // lets one tool talk to the original range, then a patched copy
  const label = (id: string) => input.graph.nodes.find((n) => n.id === id)?.label ?? id;

  const candidates = [...input.set.findings]
    .sort(byPriority)
    .filter((f) => !input.only || input.only.includes(f.id))
    .map((f) => ({ f, w: spec.weaknesses.find((x) => x.findingId === f.id) }))
    .filter((c): c is { f: Finding; w: Weakness } => !!c.w && (!!c.w.payload || c.w.kind === "no-auth"))
    .slice(0, input.max ?? 25);

  const notes: string[] = [];
  const sims: Record<string, Simulation> = {};
  const patches: Record<string, Patch> = {};
  const stub = { by: "whitebox" as const, runId: "", head: "", verifiedAt: 0 };

  const roe = whiteboxRoe({ repo: input.repo, rangeId: spec.id, now: now(), findings: candidates.length });
  const tools = [inspectTool({ spec, weaknesses: true }), requestTool({ range: holder, spec, roles: ROLES_FOR.whitebox })] as unknown as AnyTool[];

  const run = await runPlan({ roe, agent: "whitebox", tools, now, killRegistry: input.killRegistry, teardown: [() => { for (const r of ranges) r.destroy(); }] }, async (r: Run) => {
    const inspect = await r.call("range_inspect", {});
    const inspectSteps = stepOf(inspect);

    for (const { f, w } of candidates) {
      if (!r.active()) { notes.push("The run was stopped before every finding was checked; the rest are unchanged."); break; }
      const route = w.reachable ? spec.endpoints.find((e) => e.nodeId === w.endpointIds[0]) : undefined;
      const where = `${f.ruleId} ${f.path}${f.line ? `:${f.line}` : ""}`;

      if (!route) {
        sims[f.id] = { ...stub, verdict: "unreachable", confidence: "low", reaches: [], steps: inspectSteps, source: { read: false },
          summary: "Nothing exposed on the map reaches this code, so it is lower priority. The map can be missing a path, so this is not a clean bill of health." };
        r.conclude(`unreachable/low: ${where}`, true);
        continue;
      }

      // the lowest role the route is meant for: the test is about the weakness, not about whether the caller was allowed in
      const role: Role = w.kind === "no-auth" || route.auth === "none" ? "anonymous" : route.minRole === "admin" ? "admin" : route.auth === "required" ? "user" : "anonymous";
      const method = route.method === "PAGE" || route.method === "ALL" ? "GET" : route.method;
      const path = `/${route.segments.map((s) => (isParam(s) ? "1" : s)).join("/")}`;
      const entry = `${method} ${path}`;
      const req = (extra: { role?: Role; payloadClass?: PayloadClass } = {}) => ({ method, path, role: extra.role ?? role, technique: WHITEBOX_TECHNIQUE, ...(extra.payloadClass ? { payloadClass: extra.payloadClass } : {}) });

      // ---- the exploit test ----
      const isPayload = !!w.payload;
      // The control must be a kind of hostile input this route has NO weakness for, or a second real weakness in the same file would make
      // the control "succeed" and wrongly sink the finding it is meant to support.
      // Two findings of the same kind in one route file are both "the" weakness to the route, which answers with the first one's marker. So a
      // marker from ANY weakness of this kind on this route counts as this finding's exploit, and as the baseline showing none.
      const own = new Set(spec.weaknesses.filter((q) => q.endpointIds.includes(route.nodeId) && (isPayload ? q.payload === w.payload : q.kind === "no-auth")).map((q) => q.proof));
      const mine = (p: string | undefined) => !!p && own.has(p);
      const taken = new Set(spec.weaknesses.filter((q) => q.endpointIds.includes(route.nodeId)).map((q) => q.payload));
      const control = isPayload ? PAYLOAD_CLASSES.find((c) => !taken.has(c)) : undefined;
      const baseline = isPayload ? await r.call("range_request", req()) : undefined;
      const exploit = await r.call("range_request", isPayload ? req({ payloadClass: w.payload }) : req({ role: "anonymous" }));
      const ctl = await r.call("range_request", isPayload ? req({ payloadClass: control }) : req({ role: "user" }));
      const [b, e, c] = [baseline && dataOf(baseline), dataOf(exploit), dataOf(ctl)];
      const calls = [baseline, exploit, ctl].filter((x): x is CallResult => !!x);
      const test: Simulation["test"] = {
        entry, role, ...(w.payload ? { payloadClass: w.payload } : {}), technique: WHITEBOX_TECHNIQUE,
        steps: [
          ...(isPayload ? [{ name: "baseline" as const, request: { method, path, role }, expect: "an ordinary request works and shows no weakness" }] : []),
          { name: "exploit" as const, request: { method, path, role: isPayload ? role : "anonymous", ...(w.payload ? { payloadClass: w.payload } : {}) }, expect: isPayload ? "the weakness is exercised (a proof marker comes back)" : "an anonymous write is accepted (a proof marker comes back)" },
          { name: "control" as const, request: { method, path, role: isPayload ? role : "user", ...(control ? { payloadClass: control } : {}) }, expect: isPayload ? "a different kind of hostile input is rejected" : "a signed-in call shows no weakness" },
        ],
      };

      const refused = calls.find((x) => !x.ok);
      if (refused) {
        sims[f.id] = { ...stub, verdict: "not-reproduced", confidence: "low", reaches: [], test, steps: calls.flatMap(stepOf), source: { read: false },
          summary: `The test could not be run: the rules of this run refused a step (${refusedWhy(refused)}).` };
        r.conclude(`not-reproduced/low: ${where}`, false);
        continue;
      }
      // Only THIS weakness's marker matters: the same route can carry another weakness (an open write route that is also injectable),
      // and an ordinary request to it rightly shows that other one.
      const reproduced = (isPayload ? b?.status === 200 && !mine(b.proof) && c?.status === 400 && !mine(c.proof) : c?.status === 200 && !mine(c.proof)) && e?.status === 200 && mine(e.proof);
      if (!reproduced) {
        sims[f.id] = { ...stub, verdict: "not-reproduced", confidence: "low", reaches: [], test, steps: calls.flatMap(stepOf), source: { read: false },
          summary: "The simulated copy did not behave the way the scanner's finding says, so this could not be reproduced." };
        r.conclude(`not-reproduced/low: ${where}`, false);
        continue;
      }

      // ---- the code, if we were allowed to read it ----
      const x = input.excerpt ? await input.excerpt(f).catch(() => null) : null;
      const mit = x && f.line ? checkMitigation(f.ruleId, f.line, x) : { mitigated: false as const };
      const reaches = [...new Set((e.reached ?? []).map(label))].slice(0, 8);
      // the range gives every route of a service the service's dependencies, so this says what the SERVICE can reach, not what this route is known to touch
      const impact = reaches.length ? ` The service behind it can reach ${reaches.join(", ")}${e.crown?.length ? ", including the data store holding the data worth protecting" : ""}.` : "";
      const steps = [exploit, ctl, ...(baseline ? [baseline] : [])].flatMap(stepOf);

      if (x && mit.mitigated) {
        sims[f.id] = { ...stub, verdict: "mitigated", confidence: "low", reaches, test, steps, source: { read: true, mitigation: mit.why },
          summary: `A request can reach this code, but the code shows ${mit.why}. This is probably a false alarm; confirm by reading it.` };
        r.conclude(`mitigated/low: ${where}`, true);
        continue;
      }

      const scanner = f.confidence;
      // With the code read and no protection seen it can reach "high". Without it the simulation shows the way in, not that the code is vulnerable, so it stops at "medium".
      const confidence: Simulation["confidence"] = x ? (scanner === "low" ? "medium" : "high") : scanner === "low" ? "low" : "medium";
      const how = w.kind === "no-auth" ? "accepts a write from someone who is not signed in" : `can be used for ${WEAKNESS_NAME[w.kind] ?? w.kind}`;
      const sim: Simulation = { ...stub, verdict: "confirmed", confidence, reaches, test, steps, source: { read: !!x },
        summary: `${w.kind === "no-auth" ? `${entry} ${how}.` : `${entry} ${how}.`}${impact} ${x ? "The few lines read around it show no protection." : "The code was not read, so this shows the way in, not that the code is vulnerable."}` };

      // ---- a patch, and the same test against a copy without the weakness ----
      if (x && f.line && isPayload) {
        const patch = proposePatch(f.ruleId, f.line, x);
        if (patch) {
          const copy = startRange({ ...spec, weaknesses: spec.weaknesses.filter((q) => q.id !== w.id) });
          ranges.push(copy);
          r.note("re-running the test against a copy of the range with this weakness removed: an emulation of the fix, not your code");
          active = copy;
          const b2 = await r.call("range_request", req());
          const e2 = await r.call("range_request", req({ payloadClass: w.payload }));
          active = range;
          const [bd, ed] = [dataOf(b2), dataOf(e2)];
          const rejected = bd?.status === 200 && !mine(bd.proof) && ed?.status === 400 && !mine(ed.proof);
          sim.patch = { kind: patch.kind, retest: rejected ? "rejected" : "still-exploited" };
          sim.steps = [...sim.steps, ...stepOf(e2)];
          patches[f.id] = patch;
        }
      }
      sims[f.id] = sim;
      r.conclude(`confirmed/${confidence}: ${where}`, true);
    }
  });

  const verifiedAt = now();
  for (const s of Object.values(sims)) { s.runId = roe.runId; s.head = run.head; s.verifiedAt = verifiedAt; }
  const counts: Record<string, number> = {};
  for (const s of Object.values(sims)) counts[s.verdict] = (counts[s.verdict] ?? 0) + 1;
  if (!run.ok && run.stopReason !== "finished") notes.push(`The run ended early (${run.stopReason}${run.refusal ? `: ${run.refusal}` : ""}).`);
  const modelled = candidates.length, total = input.set.findings.length;
  if (total > modelled) notes.push(`${total - modelled} of ${total} findings were not exercised: the simulation covers code weaknesses a request can reach and open write routes. The rest are unchanged.`);
  return { simulations: sims, patches, run, runId: roe.runId, spec, counts, notes };
}

/** The findings with the simulation's verdicts attached. Findings it did not touch are returned exactly as they were. */
export function applySimulations(set: FindingSet, r: Pick<VerifyResult, "simulations" | "run" | "runId" | "counts" | "notes">, o: { sourceRead: boolean; at: number }): FindingSet {
  return {
    ...set,
    findings: set.findings.map((f) => (r.simulations[f.id] ? { ...f, simulation: r.simulations[f.id] } : f)),
    simulated: { at: o.at, runId: r.runId, head: r.run.head, sourceRead: o.sourceRead, counts: r.counts, notes: r.notes },
  };
}
