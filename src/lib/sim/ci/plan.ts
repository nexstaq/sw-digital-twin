import type { TwinGraph } from "@/lib/graph/types";
import { techniqueId } from "../roe";
import type { FindingSet } from "@/lib/security/types";
import { z } from "zod";
import type { KillRegistry } from "../agent/killswitch";
import { runPlan, type AgentRunResult } from "../agent/runtime";
import { defineTool, type AnyTool } from "../agent/tools";
import { T as ACCESS_T } from "../graybox/roe";
import { RT } from "../redteam/roe";
import { buildRange } from "../range/generate";
import { sha256Hex } from "../range/sha256";
import type { EndpointSpec, RangeSpec } from "../range/types";

/**
 * Authorised external runs, part one: deciding, server-side, exactly which GET requests a customer's OWN CI runner may make
 * against their OWN staging site, and why. Nothing here sends a byte to that site: "Our servers never send simulation
 * traffic to third parties" (X9) means the actual HTTP calls happen on the runner, in the generated workflow (`workflow.ts`),
 * strictly from the list this function hands back. The runner reports what it saw afterward (`apply.ts`).
 *
 * This still goes through the exact same guard every other run does (`allow()`, X0): the target is the ROE's own
 * `ci-runner` kind, capped at `probe` on any real target regardless of which agent profile is chosen, and every one of
 * these "requests" is really a *decision*, audited like any other.
 */

export const PROFILES = ["access", "reachability"] as const;
export type Profile = (typeof PROFILES)[number];

export interface PlanCandidate { path: string }
export interface PlanResult {
  runId: string; head: string;
  /** a path that cannot exist: a site that answers it exactly like a real page proves nothing, same trick as the verified-domain probe (X5) */
  controlPath: string;
  routes: PlanCandidate[];
  notes: string[];
  run: AgentRunResult;
}

export interface PlanInput {
  repo: string; url: string; profile: Profile; sha: string; graph: TwinGraph; set: FindingSet;
  /**
   * who to credit this run's authorisation to. There is no human click-through here: the repository owner's own
   * confirmation (the `SECURITY_TEST_CONFIRM_OWNER` variable the generated workflow refuses to run without) IS the
   * approval, re-asserted every time the workflow runs, so this is the OIDC-proven identity that triggered it
   * (the caller gets this from `verifyActionsToken`), never a value an agent could invent.
   */
  approvedBy: string;
  maxRoutes?: number; now?: () => number; killRegistry?: KillRegistry;
}

const noParam = (e: EndpointSpec) => e.segments.every((s) => !/^[:[{]/.test(s));

function candidatesFor(profile: Profile, spec: RangeSpec): EndpointSpec[] {
  const plainGet = spec.endpoints.filter((e) => (e.method === "GET" || e.method === "PAGE") && !e.object && noParam(e));
  // "access": the same question X5's gray-box probe asks of one domain whose ownership was proved by DNS - here authorisation
  // comes from the OIDC token and the repository's own confirmation, so only routes the map says are NOT meant for anonymous
  // callers are worth asking about at all.
  return profile === "access" ? plainGet.filter((e) => e.minRole !== "anonymous") : plainGet;
}

function planRequestTool(o: { url: string; spec: RangeSpec }) {
  return defineTool({
    name: "ci_plan_request",
    description: "Authorise one GET request a customer's own CI runner may make against their own staging site. This never sends anything itself: the runner does, afterward, strictly from the authorised list. You must name the ATT&CK technique.",
    inputSchema: z.strictObject({ path: z.string().max(512), technique: techniqueId }),
    classOf: () => "probe",
    techniqueOf: (i) => i.technique,
    targetOf: (i) => ({ kind: "ci-runner" as const, url: `${o.url}${i.path}` }),
    source: "tool-output",
    summarize: () => "authorised",
    run: async (i) => ({ path: i.path }),
  });
}

export async function buildPlan(input: PlanInput): Promise<PlanResult> {
  const now = input.now ?? Date.now;
  const spec = buildRange({ sha: input.sha, graph: input.graph }, input.set);
  const candidates = candidatesFor(input.profile, spec).sort((a, b) => a.path.localeCompare(b.path)).slice(0, input.maxRoutes ?? 25);
  const technique = input.profile === "access" ? ACCESS_T.access : RT.web;
  const agent = input.profile === "access" ? ("graybox" as const) : ("redteam" as const);

  const at = now();
  const runId = `cp_${sha256Hex(`${input.repo}|${input.url}|${input.profile}|${at}`).slice(0, 12)}`;
  const controlPath = `/__mc-control-${sha256Hex(runId).slice(0, 8)}`;
  const roe = {
    version: 1 as const, runId, repo: input.repo,
    targets: [{ kind: "ci-runner" as const, repo: input.repo, url: input.url }],
    agents: [agent],
    allowedClasses: ["observe" as const, "probe" as const],
    allowedTechniques: [technique], forbiddenTechniques: [] as string[],
    window: { notBefore: at - 60_000, notAfter: at + 30 * 60_000 },
    budgets: { steps: Math.min(500, 2 + candidates.length), tokens: 1000, wallMs: 5 * 60_000, costUsd: 1 },
    approval: { approvedBy: input.approvedBy, approvedAt: at - 60_000 },
    killSwitchId: `kill_${runId}`,
  };
  const tool = planRequestTool({ url: input.url, spec });

  const notes: string[] = [];
  const routes: PlanCandidate[] = [];
  const run = await runPlan({ roe, agent, tools: [tool] as unknown as AnyTool[], now, killRegistry: input.killRegistry }, async (r) => {
    if (!candidates.length) { notes.push(`The map has no plain GET route ${input.profile === "access" ? "meant for signed-in users or admins " : ""}to check from the outside.`); return; }
    for (const e of candidates) {
      if (!r.active()) { notes.push("The run was stopped before every route was authorised."); break; }
      const res = await r.call("ci_plan_request", { path: e.path, technique });
      if (res.ok) routes.push({ path: e.path });
    }
  });
  if (!run.ok && run.stopReason !== "finished") notes.push(`The run ended early (${run.stopReason}${run.refusal ? `: ${run.refusal}` : ""}).`);

  return { runId, head: run.head, controlPath, routes, notes, run };
}
