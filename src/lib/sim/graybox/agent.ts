import type { TwinGraph } from "@/lib/graph/types";
import type { Finding, FindingSet, Simulation } from "@/lib/security/types";
import type { KillRegistry } from "../agent/killswitch";
import { runPlan, type AgentRunResult, type CallResult, type Run } from "../agent/runtime";
import type { AnyTool } from "../agent/tools";
import { inspectTool, requestTool, ROLES_FOR } from "../agent/tools/range";
import { buildRange } from "../range/generate";
import { startRange, type RangeInstance } from "../range/runtime";
import { ROLES, roleRank, type AbuseClass, type RangeSpec, type Role, type WeaknessKind } from "../range/types";
import { grayboxRoe, T } from "./roe";

/**
 * The gray-box agent. It knows what an outside tester with an account would know: the list of routes, who each is INTENDED for, and one set of
 * credentials per role (anonymous, user, admin). It does not read the findings or see where weaknesses are seeded. It tests access control
 * systematically, route by route, and records every observation; a weakness is reported only where the range actually misbehaves.
 *
 * Tests: function-level authorisation (a lower role calls a route meant for a higher one), object-level authorisation (a user reads someone
 * else's object: IDOR), session handling (an expired or planted session), workflow abuse (a skipped step, a replayed request), attempt limits
 * (a burst against a sign-in route), and mass assignment followed by an escalation check (does a privileged field in a write make the caller
 * an admin?). Like the white-box agent it is deterministic and runs through the guarded path, so every request is checked, logged and counted.
 *
 * What it can and cannot say. The range's behaviour comes from the findings, so this reproduces what a report claimed; it does not discover
 * new weaknesses in code. What it adds is a blind, repeatable test that reproduces the behaviour from the outside, with evidence.
 */

export type TestName = "function-level" | "object-level" | "session" | "workflow" | "rate-limit" | "mass-assignment" | "escalation";

export interface Observation {
  test: TestName;
  route: string;
  role: Role;
  expected: string;
  observed: string;
  /** the range did not behave the way a correctly built system would */
  violation: boolean;
  status: number;
  /** the harmless marker the range returned, which is what ties a violation to the finding that reported it */
  proof?: string;
  technique: string;
  /** audit-log steps of the requests this rests on */
  steps: number[];
}

export interface GrayboxInput {
  repo: string; sha: string; graph: TwinGraph; set: FindingSet;
  /** at most this many routes are tested, in path order */
  maxRoutes?: number;
  now?: () => number;
  killRegistry?: KillRegistry;
}

export interface GrayboxResult {
  observations: Observation[];
  /** verdicts for the findings these tests bear on (access-control weaknesses, and open write routes) */
  simulations: Record<string, Simulation>;
  run: AgentRunResult;
  runId: string;
  spec: RangeSpec;
  counts: Record<string, number>;
  notes: string[];
}

/** the kinds of finding this agent gives a verdict on */
export const GRAYBOX_KINDS: ReadonlySet<WeaknessKind> = new Set<WeaknessKind>(["idor", "missing-authz", "mass-assignment", "no-rate-limit", "weak-session", "skip-step", "replay", "no-auth"]);

interface RouteInfo { id: string; method: string; path: string; minRole: Role; object: boolean; login: boolean }
type Reply = { ok: boolean; status: number; proof?: string; applied?: boolean; via?: string; step?: number; why?: string };

const isParam = (seg: string) => seg.startsWith(":") || (seg.startsWith("[") && seg.endsWith("]")) || (seg.startsWith("{") && seg.endsWith("}"));
const WRITE = new Set(["POST", "PUT", "PATCH", "DELETE", "ALL"]);
const concrete = (path: string, id: "1" | "2") => `/${path.split("/").filter(Boolean).map((s) => (isParam(s) ? id : s)).join("/")}`;

function routesOf(inspect: CallResult): RouteInfo[] {
  if (!inspect.ok) return [];
  const data = (inspect.result as { data?: { routes?: unknown } }).data;
  const out: RouteInfo[] = [];
  for (const x of Array.isArray(data?.routes) ? data.routes : []) {
    const r = x as Partial<RouteInfo>;
    if (typeof r.id === "string" && typeof r.method === "string" && typeof r.path === "string" && (ROLES as readonly string[]).includes(r.minRole as string)) {
      out.push({ id: r.id, method: r.method, path: r.path, minRole: r.minRole as Role, object: !!r.object, login: !!r.login });
    }
  }
  return out.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
}

const DESCRIBE: Record<TestName, (o: Observation, intended: Role) => string> = {
  "function-level": (o, intended) => `${o.route} accepted ${o.role === "anonymous" ? "a request from someone who is not signed in" : `a signed-in ${o.role}`}, although it is meant for ${intended === "admin" ? "admins" : "signed-in users"}.`,
  "object-level": (o) => `${o.route} let a signed-in user read another user's object.`,
  session: (o) => `${o.route} accepted ${o.observed.includes("planted") ? "a session planted by an attacker" : "an expired session"}.`,
  workflow: (o) => `${o.route} accepted ${o.observed.includes("replay") ? "a replayed request" : "a request that skipped a required step"}.`,
  "rate-limit": (o) => `${o.route} kept accepting attempts without ever slowing down (${o.observed}).`,
  "mass-assignment": (o) => `${o.route} accepted a privileged field in a write that it should have ignored.`,
  escalation: (o) => `After that, a plain user could reach ${o.route}, a route meant for admins.`,
};

export async function discoverAccess(input: GrayboxInput): Promise<GrayboxResult> {
  const now = input.now ?? Date.now;
  const spec = buildRange({ sha: input.sha, graph: input.graph }, input.set);
  const range: RangeInstance = startRange(spec);
  const notes: string[] = [];
  const observations: Observation[] = [];
  const tested = new Set<string>();

  const maxRoutes = input.maxRoutes ?? 40;
  const roe = grayboxRoe({ repo: input.repo, rangeId: spec.id, now: now(), routes: Math.min(maxRoutes, spec.endpoints.length) });
  const tools = [inspectTool({ spec, blind: true }), requestTool({ range, spec, roles: ROLES_FOR.graybox })] as unknown as AnyTool[];

  const run = await runPlan({ roe, agent: "graybox", tools, now, killRegistry: input.killRegistry, teardown: [() => range.destroy()] }, async (r: Run) => {
    const inspect = await r.call("range_inspect", {});
    const all = routesOf(inspect);
    const routes = all.slice(0, maxRoutes);
    if (all.length > routes.length) notes.push(`Only the first ${routes.length} of ${all.length} routes were tested.`);

    const ask = async (route: RouteInfo, role: Role, o: { id?: "1" | "2"; abuse?: AbuseClass; technique?: string } = {}): Promise<Reply> => {
      const res = await r.call("range_request", { method: route.method === "PAGE" || route.method === "ALL" ? "GET" : route.method, path: concrete(route.path, o.id ?? "1"), role, technique: o.technique ?? T.access, ...(o.abuse ? { abuse: o.abuse } : {}) });
      if (!res.ok) return { ok: false, status: 0, why: (res as { reason?: string }).reason ?? "stopped" };
      const d = (res.result as { data?: { status?: number; proof?: string; applied?: boolean; via?: string } }).data ?? {};
      return { ok: true, status: d.status ?? 0, proof: d.proof, applied: d.applied, via: d.via, step: res.step };
    };
    const record = (test: TestName, route: RouteInfo, role: Role, expected: string, observed: string, violation: boolean, a: Reply, technique: string, extra: number[] = []) => {
      observations.push({ test, route: `${route.method} ${route.path}`, role, expected, observed, violation, status: a.status, ...(a.proof ? { proof: a.proof } : {}), technique, steps: [...(a.step !== undefined ? [a.step] : []), ...extra] });
    };

    // ---- pass 1: tests that change nothing that later tests depend on ----
    for (const route of routes) {
      if (!r.active()) { notes.push("The run was stopped before every route was tested; the rest are unchanged."); break; }
      const label = `${route.method} ${route.path}`;
      const write = WRITE.has(route.method);
      tested.add(route.id);

      // function-level authorisation: with the credentials the route is meant for it works; with a lower role it must be refused
      let openToAnyone = false;
      if (route.minRole !== "anonymous") {
        const base = await ask(route, route.minRole, { technique: T.credentials });
        if (base.status === 200) {
          for (const lower of ROLES.filter((x) => roleRank(x) < roleRank(route.minRole))) {
            const a = await ask(route, lower);
            if (lower === "anonymous" && a.status === 200) openToAnyone = true;
            record("function-level", route, lower, `refused: a ${lower} is below ${route.minRole}`, a.status === 200 ? "accepted" : `refused (${a.status})`, a.status === 200, a, T.access);
          }
        } else notes.push(`${label} did not answer its own intended role (${base.status}), so its access rules were not tested.`);
      }

      // object-level authorisation (IDOR): a user can read their own object, and must not be able to read someone else's
      if (route.object && route.minRole !== "admin") {
        const own = await ask(route, "user", { id: "1" });
        if (own.status === 200) {
          const other = await ask(route, "user", { id: "2" });
          record("object-level", route, "user", "refused: the object belongs to another user", other.status === 200 ? "accepted" : `refused (${other.status})`, other.status === 200, other, T.access, own.step !== undefined ? [own.step] : []);
        }
      }

      // session handling: an expired session, and one planted by an attacker, must both be refused. If the route already answers someone with NO
      // session, there is nothing to add: "it accepted an expired session" would only repeat that the route is open to everyone.
      if (route.minRole !== "anonymous" && !openToAnyone) {
        for (const [cls, what] of [["stale-session", "an expired session"], ["fixed-session", "a planted session"]] as const) {
          const a = await ask(route, route.minRole, { abuse: cls, technique: T.session });
          record("session", route, route.minRole, `refused: ${what}`, a.status === 200 ? `accepted ${what}` : `refused (${a.status})`, a.status === 200, a, T.session);
        }
      }

      // workflow abuse: a skipped step and a replayed request must both be refused on a write
      if (write && route.minRole !== "anonymous" && !route.login) {
        for (const cls of ["skip-step", "replay"] as const) {
          const a = await ask(route, route.minRole, { abuse: cls });
          record("workflow", route, route.minRole, `refused: ${cls === "replay" ? "a replayed request" : "a skipped step"}`, a.status === 200 ? `accepted ${cls === "replay" ? "a replay" : "a skipped step"}` : `refused (${a.status})`, a.status === 200, a, T.access);
        }
      }

      // attempt limits: a sign-in route must slow down a burst
      if (route.login) {
        const burst: Reply[] = [];
        for (let i = 0; i < 12 && r.active(); i++) {
          burst.push(await ask(route, "anonymous", { technique: T.bruteForce }));
          // if the very first attempt shows this route is not open to someone who is not signed in, it is not a sign-in route and there is nothing to burst
          if (i === 0 && [401, 403, 404, 405].includes(burst[0].status)) { notes.push(`${label} is not open to anonymous callers (${burst[0].status}), so it was not treated as a sign-in route.`); break; }
        }
        if (burst.length < 11) continue;
        const limited = burst.some((b) => b.status === 429);
        const last = burst.at(-1) ?? { ok: false, status: 0 };
        const proofed = burst.find((b) => b.proof) ?? last;
        record("rate-limit", route, "anonymous", "refused with 429 before the twelfth attempt", limited ? "limited" : `${burst.length} attempts, none limited`, !limited && burst.length >= 11, { ...last, proof: proofed.proof, step: proofed.step }, T.bruteForce, burst.map((b) => b.step).filter((s): s is number => s !== undefined && s !== proofed.step));
      }
    }

    // ---- pass 2: mass assignment, then whether it made the caller an admin ----
    const adminRoute = routes.find((x) => x.minRole === "admin" && !x.object && x.method === "GET") ?? routes.find((x) => x.minRole === "admin" && !x.object);
    for (const route of routes) {
      if (!r.active()) break;
      if (!WRITE.has(route.method) || route.minRole !== "user" || route.login) continue;
      const a = await ask(route, "user", { abuse: "privileged-field" });
      const applied = a.applied === true;
      record("mass-assignment", route, "user", "ignored: a privileged field in a write must not be applied", applied ? "applied" : "ignored", applied, a, T.access);
      if (applied && adminRoute) {
        const b = await ask(adminRoute, "user", { technique: T.credentials });
        const escalated = b.status === 200 && b.via === "escalated";
        record("escalation", adminRoute, "user", "refused: the caller is still a plain user", escalated ? "accepted: the caller had become an admin" : `refused (${b.status})`, escalated, b, T.credentials, a.step !== undefined ? [a.step] : []);
      } else if (applied) notes.push("A privileged field was accepted, but there is no admin route in the list to check whether it made the caller an admin.");
    }
  });

  // ---- from observations to verdicts on findings ----
  const byProof = new Map(spec.weaknesses.map((w) => [w.proof, w]));
  const simulations: Record<string, Simulation> = {};
  const verifiedAt = now();
  const stub = { runId: roe.runId, head: run.head, verifiedAt };
  const violated = new Map<string, Observation[]>();
  for (const o of observations) if (o.violation && o.proof) { const w = byProof.get(o.proof); if (w) (violated.get(w.findingId) ?? violated.set(w.findingId, []).get(w.findingId)!).push(o); }

  for (const w of spec.weaknesses) {
    if (!GRAYBOX_KINDS.has(w.kind)) continue;
    const obs = violated.get(w.findingId);
    if (obs?.length) {
      const first = obs[0];
      const intended = spec.endpoints.find((e) => `${e.method} ${e.path}` === first.route)?.minRole ?? "user";
      const text = [...new Set(obs.map((o) => DESCRIBE[o.test](o, intended)))].join(" ");
      simulations[w.findingId] = {
        ...stub, by: "graybox", verdict: "confirmed", confidence: "medium", reaches: [], steps: [...new Set(obs.flatMap((o) => o.steps))].sort((a, b) => a - b), source: { read: false },
        test: { entry: first.route, role: first.role, technique: first.technique, steps: obs.map((o) => ({ name: o.test, request: { method: o.route.split(" ")[0], path: o.route.split(" ").slice(1).join(" "), role: o.role }, expect: o.expected })) },
        summary: `${text} Found by testing from the outside with an account; the code was not read, so this shows the behaviour, not why.`,
      };
    } else if (!w.reachable) {
      simulations[w.findingId] = { ...stub, by: "graybox", verdict: "unreachable", confidence: "low", reaches: [], steps: [], source: { read: false }, summary: "No route on the map has the behaviour this report is about, so it could not be tested. The map can be missing a route, so this is not a clean bill of health." };
    } else {
      const wasTested = w.endpointIds.some((id) => tested.has(id));
      if (!wasTested) {
        simulations[w.findingId] = { ...stub, by: "graybox", verdict: "not-reproduced", confidence: "low", reaches: [], steps: [], source: { read: false }, summary: `The route this report is about was not tested: only the first ${maxRoutes} routes are.` };
        continue;
      }
      simulations[w.findingId] = { ...stub, by: "graybox", verdict: "not-reproduced", confidence: "low", reaches: [], steps: observations.filter((o) => w.endpointIds.some((id) => spec.endpoints.find((e) => e.nodeId === id && `${e.method} ${e.path}` === o.route))).flatMap((o) => o.steps).slice(0, 6), source: { read: false }, summary: "The tests that would show this ran and the simulated copy behaved correctly, so it could not be reproduced from the outside." };
    }
  }
  const counts: Record<string, number> = {};
  for (const s of Object.values(simulations)) counts[s.verdict] = (counts[s.verdict] ?? 0) + 1;
  if (!run.ok && run.stopReason !== "finished") notes.push(`The run ended early (${run.stopReason}${run.refusal ? `: ${run.refusal}` : ""}).`);
  const violations = observations.filter((o) => o.violation).length;
  notes.push(`${tested.size} routes tested from the outside with one set of credentials per role: ${violations} unexpected behaviour${violations === 1 ? "" : "s"} seen.`);
  return { observations, simulations, run, runId: roe.runId, spec, counts, notes };
}

export type { Finding };
