import { z } from "zod";
import {
  ABUSE_CLASSES, METHODS, PAYLOAD_CLASSES, ROLES, WRITE_METHODS, roleRank,
  type EndpointSpec, type Fault, type FlowResult, type RangeEvent, type RangeRequest, type RangeResponse, type RangeSpec, type Role, type Weakness, type WeaknessKind, type WorkflowResult,
} from "./types";

/**
 * The running range. Everything here is a plain function over in-memory data:
 *  - no sockets, files, processes, environment, `fetch`, wall clock or `Math.random` (isolation.test.ts fails the build if any appear);
 *  - time is a virtual counter that only moves when the range says so;
 *  - "randomness" is a seeded generator, so the same spec and the same calls always give the same events.
 * So there is nothing to block: the range has no way to reach the network in the first place.
 */

const MAX_EVENTS_DEFAULT = 20_000;
const MAX_DEPTH = 6;
const MAX_ADVANCE_MS = 24 * 60 * 60 * 1000;
const WEB_FLOW = new Set(["calls", "reads", "publishes"]);
const ASSETS = new Set(["datastore", "external", "queue", "env"]);

export class RangeDestroyedError extends Error { constructor(why: string) { super(`range destroyed: ${why}`); this.name = "RangeDestroyedError"; } }
export class RangeLimitError extends Error { constructor(what: string) { super(`range limit reached: ${what}`); this.name = "RangeLimitError"; } }

const RequestSchema = z.strictObject({
  method: z.enum(METHODS),
  path: z.string().max(512).regex(/^\/[A-Za-z0-9._~\-/:[\]{}@%]*$/),
  role: z.enum(ROLES),
  payload: z.strictObject({ class: z.enum(PAYLOAD_CLASSES) }).optional(),
  abuse: z.strictObject({ class: z.enum(ABUSE_CLASSES) }).optional(),
}).refine((r) => !(r.payload && r.abuse), { message: "a request carries a payload class or an abuse class, not both" });

/** how many attempts a login-like route allows per principal per minute (virtual time) before it answers 429 */
const RATE_LIMIT = 10;
const RATE_WINDOW_MS = 60_000;
/** synthetic data only: object 1 belongs to user A, 2 to user B, and so on */
const ownerOf = (objectId: string): "userA" | "userB" => ((/^\d+$/.test(objectId) ? Number(objectId) : [...objectId].reduce((a, c) => a + c.charCodeAt(0), 0)) % 2 === 1 ? "userA" : "userB");

const isParam = (seg: string) => seg.startsWith(":") || (seg.startsWith("[") && seg.endsWith("]")) || (seg.startsWith("{") && seg.endsWith("}"));

export interface RangeInstance {
  readonly id: string;
  readonly destroyed: boolean;
  /** virtual milliseconds since start */
  now(): number;
  advance(ms: number): void;
  handle(req: RangeRequest): RangeResponse;
  flow(entryNodeId: string): FlowResult;
  runWorkflow(workflowId: string, opts?: { sha?: string; trigger?: WorkflowResult["trigger"]; failJob?: string }): WorkflowResult;
  inject(nodeId: string, fault: Fault): void;
  clearFault(nodeId: string): void;
  queueDepth(nodeId: string): number;
  events(): readonly RangeEvent[];
  /** the events so far, then destroy */
  finish(): { events: RangeEvent[]; endedAt: number };
  destroy(reason?: string): void;
}

export function startRange(spec: RangeSpec, opts: { maxEvents?: number } = {}): RangeInstance {
  const maxEvents = opts.maxEvents ?? MAX_EVENTS_DEFAULT;
  let dead: string | null = null;
  let t = 0, seq = 0, traces = 0, runs = 0;
  let state = spec.seed >>> 0;
  const rand = () => { // mulberry32
    state = (state + 0x6d2b79f5) >>> 0;
    let z = state;
    z = Math.imul(z ^ (z >>> 15), z | 1);
    z ^= z + Math.imul(z ^ (z >>> 7), z | 61);
    return ((z ^ (z >>> 14)) >>> 0) / 4294967296;
  };

  const emus = new Map(spec.emulators.map((e) => [e.nodeId, e]));
  const crowns = new Map(spec.datastores.map((d) => [d.nodeId, d.crown]));
  const adj = new Map<string, { id: string; to: string; kind: string }[]>();
  for (const e of [...spec.edges].sort((a, b) => a.id.localeCompare(b.id))) (adj.get(e.from) ?? adj.set(e.from, []).get(e.from)!).push({ id: e.id, to: e.to, kind: e.kind });
  const faults = new Map<string, Fault>();
  const depth = new Map<string, number>();
  const deployed = new Map<string, string>();
  /** callers whose role an earlier request raised (a mass-assignment weakness), and the weakness that did it */
  const escalated = new Map<string, Weakness>();
  const attempts = new Map<string, number[]>();
  let log: RangeEvent[] = [];

  const alive = () => { if (dead) throw new RangeDestroyedError(dead); };
  const destroy = (reason = "finished") => { if (dead) return; dead = reason; log = []; faults.clear(); depth.clear(); deployed.clear(); escalated.clear(); attempts.clear(); emus.clear(); adj.clear(); crowns.clear(); };
  const emit = (e: Omit<RangeEvent, "seq" | "t"> & { t?: number }) => {
    if (log.length >= maxEvents) { destroy("event limit"); throw new RangeLimitError(`more than ${maxEvents} events`); }
    log.push({ seq: seq++, t: e.t ?? t, traceId: e.traceId, kind: e.kind, nodeId: e.nodeId, ...(e.from ? { from: e.from } : {}), ...(e.via ? { via: e.via } : {}), ok: e.ok, ms: e.ms, ...(e.status !== undefined ? { status: e.status } : {}), ...(e.note ? { note: e.note } : {}) });
  };
  const newTrace = () => `t${(++traces).toString(36).padStart(4, "0")}`;

  interface Ctx { traceId: string; visited: Set<string>; reached: string[]; failedAt?: string }

  function visit(id: string, from: string | undefined, via: { id: string; kind: string } | undefined, level: number, ctx: Ctx): { ok: boolean; ms: number } {
    const emu = emus.get(id)!;
    ctx.visited.add(id);
    let own = emu.latencyMs + Math.floor(rand() * (emu.jitterMs + 1));
    const f = faults.get(id);
    let ok = true;
    let note: string | undefined;
    if (f?.kind === "latency") own += f.ms;
    if (f?.kind === "outage") { ok = false; note = "outage"; }
    else if (f?.kind === "error" && rand() < f.rate) { ok = false; note = "injected error"; }
    if (!ok && !ctx.failedAt) ctx.failedAt = id;
    t += own;
    let total = own;
    if (ok && level < MAX_DEPTH) {
      for (const e of adj.get(id) ?? []) {
        if (!WEB_FLOW.has(e.kind) || !emus.has(e.to) || ctx.visited.has(e.to)) continue;
        const r = visit(e.to, id, e, level + 1, ctx);
        total += r.ms;
        if (!r.ok) { ok = false; note ??= `a dependency failed (${emus.get(e.to)!.label})`; }
      }
    }
    if (ok && ASSETS.has(emu.kind)) ctx.reached.push(id);
    if (ok && emu.kind === "queue" && via?.kind === "publishes") depth.set(id, (depth.get(id) ?? 0) + 1);
    // stamped when the visit ends (after its dependencies), so the log is always in time order
    emit({ traceId: ctx.traceId, kind: "visit", nodeId: id, from, via: via?.id, ok, ms: total, note });
    return { ok, ms: total };
  }

  function flow(entry: string): FlowResult {
    alive();
    if (!emus.has(entry)) throw new Error(`unknown node: ${entry}`);
    const ctx: Ctx = { traceId: newTrace(), visited: new Set(), reached: [] };
    const r = visit(entry, undefined, undefined, 0, ctx);
    return { ok: r.ok, traceId: ctx.traceId, ms: r.ms, visited: [...ctx.visited], reached: ctx.reached, ...(ctx.failedAt ? { failedAt: ctx.failedAt } : {}) };
  }

  const byPath = [...spec.endpoints].sort((a, b) => b.segments.filter((s) => !isParam(s)).length - a.segments.filter((s) => !isParam(s)).length || a.nodeId.localeCompare(b.nodeId));
  const matches = (e: EndpointSpec, method: string, segs: string[]) =>
    (e.method === method || e.method === "ALL" || (e.method === "PAGE" && method === "GET")) &&
    e.segments.length === segs.length && e.segments.every((s, i) => s === segs[i] || isParam(s));
  const weaknessesOf = (e: EndpointSpec): Weakness[] => spec.weaknesses.filter((w) => w.reachable && w.endpointIds.includes(e.nodeId));

  function handle(input: RangeRequest): RangeResponse {
    alive();
    const traceId = newTrace();
    const parsed = RequestSchema.safeParse(input);
    if (!parsed.success) return { status: 400, traceId, ms: 0, body: "bad request" };
    const req = parsed.data;
    const segs = req.path.split("/").filter(Boolean);
    const ep = byPath.find((e) => matches(e, req.method, segs));
    if (!ep) return { status: 404, traceId, ms: 0, body: "not found" };

    const answer = (status: number, body: string, note: string, extra: Partial<RangeResponse> = {}): RangeResponse => {
      t += 1;
      emit({ traceId, kind: "request", nodeId: ep.nodeId, ok: true, ms: 1, status, note });
      return { status, traceId, ms: 1, body, ...extra };
    };
    if (ep.auth === "required" && req.role === "anonymous") return answer(401, "authentication required", "unauthenticated");

    // ---- who is calling, and what rules apply to this route ----
    const principal = req.role === "admin" ? "admin" : req.role === "user" ? "userA" : "anon";
    const raised = escalated.get(principal);
    const eff: Role = raised && roleRank("admin") > roleRank(req.role) ? "admin" : req.role;
    const ws = weaknessesOf(ep);
    const weak = (kind: WeaknessKind) => ws.find((w) => w.kind === kind);
    let finding: Weakness | undefined; // the weakness a normal-looking request ended up exercising, if any

    // a session that should not work (expired, or planted by the attacker) is refused on routes that need a sign-in, unless the weakness is seeded
    if (req.abuse && (req.abuse.class === "stale-session" || req.abuse.class === "fixed-session") && ep.auth === "required") {
      const w = ws.find((x) => x.kind === "weak-session" && x.abuses?.includes(req.abuse!.class));
      if (!w) return answer(401, "session not valid", "invalid session refused");
      finding = w;
    }

    // function-level authorisation: a route meant for admins refuses a user, unless the weakness is seeded. A route flagged as open to everyone has no such rule.
    if (ep.auth !== "none" && roleRank(eff) < roleRank(ep.minRole)) {
      const w = weak("missing-authz");
      if (!w) return answer(403, "forbidden", "not permitted for this role");
      finding ??= w;
    }

    // object-level authorisation: a user may only read and change their own objects, unless the weakness is seeded
    if (ep.object && eff === "user") {
      const id = segs[ep.segments.findIndex(isParam)] ?? "";
      if (ownerOf(id) !== "userA") {
        const w = weak("idor");
        if (!w) return answer(403, "forbidden", "not the owner");
        finding ??= w;
      }
    }

    // sign-in style routes limit repeated attempts, unless the weakness is seeded
    if (ep.login) {
      const key = `${ep.nodeId}|${principal}`;
      const recent = (attempts.get(key) ?? []).filter((x) => x > t - RATE_WINDOW_MS);
      attempts.set(key, [...recent, t]);
      if (recent.length >= RATE_LIMIT) {
        const w = weak("no-rate-limit");
        if (!w) return answer(429, "too many attempts", "rate limited");
        finding ??= w;
      }
    }

    const ctx: Ctx = { traceId, visited: new Set(), reached: [] };
    const entry = emus.has(ep.ownerId) ? ep.ownerId : ep.nodeId;
    const own = emus.get(ep.nodeId);
    const epMs = own ? own.latencyMs : 1;
    t += epMs;
    const r = emus.has(entry) ? visit(entry, ep.nodeId, undefined, 0, ctx) : { ok: true, ms: 0 };
    const ms = epMs + r.ms;
    if (!r.ok) {
      emit({ traceId, kind: "request", nodeId: ep.nodeId, ok: false, ms, status: 503, note: ctx.failedAt ? `failed at ${emus.get(ctx.failedAt)?.label ?? ctx.failedAt}` : "failed" });
      return { status: 503, traceId, ms, body: "service unavailable" };
    }

    const write = WRITE_METHODS.has(ep.method);
    const hit = req.payload ? ws.find((w) => w.payload === req.payload!.class) : undefined;
    const noAuth = !req.payload && ep.auth === "none" && ep.authSource === "finding" && req.role === "anonymous" && write ? weak("no-auth") : undefined;
    let abuseWeak: Weakness | undefined;
    let applied = false;
    if (req.abuse && write) {
      const k = req.abuse.class;
      if (k === "privileged-field") {
        abuseWeak = weak("mass-assignment");
        if (abuseWeak) { applied = true; if (principal === "userA") escalated.set(principal, abuseWeak); }
      } else if (k === "skip-step" || k === "replay") {
        abuseWeak = ws.find((w) => w.kind === k);
        if (!abuseWeak) { emit({ traceId, kind: "request", nodeId: ep.nodeId, ok: true, ms, status: 409, note: k === "replay" ? "replay refused" : "missing step refused" }); return { status: 409, traceId, ms, body: "conflict" }; }
      }
    } else if (req.abuse && !write && req.abuse.class !== "stale-session" && req.abuse.class !== "fixed-session") {
      emit({ traceId, kind: "request", nodeId: ep.nodeId, ok: true, ms, status: 400, note: "not applicable" });
      return { status: 400, traceId, ms, body: "not applicable" };
    }
    const viaEscalation = !!raised && roleRank(req.role) < roleRank(eff) && roleRank(ep.minRole) > roleRank(req.role) && ep.auth !== "none";
    const proven = hit ?? noAuth ?? abuseWeak ?? finding ?? (viaEscalation ? raised : undefined);
    if (proven) {
      const crown = ctx.reached.map((id) => crowns.get(id)).filter((c): c is string => !!c);
      emit({ traceId, kind: "request", nodeId: ep.nodeId, ok: true, ms, status: 200, note: `weakness exercised (${proven.kind})` });
      return { status: 200, traceId, ms, body: "ok", proof: proven.proof, reached: ctx.reached, ...(applied ? { applied: true as const } : {}), ...(viaEscalation && proven === raised ? { via: "escalated" as const } : {}), ...(crown.length ? { crown } : {}) };
    }
    if (req.payload) {
      emit({ traceId, kind: "request", nodeId: ep.nodeId, ok: true, ms, status: 400, note: "input rejected" });
      return { status: 400, traceId, ms, body: "input rejected" };
    }
    emit({ traceId, kind: "request", nodeId: ep.nodeId, ok: true, ms, status: 200 });
    return { status: 200, traceId, ms, body: "ok" };
  }

  const stagesOf = (wfId: string) => [...emus.values()].filter((e) => (e.kind === "job" || e.kind === "env") && e.parentId === wfId).sort((a, b) => a.nodeId.localeCompare(b.nodeId));
  /** a workflow is a job that has stages (jobs, and environments it deploys to) inside it */
  const isWorkflow = (id: string) => emus.get(id)?.kind === "job" && stagesOf(id).length > 0;

  function runWorkflow(wfId: string, o: { sha?: string; trigger?: WorkflowResult["trigger"]; failJob?: string } = {}): WorkflowResult {
    alive();
    if (!isWorkflow(wfId)) throw new Error(`not a workflow in this range: ${wfId}`);
    const sha = o.sha ?? "0".repeat(40);
    const trigger = o.trigger ?? "push";
    const traceId = newTrace();
    const jobs = stagesOf(wfId);
    const ids = new Set(jobs.map((j) => j.nodeId));
    const needs = new Map(jobs.map((j) => [j.nodeId, [] as string[]]));
    for (const e of spec.edges) if (e.kind === "triggers" && ids.has(e.from) && ids.has(e.to)) needs.get(e.to)!.push(e.from);

    const startedAt = t;
    const done = new Map<string, WorkflowResult["jobs"][number]>();
    const pending = new Set(ids);
    while (pending.size) {
      const ready = [...pending].sort().find((id) => needs.get(id)!.every((n) => done.has(n)));
      if (!ready) { for (const id of [...pending].sort()) done.set(id, { nodeId: id, label: emus.get(id)!.label, stage: emus.get(id)!.kind === "env" ? "env" : "job", conclusion: "skipped", startedAt: t, endedAt: t }); break; } // a cycle: never run
      pending.delete(ready);
      const emu = emus.get(ready)!;
      const stage = emu.kind === "env" ? "env" : "job";
      const deps = needs.get(ready)!.map((n) => done.get(n)!);
      const start = Math.max(startedAt, ...deps.map((d) => d.endedAt));
      if (deps.some((d) => d.conclusion !== "success")) { done.set(ready, { nodeId: ready, label: emu.label, stage, conclusion: "skipped", startedAt: start, endedAt: start }); continue; }
      const end = start + (emu.durationMs ?? (stage === "env" ? 3_000 : 30_000)) + Math.floor(rand() * 5000);
      const f = faults.get(ready);
      const failed = o.failJob === ready || f?.kind === "outage" || (f?.kind === "error" && rand() < f.rate);
      done.set(ready, { nodeId: ready, label: emu.label, stage, conclusion: failed ? "failure" : "success", startedAt: start, endedAt: end, ...(failed ? { failedStep: o.failJob === ready ? "(simulated failure)" : "(injected fault)" } : {}) });
    }
    const results = [...done.values()].sort((a, b) => a.startedAt - b.startedAt || a.nodeId.localeCompare(b.nodeId));
    const endedAt = Math.max(startedAt, ...results.map((r) => r.endedAt));
    const conclusion = results.some((r) => r.conclusion === "failure") ? "failure" : "success";

    // an environment inside the workflow is a deploy step; an environment elsewhere on the map is reached by a `deploys_to` edge from a job
    const deploys: WorkflowResult["deploys"] = [];
    for (const r of results) {
      if (r.conclusion === "skipped") continue;
      if (r.stage === "env") { if (r.conclusion === "success") deployed.set(r.nodeId, sha); deploys.push({ envId: r.nodeId, state: r.conclusion, sha }); continue; }
      for (const e of adj.get(r.nodeId) ?? []) {
        if (e.kind !== "deploys_to" || emus.get(e.to)?.kind !== "env" || ids.has(e.to)) continue;
        const state = r.conclusion === "success" ? "success" : "failure";
        if (state === "success") deployed.set(e.to, sha);
        deploys.push({ envId: e.to, state, sha });
      }
    }
    const proofs = trigger !== "outsider-pr" ? [] : spec.weaknesses.filter((w) => w.kind === "pipeline-injection" && w.reachable && (w.nodeId === wfId || results.some((r) => r.nodeId === w.nodeId && r.conclusion !== "skipped"))).map((w) => w.proof);

    for (const r of [...results].sort((a, b) => a.endedAt - b.endedAt || a.nodeId.localeCompare(b.nodeId))) {
      emit({ t: r.endedAt, traceId, kind: r.stage === "env" ? "deploy" : "job", nodeId: r.nodeId, ok: r.conclusion !== "failure", ms: r.endedAt - r.startedAt, note: r.conclusion === "skipped" ? "skipped" : r.failedStep });
    }
    for (const d of deploys) if (!ids.has(d.envId)) emit({ t: endedAt, traceId, kind: "deploy", nodeId: d.envId, ok: d.state === "success", ms: 0, note: d.sha.slice(0, 7) });
    t = endedAt;
    return { runId: ++runs, workflowId: wfId, sha, trigger, conclusion, startedAt, endedAt, jobs: results, deploys, proofs };
  }

  return {
    id: spec.id,
    get destroyed() { return dead !== null; },
    now: () => { alive(); return t; },
    advance(ms) {
      alive();
      if (!Number.isFinite(ms) || ms < 0 || ms > MAX_ADVANCE_MS) throw new Error("advance: ms must be between 0 and 24 hours");
      t += ms;
    },
    handle, flow, runWorkflow,
    inject(nodeId, fault) {
      alive();
      if (!emus.has(nodeId)) throw new Error(`unknown node: ${nodeId}`);
      if (fault.kind === "latency" && !(Number.isFinite(fault.ms) && fault.ms >= 0 && fault.ms <= 60_000)) throw new Error("latency fault: ms must be between 0 and 60000");
      if (fault.kind === "error" && !(Number.isFinite(fault.rate) && fault.rate >= 0 && fault.rate <= 1)) throw new Error("error fault: rate must be between 0 and 1");
      faults.set(nodeId, fault);
    },
    clearFault(nodeId) { alive(); faults.delete(nodeId); },
    queueDepth(nodeId) { alive(); return depth.get(nodeId) ?? 0; },
    events() { return dead ? [] : log; },
    finish() { alive(); const out = { events: [...log], endedAt: t }; destroy("finished"); return out; },
    destroy,
  };
}
