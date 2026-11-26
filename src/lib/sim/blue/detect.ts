import { applyHealth } from "@/lib/health/engine";
import { ewmaAnomaly } from "@/lib/health/anomaly";
import { findIncident, sampleFrames, type Incident } from "@/lib/health/incident";
import type { TwinGraph } from "@/lib/graph/types";
import { fingerprint } from "@/lib/security/util";
import type { Finding, FindingSet, Severity } from "@/lib/security/types";
import { rangeSignals } from "../range/health";
import { buildRange } from "../range/generate";
import { startRange, type RangeInstance } from "../range/runtime";
import type { EndpointSpec, RangeRequest, RangeSpec, WeaknessKind } from "../range/types";

/**
 * The blue observer: did the health engine that already exists in this app NOTICE a weakness actually being used, and how long
 * would it have taken? Answered with the REAL, unmodified engine (`applyHealth`), never a model and never a new weakness: it
 * replays exactly the weaknesses the other three agents already found reachable (`spec.weaknesses`, X1), plus one general check
 * (read amplification on a crown jewel, below). The combined replay reuses the incident module (`sampleFrames`, `findIncident`)
 * so a detection has the same patient-zero-and-propagation shape a real incident replay already has.
 *
 * What counts as "detected": the node the weakness touches turning `degraded`/`failing` at or after the moment it was
 * exercised. A miss is not a flaw in this tool: the production health engine tracks operational health (errors, latency,
 * CI pass/fail), not security events, and most of these weaknesses are, honestly, invisible to it today. That gap is exactly
 * what this surfaces, with a concrete per-kind suggestion rather than a vague "add monitoring".
 *
 * The one check that needs more than "did a single request look different": a flood of ordinary, error-free, equal-latency
 * reads of a crown-jewel route (the shape of a slow data exfiltration). The engine has no request-VOLUME signal at all, so
 * this is reported missed by the real engine every time; a clearly-labelled, not-yet-built candidate rule (the same EWMA
 * machinery `health/anomaly.ts` already uses for errors and latency, here applied to request counts) is run alongside it to
 * prove the suggestion is real and that this tool can tell "missed" from "would be caught" apart.
 */

export type CoverageKind = WeaknessKind | "read-amplification";
export type CoverageOutcome = "detected" | "missed" | "not-tried";

export interface Coverage {
  kind: CoverageKind;
  /** absent only for the general read-amplification check, which is not tied to one scanner finding */
  findingId?: string;
  nodeId: string;
  label: string;
  outcome: CoverageOutcome;
  /** only when detected */
  timeToDetectMs?: number;
  /** only when missed: a concrete signal or threshold to add, never "add monitoring" */
  suggestion?: string;
  /** what was actually done and seen */
  note: string;
}

export interface DetectionResult {
  coverage: Coverage[];
  summary: { tried: number; detected: number; missed: number };
  /** new findings for genuine misses, category "detection-gap"; a re-run replaces this category's previous findings */
  findings: Finding[];
  /** everything exercised, replayed together through the same incident-finding module a real incident uses; null if nothing in the combined replay ever became unhealthy */
  incident: Incident | null;
  notes: string[];
}

export interface DetectInput {
  repo: string; sha: string; graph: TwinGraph; set: FindingSet;
  /** at most this many weaknesses are checked, highest severity first */
  max?: number;
  now?: () => number;
}

const BUCKET_MS = 5 * 60_000;
/** the engine's anomaly detector needs this many points of baseline before it will call anything unusual (health/anomaly.ts) */
const HEALTHY_ROUNDS = 8;
const FOLLOWUP_ROUNDS = 4;
const PER_ROUND = 6;
const FLOOD_MULTIPLIER = 20;

const isParam = (seg: string) => seg.startsWith(":") || (seg.startsWith("[") && seg.endsWith("]")) || (seg.startsWith("{") && seg.endsWith("}"));
const concretePath = (path: string) => `/${path.split("/").filter(Boolean).map((s) => (isParam(s) ? "1" : s)).join("/")}`;
const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** climbs the parent chain from a weakness's own node to the nearest ancestor that is a real workflow (a job with stages). Pure: reads only the spec, never the live range. */
function workflowOf(spec: RangeSpec, nodeId: string): string | null {
  const byId = new Map(spec.emulators.map((e) => [e.nodeId, e]));
  const hasStages = (id: string) => spec.emulators.some((e) => e.parentId === id && (e.kind === "job" || e.kind === "env"));
  for (let id: string | undefined = nodeId; id; id = byId.get(id)?.parentId) if (byId.get(id)?.kind === "job" && hasStages(id)) return id;
  return null;
}

const SUGGESTION: Record<WeaknessKind, string> = {
  "sql-injection": "A successful injection returns 200 like any other request: no error, no latency change. Add a query-shape or parameterisation check at the database layer (or a WAF rule), not a request-volume or error-rate alert.",
  "command-injection": "The shell command still exits normally from the application's point of view. Add host-level process/command auditing (what ran, not just whether the HTTP call succeeded).",
  "code-injection": "Evaluated code runs inside the normal request/response cycle and looks identical to it. Add a runtime check that flags dynamic evaluation of request-derived strings at all, since legitimate code rarely needs it.",
  "path-traversal": "The file read succeeds and returns 200. Add file-access auditing that flags a path resolving outside the folder the handler is meant to serve.",
  ssrf: "The outbound call succeeds like any other. Add egress monitoring or an allow-list alert for requests to internal or cloud-metadata addresses.",
  xss: "This happens in the victim's browser, not on the server, so none of this app's server-side health signals can ever see it. It needs client-side reporting (a CSP report-uri) that this map does not model.",
  "open-redirect": "The redirect is a normal 3xx response. Add an alert for a redirect target that is not on an allow-list of this site's own hosts.",
  "no-auth": "The write succeeds and looks like any other write. Add an authorization-decision audit log and alert on a state-changing call with no recorded caller identity.",
  idor: "The read or write succeeds and looks like ordinary traffic from a signed-in user. Add an authorization-decision audit log and alert when a caller is granted an object it does not own.",
  "missing-authz": "The call succeeds like any other. Add the same authorization-decision audit log, alerting on a role below the one a route requires.",
  "mass-assignment": "An extra field in a write is silently accepted. Add field-level audit logging for privileged fields (anything that changes a role or permission).",
  "no-rate-limit": "The engine currently has no signal tied to request rate or login attempts at all (see the read-amplification check). Add a per-caller attempt-rate alert on sign-in style routes.",
  "weak-session": "An expired or planted session is accepted like a valid one; the request itself is indistinguishable from a legitimate one. Add session-issuance and session-validation audit logging.",
  "skip-step": "A workflow step is skipped but the call still succeeds. Add business-process audit logging that checks the steps a transaction actually went through, not just its final result.",
  replay: "A replayed request is accepted. Add idempotency-key tracking and alert on a request replaying one already completed.",
  "exposed-credential": "A leaked credential being used looks like a normal, successful sign-in. Add alerting on credential use from an unfamiliar context (new address range, new client), which this map does not model.",
  "vulnerable-dependency": "Exploiting a known library vulnerability happens inside an otherwise normal request and rarely changes error rate or latency by itself. Detection belongs at the dependency layer (this scanner), not the health engine.",
  "container-misconfig": "A misconfigured container does not, by itself, produce an operational signal until something is actually done with the extra access it grants. Detection belongs at the infrastructure layer, not the health engine.",
  "pipeline-injection": "A pipeline an outsider triggered still reports success like any other green run: the engine only tracks pass/fail, never who or what triggered it. Add a check for workflow runs triggered by a pull request from a fork, or for who approved the resulting deploy.",
  "pipeline-misconfig": "A misconfigured pipeline is not, by itself, an event the health engine would see happen. Detection belongs in the pipeline analysis (this scanner), not the health engine.",
};
const READ_AMPLIFICATION_SUGGESTION = "The engine judges error rate and latency; it has no signal for request VOLUME at all, so a flood of ordinary, successful, equal-latency reads is invisible to it however large it gets. Add a request-rate anomaly check (the same EWMA method already used for errors and latency, applied to request counts instead).";

/** a concrete path with every parameter filled in with one of two synthetic ids ("1" is always user A's own object; "2" is someone else's) */
const pathWith = (ep: EndpointSpec, id: "1" | "2") => `/${ep.segments.map((s) => (isParam(s) ? id : s)).join("/")}`;

/**
 * The single request (or abuse call) that actually reproduces each kind of weakness, and the ordinary baseline request to compare
 * it against. This mirrors how the white-box and gray-box agents already exercise each kind (X4, X5): IDOR needs someone ELSE's
 * object id, not a payload; mass assignment needs the `privileged-field` abuse class on a write; and so on. `null` means this
 * weakness has no single-request shape this function knows how to build (handled as its own branch in `exerciseWeakness`, or not
 * exercised at all).
 */
function shapeFor(spec: RangeSpec, w: RangeSpec["weaknesses"][number]): { req: RangeRequest; baseline: RangeRequest; ep: EndpointSpec; what: string } | null {
  const ep = spec.endpoints.find((e) => w.endpointIds.includes(e.nodeId));
  if (!ep) return null;
  const method = ep.method === "PAGE" || ep.method === "ALL" ? "GET" : ep.method;
  const own = pathWith(ep, "1");
  const label = `${method} ${ep.path}`;
  switch (w.kind) {
    case "no-auth":
      return { ep, baseline: { method, path: own, role: "user" }, req: { method, path: own, role: "anonymous" }, what: `${label} as anonymous (meant to need a sign-in)` };
    case "idor":
      return { ep, baseline: { method, path: own, role: "user" }, req: { method, path: pathWith(ep, "2"), role: "user" }, what: `${label} as a signed-in user, for an object that belongs to someone else` };
    case "missing-authz":
      return { ep, baseline: { method, path: own, role: "admin" }, req: { method, path: own, role: "user" }, what: `${label} as a plain user (meant for admins)` };
    case "mass-assignment":
      return { ep, baseline: { method, path: own, role: "user" }, req: { method, path: own, role: "user", abuse: { class: "privileged-field" } }, what: `${label} as a signed-in user, with a privileged field added` };
    case "weak-session": {
      const cls = w.abuses?.[0] ?? "stale-session";
      return { ep, baseline: { method, path: own, role: ep.minRole }, req: { method, path: own, role: ep.minRole, abuse: { class: cls } }, what: `${label} with ${cls === "fixed-session" ? "a session planted by an attacker" : "an expired session"}` };
    }
    case "skip-step":
    case "replay":
      return { ep, baseline: { method, path: own, role: ep.minRole }, req: { method, path: own, role: ep.minRole, abuse: { class: w.kind } }, what: `${label} ${w.kind === "replay" ? "replayed" : "with a required step skipped"}` };
    default: // the payload-based web weaknesses: the role the route is actually meant for, so the request gets past sign-in and reaches the weak code
      return { ep, baseline: { method, path: own, role: ep.minRole }, req: { method, path: own, role: ep.minRole, ...(w.payload ? { payload: { class: w.payload } } : {}) }, what: `${label} as ${ep.minRole}${w.payload ? ` with a ${w.payload} payload` : ""}` };
  }
}

/** runs `rounds` ordinary baseline requests, advancing the virtual clock a bucket after each round */
function steady(r: RangeInstance, req: RangeRequest, rounds: number) {
  for (let i = 0; i < rounds; i++) { for (let k = 0; k < PER_ROUND; k++) r.handle(req); r.advance(BUCKET_MS); }
}

interface Exercise { ok: boolean; nodeId: string; label: string; what: string; attackVirtualTs: number; /** true for a pipeline weakness: judged by run outcome, not a runtime signal */ pipeline: boolean }

/** exercises one weakness on the given (already-started) range, in the middle of HEALTHY_ROUNDS before and FOLLOWUP_ROUNDS after it, so the attack blends into ordinary traffic. Returns null if this weakness has no exercise this range can run. */
function exerciseWeakness(r: RangeInstance, spec: RangeSpec, w: RangeSpec["weaknesses"][number], label: (id: string) => string): Exercise | null {
  if (w.kind === "pipeline-injection") {
    const wf = workflowOf(spec, w.nodeId);
    if (!wf) return null;
    for (let i = 0; i < HEALTHY_ROUNDS; i++) r.advance(BUCKET_MS);
    const attackVirtualTs = r.now();
    const res = r.runWorkflow(wf, { trigger: "outsider-pr" });
    for (let i = 0; i < FOLLOWUP_ROUNDS; i++) r.advance(BUCKET_MS);
    return { ok: res.proofs.includes(w.proof), nodeId: wf, label: label(wf), what: `an outsider's pull request triggering ${label(wf)}`, attackVirtualTs, pipeline: true };
  }
  if (w.kind === "no-rate-limit") {
    const ep = spec.endpoints.find((e) => w.endpointIds.includes(e.nodeId));
    if (!ep) return null;
    const method = ep.method === "PAGE" || ep.method === "ALL" ? "GET" : ep.method;
    const req: RangeRequest = { method, path: pathWith(ep, "1"), role: "anonymous" };
    steady(r, req, HEALTHY_ROUNDS);
    const attackVirtualTs = r.now();
    let ok = false;
    for (let i = 0; i < 12; i++) if (r.handle(req).proof === w.proof) ok = true; // a burst of attempts, same size as the gray-box agent's own test
    steady(r, req, FOLLOWUP_ROUNDS);
    return { ok, nodeId: ep.nodeId, label: `${method} ${ep.path}`, what: `12 rapid anonymous attempts at ${method} ${ep.path}`, attackVirtualTs, pipeline: false };
  }
  const shaped = shapeFor(spec, w);
  if (!shaped) return null;
  steady(r, shaped.baseline, HEALTHY_ROUNDS);
  const attackVirtualTs = r.now();
  const res = r.handle(shaped.req);
  steady(r, shaped.baseline, FOLLOWUP_ROUNDS);
  return { ok: res.status === 200 && res.proof === w.proof, nodeId: shaped.ep.nodeId, label: `${shaped.req.method} ${shaped.ep.path}`, what: shaped.what, attackVirtualTs, pipeline: false };
}

/** `nodeId`'s state at the first sampled frame at or after `fromTs` where it is unhealthy */
/** `nodeId`'s state at the first sampled frame at or after `fromTs` where it is unhealthy. Exported so the exact function `checkOne` relies on can be tested directly against a real range session, not a reimplementation of it. */
export function firstBadAfter(frames: ReturnType<typeof sampleFrames>, nodeId: string, fromTs: number): { ts: number } | undefined {
  const hit = frames.find((f) => f.ts >= fromTs && (f.states[nodeId] === "failing" || f.states[nodeId] === "degraded"));
  return hit ? { ts: hit.ts } : undefined;
}

/**
 * Did `nodeId` turn unhealthy at or after virtual time `attackVirtualTs`, given everything the range recorded up to `endedAt`?
 * The one place `baseTs + attackVirtualTs` becomes the real timestamp `firstBadAfter` is asked about, shared by `checkOne` and
 * directly testable with a hand-built range session (e.g. one with a real fault injected), not just with fixtures that happen
 * to produce a miss.
 */
export function detectedAfter(graph: TwinGraph, spec: RangeSpec, events: Parameters<typeof rangeSignals>[1]["events"], endedAt: number, nodeId: string, baseTs: number, attackVirtualTs: number): { ts: number } | undefined {
  const now = baseTs + endedAt + BUCKET_MS;
  const signals = rangeSignals(spec, { events, workflows: [] }, { baseTs, now });
  const frames = sampleFrames(graph, signals, { to: baseTs + endedAt, hours: Math.ceil(endedAt / 3_600_000) + 1, stepMs: BUCKET_MS });
  return firstBadAfter(frames, nodeId, baseTs + attackVirtualTs);
}

function checkOne(spec: RangeSpec, graph: TwinGraph, w: RangeSpec["weaknesses"][number], baseTs: number): Coverage {
  const label = (id: string) => graph.nodes.find((n) => n.id === id)?.label ?? id;
  const r = startRange(spec, { maxEvents: 50_000 });
  const ex = exerciseWeakness(r, spec, w, label);
  if (!ex) { r.destroy(); return { kind: w.kind, findingId: w.findingId, nodeId: w.nodeId, label: label(w.nodeId), outcome: "not-tried", note: "This weakness has no request- or workflow-shaped exercise in the range, so detection could not be checked." }; }
  const { events, endedAt } = r.finish();
  if (!ex.ok) return { kind: w.kind, findingId: w.findingId, nodeId: ex.nodeId, label: ex.label, outcome: "not-tried", note: `Exercising ${ex.what} did not reproduce the weakness in this run; detection could not be checked.` };

  // A pipeline an outsider triggers still reports success, judged by pass/fail alone: no runtime signal to sample, and the
  // outcome is already known once the run itself does not fail. Checking it against applyHealth would always say the same thing.
  if (ex.pipeline) return { kind: w.kind, findingId: w.findingId, nodeId: ex.nodeId, label: ex.label, outcome: "missed", suggestion: SUGGESTION[w.kind], note: `${ex.what}: the run still reported success, which the engine judges as healthy.` };

  const hit = detectedAfter(graph, spec, events, endedAt, ex.nodeId, baseTs, ex.attackVirtualTs);
  const attackRealTs = baseTs + ex.attackVirtualTs;
  return hit
    ? { kind: w.kind, findingId: w.findingId, nodeId: ex.nodeId, label: ex.label, outcome: "detected", timeToDetectMs: hit.ts - attackRealTs, note: `${ex.what}: ${ex.nodeId} turned unhealthy ${Math.round((hit.ts - attackRealTs) / 60_000)} minute(s) after.` }
    : { kind: w.kind, findingId: w.findingId, nodeId: ex.nodeId, label: ex.label, outcome: "missed", suggestion: SUGGESTION[w.kind], note: `${ex.what}: ${ex.nodeId} stayed healthy for the ${Math.round((endedAt - ex.attackVirtualTs) / 60_000)} minutes observed afterward.` };
}

/** everything exercised again, back to back on ONE range, so the combined timeline can be read by the same incident-finding code a real incident uses */
function combinedReplay(spec: RangeSpec, graph: TwinGraph, candidates: RangeSpec["weaknesses"], baseTs: number): Incident | null {
  const label = (id: string) => graph.nodes.find((n) => n.id === id)?.label ?? id;
  const r = startRange(spec, { maxEvents: 500_000 });
  for (const w of candidates) { try { exerciseWeakness(r, spec, w, label); } catch { /* one weakness failing to exercise does not stop the replay */ } }
  if (r.destroyed) return null; // the event cap was hit; no replay rather than a wrong one
  const { events, endedAt } = r.finish();
  if (!events.length) return null;
  const now = baseTs + endedAt + BUCKET_MS;
  const signals = rangeSignals(spec, { events, workflows: [] }, { baseTs, now });
  const frames = sampleFrames(graph, signals, { to: baseTs + endedAt, hours: Math.ceil(endedAt / 3_600_000) + 1, stepMs: BUCKET_MS });
  return findIncident(graph, frames);
}

/** a flood of ordinary, error-free, equal-latency reads of a crown-jewel route: missed by the real engine (no volume signal exists), detected by a labelled candidate rule */
function checkReadAmplification(spec: RangeSpec, graph: TwinGraph, baseTs: number): Coverage | null {
  if (!spec.datastores.length) return null;
  const route = spec.endpoints.find((e) => (e.method === "GET" || e.method === "PAGE") && !e.segments.some(isParam));
  if (!route) return null;
  const r = startRange(spec, { maxEvents: 200_000 });
  const req: RangeRequest = { method: route.method === "PAGE" ? "GET" : route.method, path: concretePath(route.path), role: "anonymous" };
  steady(r, req, HEALTHY_ROUNDS);
  for (let i = 0; i < 3; i++) { for (let k = 0; k < PER_ROUND * FLOOD_MULTIPLIER; k++) r.handle(req); r.advance(BUCKET_MS); }
  const { events, endedAt } = r.finish();
  const now = baseTs + endedAt + BUCKET_MS;
  const signals = rangeSignals(spec, { events, workflows: [] }, { baseTs, now });
  const after = applyHealth(graph, signals, now);
  const node = after.nodes.find((n) => n.id === route.ownerId);
  const engineDetected = node?.state === "degraded" || node?.state === "failing";

  const bucket = (signals.runtime ?? []).filter((b) => b.key === route.ownerId).sort((a, b) => a.ts - b.ts);
  const volume = bucket.map((b) => b.requests ?? 0);
  let detectedAtBucket = -1;
  for (let i = HEALTHY_ROUNDS; i < volume.length; i++) if (ewmaAnomaly(volume.slice(0, i + 1), { floor: 1 })?.anomalous) { detectedAtBucket = i; break; }
  const candidateDetected = detectedAtBucket >= 0;

  const floodReads = PER_ROUND * FLOOD_MULTIPLIER, normalReads = PER_ROUND;
  const note = engineDetected
    ? `A flood of ${floodReads} successful, error-free reads a bucket (vs ${normalReads} normally) was flagged by the live health rules.`
    : candidateDetected
      ? `A flood of ${floodReads} successful, error-free reads a bucket (vs ${normalReads} normally) was not flagged by the live health rules, but a candidate request-volume check would have flagged it after ${detectedAtBucket - HEALTHY_ROUNDS + 1} flood bucket(s).`
      : `A flood of ${floodReads} successful, error-free reads a bucket (vs ${normalReads} normally) was not flagged by the live health rules, and the candidate volume check also did not trigger with this shape of traffic.`;
  return {
    kind: "read-amplification", nodeId: route.ownerId, label: `${req.method} ${route.path}`, outcome: engineDetected ? "detected" : "missed",
    ...(engineDetected ? { timeToDetectMs: 0 } : { suggestion: READ_AMPLIFICATION_SUGGESTION }), note,
  };
}

export function assessDetection(input: DetectInput): DetectionResult {
  const now = input.now ?? Date.now;
  const spec = buildRange({ sha: input.sha, graph: input.graph }, input.set);
  const candidates = [...spec.weaknesses]
    .filter((w) => w.reachable)
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.id.localeCompare(b.id))
    .slice(0, input.max ?? 15);

  const notes: string[] = [];
  if (spec.weaknesses.filter((w) => w.reachable).length > candidates.length) notes.push(`Only the ${candidates.length} highest-severity of ${spec.weaknesses.filter((w) => w.reachable).length} reachable weaknesses were checked.`);

  const baseTs = now();
  const coverage: Coverage[] = candidates.map((w) => checkOne(spec, input.graph, w, baseTs));
  const amp = checkReadAmplification(spec, input.graph, baseTs);
  if (amp) coverage.push(amp); else notes.push("The map has no plain GET route to a crown-jewel asset, so the read-amplification check could not run.");
  if (coverage.some((c) => c.outcome === "missed" && c.kind === "read-amplification")) notes.push("Read amplification on a crown-jewel route is invisible to the live health rules by design (no request-volume signal exists yet); see the suggestion on that row.");

  const incident = candidates.length ? combinedReplay(spec, input.graph, candidates, baseTs) : null;

  const findings: Finding[] = coverage.filter((c) => c.outcome === "missed").map((c) => {
    const original = c.findingId ? input.set.findings.find((f) => f.id === c.findingId) : undefined;
    const path = original?.path ?? `(detection) ${c.label}`;
    return {
      id: fingerprint("blue", c.findingId ?? c.nodeId, c.kind), ruleId: "BLUE/not-detected", category: "detection-gap" as const,
      severity: original?.severity ?? "medium", confidence: "high" as const,
      title: `Not noticed: ${c.kind === "read-amplification" ? "a flood of reads on" : c.kind} ${c.label}`,
      path, ...(original?.line ? { line: original.line } : {}),
      reason: `${c.note} A monitoring system built only on error rate and latency will not notice this.`,
      fix: c.suggestion ?? "Add a signal that would catch this.",
      // never the original's CWE tags: those would make this synthetic finding re-enter the weakness pipeline (by CWE) on the next run
      cwe: [], detail: { source: "blue-team" },
    };
  });

  return {
    coverage, incident, notes, findings,
    summary: { tried: coverage.filter((c) => c.outcome !== "not-tried").length, detected: coverage.filter((c) => c.outcome === "detected").length, missed: coverage.filter((c) => c.outcome === "missed").length },
  };
}
