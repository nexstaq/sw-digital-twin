import { z } from "zod";
import type { RangeInstance } from "../../range/runtime";
import { ABUSE_CLASSES, METHODS, PAYLOAD_CLASSES, ROLES, type RangeSpec, type Role } from "../../range/types";
import { techniqueId } from "../../roe";
import { defineTool } from "../tools";

/**
 * The tools an agent uses against the range. The range id is fixed when the tool is built, so the model has no argument that could
 * name another one. What a call IS (an observation, a probe, an exploit of a known weakness class) comes from its input, and
 * `allow()` decides whether this run may do that.
 */

export function inspectTool(o: { spec: RangeSpec; /** also show which weakness kinds exist and where (white-box only) */ weaknesses?: boolean; /** show only the INTENDED policy of each route (who it is meant for), not how it is actually protected: what an outside tester would assume */ blind?: boolean }) {
  return defineTool({
    name: "range_inspect",
    description: "List the routes (with how each is protected) and the blocks of the range. Read-only.",
    inputSchema: z.strictObject({}),
    classOf: () => "observe",
    techniqueOf: () => undefined,
    targetOf: () => ({ kind: "range" as const, rangeId: o.spec.id }),
    source: "tool-output",
    summarize: (out: { routes: unknown[]; blocks: unknown[] }) => `${out.routes.length} routes, ${out.blocks.length} blocks`,
    run: async () => ({
      routes: o.spec.endpoints.map((e) => (o.blind
        ? { id: e.nodeId, method: e.method, path: e.path, minRole: e.minRole, object: e.object, login: e.login }
        : { id: e.nodeId, method: e.method, path: e.path, auth: e.auth, authSource: e.authSource, minRole: e.minRole, object: e.object, login: e.login })).slice(0, 200),
      blocks: o.spec.emulators.filter((e) => e.kind !== "endpoint").map((e) => ({ id: e.nodeId, label: e.label, kind: e.kind })).slice(0, 200),
      ...(o.weaknesses ? { weaknesses: o.spec.weaknesses.map((w) => ({ id: w.id, kind: w.kind, severity: w.severity, endpointIds: w.endpointIds, reachable: w.reachable })).slice(0, 100) } : {}),
    }),
  });
}

export function requestTool(o: { range: RangeInstance; spec: RangeSpec; /** the roles this agent may call as */ roles: readonly Role[] }) {
  const roles = z.enum(o.roles as [Role, ...Role[]]);
  return defineTool({
    name: "range_request",
    description: "Send one request to a route of the range. Give a payload class (hostile input) or an abuse class (hostile behaviour: privileged field, stale or planted session, skipped step, replay) to test a weakness class; a request with one is an exploit attempt, one without is a probe. You must name the ATT&CK technique.",
    inputSchema: z.strictObject({ method: z.enum(METHODS), path: z.string().max(512), role: roles, payloadClass: z.enum(PAYLOAD_CLASSES).optional(), abuse: z.enum(ABUSE_CLASSES).optional(), technique: techniqueId })
      .refine((i) => !(i.payloadClass && i.abuse), { message: "a payload class or an abuse class, not both" }),
    classOf: (i) => (i.payloadClass || i.abuse ? "exploit-range" : "probe"),
    techniqueOf: (i) => i.technique,
    targetOf: () => ({ kind: "range" as const, rangeId: o.spec.id }),
    source: "range-response",
    summarize: (out: { status: number; proof?: string }) => `status ${out.status}${out.proof ? ", weakness exercised" : ""}`,
    run: async (i) => {
      const r = o.range.handle({ method: i.method, path: i.path, role: i.role, ...(i.payloadClass ? { payload: { class: i.payloadClass } } : {}), ...(i.abuse ? { abuse: { class: i.abuse } } : {}) });
      return { status: r.status, body: r.body, ms: r.ms, ...(r.proof ? { proof: r.proof } : {}), ...(r.reached ? { reached: r.reached } : {}), ...(r.crown ? { crown: r.crown } : {}), ...(r.applied ? { applied: r.applied } : {}), ...(r.via ? { via: r.via } : {}) };
    },
  });
}

export const ROLES_FOR: Record<"whitebox" | "graybox" | "redteam", readonly Role[]> = {
  whitebox: ROLES,
  graybox: ROLES, // one set of range credentials per role: anonymous, user and admin
  redteam: ["anonymous"],
};
