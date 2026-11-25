import { z } from "zod";
import { isIP } from "node:net";
import { parseDomain } from "@/lib/security/passive/domain";

/**
 * Rules of engagement (ROE): the written, machine-checked limits of one simulation run. Everything an agent may touch, for how
 * long, and how much it may spend is in here, and `allow()` (scope.ts) is the only thing that reads it. Strict everywhere: an
 * unknown key, a missing budget or a malformed value makes the whole ROE invalid, and an invalid ROE allows nothing.
 */

export const LIMITS = {
  /** a run is at most a day, so an approval cannot quietly become standing permission */
  maxWindowMs: 24 * 60 * 60 * 1000,
  maxSteps: 500,
  maxTokens: 2_000_000,
  maxWallMs: 60 * 60 * 1000,
  maxCostUsd: 25,
  maxTargets: 5,
  maxList: 200,
} as const;

export const AGENTS = ["whitebox", "graybox", "redteam", "blue", "narrator"] as const;
export type Agent = (typeof AGENTS)[number];

/** Ordered from harmless to harmful. `intrusive` exists only so an agent that asks for it gets a clear refusal. */
export const ACTION_CLASSES = ["observe", "probe", "exploit-range", "intrusive"] as const;
export type ActionClass = (typeof ACTION_CLASSES)[number];
export const classRank = (c: ActionClass) => ACTION_CLASSES.indexOf(c);

const ident = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/, "must be 1 to 64 letters, digits, _ or -");
const epochMs = z.number().int().nonnegative().max(8.64e15);
export const techniqueId = z.string().regex(/^T\d{4}(\.\d{3})?$/, "must be a MITRE ATT&CK technique id such as T1190 or T1059.004");
export const repoSlug = z.string().regex(/^[\w.-]{1,100}\/[\w.-]{1,100}$/, "must be owner/name");

/** A plain hostname and nothing else: no scheme, port, path, credentials, wildcard or IP literal. Lowercased. */
const domainName = z.string().max(253).transform((s, ctx) => {
  const bad = (message: string) => { ctx.addIssue({ code: "custom", message }); return z.NEVER; };
  if (!/^[A-Za-z0-9.-]+$/.test(s)) return bad("must be a plain host name (no scheme, port, path, wildcard or login)");
  const p = parseDomain(s);
  return p.ok ? p.domain : bad(p.reason);
});

/** https, default port, no credentials, no path: the origin of a staging site that the customer's own CI will test. */
const stagingOrigin = z.string().max(300).transform((s, ctx) => {
  const bad = (message: string) => { ctx.addIssue({ code: "custom", message }); return z.NEVER; };
  let u: URL;
  try { u = new URL(s); } catch { return bad("must be an https URL"); }
  if (u.protocol !== "https:") return bad("must be https");
  if (u.username || u.password) return bad("must not contain credentials");
  if (u.port) return bad("must use the standard port");
  if (u.pathname !== "/" || u.search || u.hash) return bad("must be an origin only (no path, query or fragment)");
  if (isIP(u.hostname.replace(/^\[|\]$/g, ""))) return bad("must be a host name, not an IP address");
  const p = parseDomain(u.hostname);
  return p.ok ? u.origin : bad(p.reason);
});

const TargetSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("range"), rangeId: ident }),
  z.strictObject({ kind: z.literal("verified-domain"), domain: domainName }),
  z.strictObject({ kind: z.literal("ci-runner"), repo: repoSlug, url: stagingOrigin }),
]);
export type Target = z.infer<typeof TargetSchema>;

const techniques = z.array(techniqueId).max(LIMITS.maxList);
const budget = (cap: number, whole: boolean) => (whole ? z.number().int() : z.number()).positive().max(cap);

export const RoeSchema = z
  .strictObject({
    version: z.literal(1),
    runId: ident,
    repo: repoSlug,
    targets: z.array(TargetSchema).min(1).max(LIMITS.maxTargets),
    agents: z.array(z.enum(AGENTS)).min(1).max(AGENTS.length),
    /** `intrusive` cannot be granted in this version: it needs a per-action human approval gate that does not exist yet (X3). */
    allowedClasses: z.array(z.enum(["observe", "probe", "exploit-range"])).min(1).max(3),
    allowedTechniques: techniques,
    forbiddenTechniques: techniques,
    window: z.strictObject({ notBefore: epochMs, notAfter: epochMs }),
    budgets: z.strictObject({
      steps: budget(LIMITS.maxSteps, true),
      tokens: budget(LIMITS.maxTokens, true),
      wallMs: budget(LIMITS.maxWallMs, true),
      costUsd: budget(LIMITS.maxCostUsd, false),
    }),
    /** Who approved this run, and when. Whether that person MAY approve is checked by the caller with the repo's own access rules. */
    approval: z.strictObject({ approvedBy: z.string().trim().min(1).max(100), approvedAt: epochMs }).optional(),
    killSwitchId: ident,
  })
  .superRefine((r, ctx) => {
    const issue = (path: (string | number)[], message: string) => ctx.addIssue({ code: "custom", path, message });
    if (r.window.notAfter <= r.window.notBefore) issue(["window"], "must end after it starts");
    else if (r.window.notAfter - r.window.notBefore > LIMITS.maxWindowMs) issue(["window"], "cannot be longer than 24 hours");
    if (r.targets.some((t) => t.kind !== "range") && !r.approval) issue(["approval"], "a named approval is required for any target that is not a range");
    if (r.approval && r.approval.approvedAt > r.window.notBefore) issue(["approval", "approvedAt"], "the approval must be given before the window opens");
    for (const t of r.allowedTechniques) if (r.forbiddenTechniques.includes(t)) issue(["forbiddenTechniques"], `${t} is both allowed and forbidden`);
    r.targets.forEach((t, i) => {
      if (t.kind === "ci-runner" && t.repo.toLowerCase() !== r.repo.toLowerCase()) issue(["targets", i, "repo"], "a CI run may only test its own repository");
    });
  });
export type Roe = z.infer<typeof RoeSchema>;

export type ParsedRoe = { ok: true; roe: Roe } | { ok: false; errors: string[] };

export function parseRoe(input: unknown): ParsedRoe {
  const r = RoeSchema.safeParse(input);
  if (r.success) return { ok: true, roe: r.data };
  return { ok: false, errors: r.error.issues.map((i) => `${i.path.join(".") || "(roe)"}: ${i.message}`) };
}
