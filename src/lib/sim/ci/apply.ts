import type { TwinGraph } from "@/lib/graph/types";
import type { Finding, FindingSet } from "@/lib/security/types";
import { fingerprint } from "@/lib/security/util";
import { buildRange } from "../range/generate";
import { T as ACCESS_T } from "../graybox/roe";
import type { Profile } from "./plan";

/**
 * Authorised external runs, part two: what the customer's own CI runner reported after making exactly the requests
 * `buildPlan` authorised (`plan.ts`), turned into findings. A reported path that was never authorised is ignored, never
 * scored: the plan is the only thing trusted, not whatever the runner's own script claims it did.
 *
 * "access" asks the same question X5's verified-domain probe asks of one domain: does a route the map says is meant for a
 * signed-in user or admin answer an anonymous visitor anyway? "reachability" asks a different, non-security question (is
 * the map still accurate: which routes are actually live out there) and produces no findings, only a count.
 */

export interface Observation { path: string; status: number; bytes: number }
export interface ApplyInput {
  url: string; profile: Profile; sha: string; graph: TwinGraph; set: FindingSet;
  controlStatus: number; controlBytes: number;
  observations: readonly Observation[];
  /** the exact routes `buildPlan` authorised; anything else reported is rejected outright */
  authorizedPaths: readonly string[];
}
export interface ApplyResult { findings: Finding[]; notes: string[]; accepted: number; rejected: number }

/** how close two response sizes must be to count as "the same page" (same rule as the verified-domain probe, X5) */
const sameSize = (a: number, b: number) => Math.abs(a - b) <= Math.max(16, Math.max(a, b) * 0.05);

export function applyReport(input: ApplyInput): ApplyResult {
  const spec = buildRange({ sha: input.sha, graph: input.graph }, input.set);
  // GET only: the runner never sends anything else, and more than one method can share a path (POST /x, GET /x), so keying
  // by path alone would let a write route's minRole silently decide a read route's score
  const byPath = new Map(spec.endpoints.filter((e) => e.method === "GET" || e.method === "PAGE").map((e) => [e.path, e]));
  const authorized = new Set(input.authorizedPaths);
  const domain = new URL(input.url).hostname;

  const findings: Finding[] = [];
  let accepted = 0, rejected = 0, live = 0;
  for (const o of input.observations) {
    if (!authorized.has(o.path)) { rejected++; continue; }
    accepted++;
    const e = byPath.get(o.path);
    if (!e) continue;
    if (o.status !== 200) continue; // protected (401/403), redirected, or anything else: nothing to report
    if (input.controlStatus === 200 && sameSize(o.bytes, input.controlBytes)) continue; // the site answers everything alike; proves nothing
    live++;
    if (input.profile !== "access" || e.minRole === "anonymous") continue; // "reachability" is informational; an already-public route answering is not a finding
    const admin = e.minRole === "admin";
    const url = `${input.url}${o.path}`;
    findings.push({
      id: fingerprint("ci-runner", domain, o.path), ruleId: "SIM/anonymous-access", category: "runtime",
      severity: admin ? "high" : "medium", confidence: admin ? "medium" : "low",
      title: `GET ${o.path} answers without signing in`,
      path: url,
      reason: `The map treats ${o.path} as meant for ${admin ? "admins" : "signed-in users"}, but your own staging site answered an anonymous request with a real page (200, ${o.bytes} bytes), unlike a page that does not exist (${input.controlStatus}). That is an assumption about what the page is meant for, so confirm it is meant to be private.`,
      fix: "Check who should be able to open this page. If it is private, require a sign-in (and, for an admin page, an admin role) before anything is returned, and make it answer 401 or 403 to everyone else.",
      cwe: [admin ? "CWE-862" : "CWE-306"], owasp: "A01:2021 Broken Access Control", detail: { source: "ci-runner" },
      technique: ACCESS_T.access, proof: `GET ${url} answered 200 (${o.bytes} bytes) with no sign-in; a made-up path answered ${input.controlStatus}.`,
    });
  }

  const notes: string[] = [];
  if (rejected) notes.push(`${rejected} reported route${rejected === 1 ? "" : "s"} were not on the list this run authorised, and were ignored.`);
  if (input.profile === "reachability") notes.push(`${live} of ${accepted} checked route${accepted === 1 ? "" : "s"} answered live; the rest were protected, redirected, or inconclusive.`);
  if (!accepted) notes.push("Nothing was reported.");
  return { findings, notes, accepted, rejected };
}
