import type { TwinGraph } from "@/lib/graph/types";
import type { Transport } from "@/lib/security/passive/transport";
import type { Finding, FindingSet } from "@/lib/security/types";
import { fingerprint } from "@/lib/security/util";
import type { KillRegistry } from "../agent/killswitch";
import { runPlan, type AgentRunResult } from "../agent/runtime";
import type { AnyTool } from "../agent/tools";
import { probeTool, type ProbeTransport } from "../agent/tools/probe";
import { buildRange } from "../range/generate";
import { sha256Hex } from "../range/sha256";
import { T } from "./roe";

/**
 * The non-intrusive subset of the gray-box tests, against a REAL site. Only when its owner proved ownership in this very run, and a named person
 * approved the run (both are required by the rules of engagement, and the guard re-checks them on every request).
 *
 * What makes it non-intrusive. It sends only GET requests, through the S4 passive-check client: public addresses only (the address it validated is the
 * one it connects to), no redirects off the host, size and time caps, a pause between requests. It sends no credentials and no body, so it cannot sign
 * in, change anything or guess anything. For each route the map says is meant for signed-in users or admins and that is a plain GET without parameters,
 * it asks whether an anonymous visitor gets the page.
 *
 * What it does NOT do. It does not test object-level access, sessions, mass assignment, workflow or rate limits: those need credentials or write
 * requests. It does not take real credentials at all.
 *
 * The honest caveat: the map's "meant for signed-in users" is an assumption from the route's path and method. A 200 is reported as "reachable without
 * signing in; confirm that it is meant to be private", never as a proven flaw. And some sites answer 200 to every path (single-page apps), so a page
 * that answers a made-up path in the same way is treated as inconclusive, as S4 learned.
 */

export interface DomainObservation { route: string; url: string; status: number; bytes: number; outcome: "reachable" | "protected" | "inconclusive"; why: string; step?: number }

export interface DomainProbeInput {
  repo: string; domain: string; sha: string; graph: TwinGraph; set: FindingSet;
  /** the S4 client: GET/HEAD/OPTIONS only, public addresses only, caps */
  transport: Transport;
  /** proves ownership (S4: DNS record or well-known file). The runtime calls it itself, at the start of this run. */
  verifyDomain: (domain: string) => Promise<boolean>;
  /** who approved this run. The caller must already have checked that this person is allowed to (push access). */
  approval: { approvedBy: string; approvedAt: number };
  maxRoutes?: number;
  /** pause between requests, as S4 does (default 300 ms) */
  pauseMs?: number;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  killRegistry?: KillRegistry;
}

export interface DomainProbeResult { findings: Finding[]; observations: DomainObservation[]; requests: number; run: AgentRunResult; notes: string[] }

/** how close two response sizes must be to count as "the same page" */
const SAME = 0.05;
const sameSize = (a: number, b: number) => Math.abs(a - b) <= Math.max(16, Math.max(a, b) * SAME);

export async function probeDomain(input: DomainProbeInput): Promise<DomainProbeResult> {
  const now = input.now ?? Date.now;
  const sleep = input.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const pauseMs = input.pauseMs ?? 300;
  const notes: string[] = [];
  const observations: DomainObservation[] = [];
  const findings: Finding[] = [];
  let requests = 0;

  const spec = buildRange({ sha: input.sha, graph: input.graph }, input.set);
  const candidates = spec.endpoints
    .filter((e) => (e.method === "GET" || e.method === "PAGE") && e.minRole !== "anonymous" && !e.object && e.segments.every((s) => !/^[:[{]/.test(s)))
    .sort((a, b) => a.path.localeCompare(b.path))
    .slice(0, input.maxRoutes ?? 20);

  // Our adapter around the S4 client. Every request counts, waits its turn, and is a plain GET: the client itself cannot send anything else.
  const transport: ProbeTransport = async (url) => {
    const u = new URL(url);
    if (requests > 0) await sleep(pauseMs);
    requests++;
    const res = await input.transport.request(u.hostname, `${u.pathname}${u.search}`, { scheme: "https", method: "GET", maxBytes: 4096 });
    return { status: res.status, bodyBytes: res.bytes, headers: Object.fromEntries(Object.entries(res.headers).filter((e): e is [string, string] => typeof e[1] === "string")) };
  };
  const tool = probeTool({ transport });

  const at = now();
  const runId = `gd_${sha256Hex(`${input.repo}|${input.domain}|${at}`).slice(0, 12)}`;
  const roe = {
    version: 1 as const, runId, repo: input.repo,
    targets: [{ kind: "verified-domain" as const, domain: input.domain }],
    agents: ["graybox" as const],
    allowedClasses: ["observe" as const, "probe" as const],
    allowedTechniques: [T.access], forbiddenTechniques: [] as string[],
    window: { notBefore: Math.max(input.approval.approvedAt, at - 60_000), notAfter: at + 30 * 60_000 },
    budgets: { steps: Math.min(500, 4 + candidates.length), tokens: 1000, wallMs: 10 * 60_000, costUsd: 1 },
    approval: input.approval,
    killSwitchId: `kill_${runId}`,
  };

  const run = await runPlan({ roe, agent: "graybox", tools: [tool] as unknown as AnyTool[], verifyDomain: input.verifyDomain, now, killRegistry: input.killRegistry }, async (r) => {
    if (!candidates.length) { notes.push("The map has no plain GET route meant for signed-in users or admins, so there is nothing safe to check from the outside."); return; }
    const base = `https://${input.domain}`;

    // the control: a page that cannot exist. A site that answers it like a real page answers everything alike, and proves nothing.
    const controlPath = `/__mc-control-${sha256Hex(`${runId}`).slice(0, 8)}`;
    const control = await r.call("http_probe", { url: `${base}${controlPath}`, technique: T.access });
    if (!control.ok) {
      notes.push((control as { reason?: string }).reason === "ownership-not-reproved" ? "Ownership of the domain could not be proved just now, so nothing was sent to it." : `The run could not start (${(control as { reason?: string }).reason ?? "stopped"}).`);
      return;
    }
    const c = (control.result as { data?: { status?: number; bodyBytes?: number } }).data ?? {};
    const controlStatus = c.status ?? 0, controlBytes = c.bodyBytes ?? 0;

    for (const e of candidates) {
      if (!r.active()) { notes.push("The run was stopped before every route was checked."); break; }
      const url = `${base}${e.path}`;
      const label = `${e.method === "PAGE" ? "GET" : e.method} ${e.path}`;
      const res = await r.call("http_probe", { url, technique: T.access });
      if (!res.ok) { observations.push({ route: label, url, status: 0, bytes: 0, outcome: "inconclusive", why: `refused by the rules of this run (${(res as { reason?: string }).reason ?? "stopped"})` }); continue; }
      const d = (res.result as { data?: { status?: number; bodyBytes?: number } }).data ?? {};
      const status = d.status ?? 0, bytes = d.bodyBytes ?? 0;
      if (status === 401 || status === 403 || (status >= 300 && status < 400)) { observations.push({ route: label, url, status, bytes, outcome: "protected", why: status >= 300 && status < 400 ? "redirected, most likely to a sign-in page" : "refused without a sign-in", step: res.step }); continue; }
      if (status !== 200) { observations.push({ route: label, url, status, bytes, outcome: "inconclusive", why: `answered ${status}, which says nothing about access`, step: res.step }); continue; }
      if (controlStatus === 200 && sameSize(bytes, controlBytes)) { observations.push({ route: label, url, status, bytes, outcome: "inconclusive", why: "the site answers a page that does not exist in the same way, so a 200 proves nothing", step: res.step }); continue; }
      observations.push({ route: label, url, status, bytes, outcome: "reachable", why: "answered without a sign-in, unlike a page that does not exist", step: res.step });
      const admin = e.minRole === "admin";
      findings.push({
        id: fingerprint("sim", "anonymous-access", input.domain, e.path), ruleId: "SIM/anonymous-access", category: "runtime", severity: admin ? "high" : "medium", confidence: admin ? "medium" : "low",
        title: `${label} answers without signing in`,
        path: url,
        reason: `The map treats ${e.path} as meant for ${admin ? "admins" : "signed-in users"}, but an anonymous request to the live site got a real page back (200, ${bytes} bytes), unlike a page that does not exist (${controlStatus}). That is an assumption about what the page is meant for, so confirm it is meant to be private.`,
        fix: "Check who should be able to open this page. If it is private, require a sign-in (and, for an admin page, an admin role) before anything is returned, and make it answer 401 or 403 to everyone else.",
        cwe: [admin ? "CWE-862" : "CWE-306"], owasp: "A01:2021 Broken Access Control", detail: {},
        technique: T.access, proof: `GET ${url} answered 200 (${bytes} bytes) with no sign-in; a made-up path answered ${controlStatus}. Audit step #${res.step}.`,
      });
      r.conclude(`reachable: ${label}`, true);
    }
  });

  if (!run.ok && run.stopReason !== "finished") notes.push(`The run ended early (${run.stopReason}${run.refusal ? `: ${run.refusal}` : ""}).`);
  if (requests === 0 && !notes.length) notes.push("Nothing was sent.");
  return { findings, observations, requests, run, notes };
}
