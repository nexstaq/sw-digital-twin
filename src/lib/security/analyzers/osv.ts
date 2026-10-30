import type { Severity, Vuln } from "../types";
import { cvss3, severityOfLabel, severityOfScore } from "./cvss";
import type { Pkg } from "./lockfiles";

/** OSV.dev: open, free, no key. OSV_API_URL points tests (and a self-hosted mirror) elsewhere. */
const base = () => (process.env.OSV_API_URL ?? "https://api.osv.dev").replace(/\/$/, "");
export interface OsvOpts { fetch?: typeof fetch; signal?: AbortSignal }

const BATCH = 1000;
const DETAIL_CONCURRENCY = 8;
export const MAX_VULN_DETAILS = 200;

async function post<T>(path: string, body: unknown, o: OsvOpts): Promise<T> {
  const res = await (o.fetch ?? fetch)(`${base()}${path}`, { method: "POST", headers: { "content-type": "application/json", "user-agent": "sw-digital-twin" }, body: JSON.stringify(body), signal: o.signal });
  if (!res.ok) throw new Error(`OSV answered ${res.status}`);
  return (await res.json()) as T;
}

/** For each package (same order), the ids of the advisories that affect exactly that version. */
export async function queryBatch(pkgs: Pkg[], o: OsvOpts = {}): Promise<string[][]> {
  const out: string[][] = [];
  for (let i = 0; i < pkgs.length; i += BATCH) {
    const chunk = pkgs.slice(i, i + BATCH);
    const r = await post<{ results?: { vulns?: { id: string }[] }[] }>("/v1/querybatch", { queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version.replace(/^v(?=\d)/, p.ecosystem === "Go" ? "v" : "") })) }, o);
    for (let k = 0; k < chunk.length; k++) out.push((r.results?.[k]?.vulns ?? []).map((v) => v.id));
  }
  return out;
}

interface RawVuln {
  id: string; aliases?: string[]; summary?: string; details?: string; withdrawn?: string;
  severity?: { type: string; score: string }[]; database_specific?: { severity?: string; cwe_ids?: string[] };
  affected?: { package?: { name?: string; ecosystem?: string }; ranges?: { events?: { fixed?: string }[] }[] }[];
  references?: { type?: string; url: string }[];
}

export interface VulnDetail extends Vuln { cwe: string[]; withdrawn: boolean }

/** Turns an advisory into what we show. `pkg` picks the right `fixed` versions when one advisory covers several packages. */
export function normalizeVuln(raw: RawVuln, pkg: Pkg): VulnDetail {
  const vec = raw.severity?.find((s) => /^CVSS_V3/i.test(s.type))?.score ?? raw.severity?.find((s) => /^CVSS:3/.test(s.score))?.score;
  const score = vec ? cvss3(vec) : null;
  const severity: Severity = score !== null ? severityOfScore(score) : severityOfLabel(raw.database_specific?.severity) ?? "medium";
  const fixedIn = [...new Set((raw.affected ?? [])
    .filter((a) => !a.package || (a.package.name?.toLowerCase() === pkg.name.toLowerCase() && (!a.package.ecosystem || a.package.ecosystem.split(":")[0] === pkg.ecosystem)))
    .flatMap((a) => (a.ranges ?? []).flatMap((r) => (r.events ?? []).map((e) => e.fixed).filter((f): f is string => !!f))))];
  const advisory = raw.references?.find((r) => r.type === "ADVISORY")?.url ?? raw.references?.[0]?.url;
  const summary = (raw.summary ?? raw.details ?? "No description published.").replace(/\s+/g, " ").trim().slice(0, 200);
  return {
    id: raw.id, aliases: (raw.aliases ?? []).slice(0, 6), summary, severity, ...(score !== null ? { score } : {}), fixedIn,
    url: advisory && /^https?:\/\//.test(advisory) ? advisory : `https://osv.dev/vulnerability/${encodeURIComponent(raw.id)}`,
    cwe: raw.database_specific?.cwe_ids ?? [], withdrawn: !!raw.withdrawn,
  };
}

export async function fetchVuln(id: string, o: OsvOpts = {}): Promise<RawVuln | null> {
  const res = await (o.fetch ?? fetch)(`${base()}/v1/vulns/${encodeURIComponent(id)}`, { headers: { "user-agent": "sw-digital-twin" }, signal: o.signal });
  return res.ok ? ((await res.json()) as RawVuln) : null;
}

/** Fetches each distinct advisory once, a few at a time. Returns what it could get and how many it had to skip. */
export async function fetchVulns(ids: string[], o: OsvOpts = {}): Promise<{ byId: Map<string, RawVuln>; skipped: number; failed: number }> {
  const unique = [...new Set(ids)];
  const wanted = unique.slice(0, MAX_VULN_DETAILS);
  const byId = new Map<string, RawVuln>();
  let failed = 0, next = 0;
  await Promise.all(Array.from({ length: Math.min(DETAIL_CONCURRENCY, wanted.length) }, async () => {
    while (next < wanted.length) {
      const id = wanted[next++];
      try { const v = await fetchVuln(id, o); if (v) byId.set(id, v); else failed++; } catch { failed++; }
    }
  }));
  return { byId, skipped: unique.length - wanted.length, failed };
}

/**
 * One flaw is often published under several ids (a GHSA, a PYSEC and a BIT entry for the same CVE). Advisories that share any id or
 * alias are merged into one: worst severity and score, every fixed version, a CVE id first in the aliases.
 */
export function mergeVulns(vulns: VulnDetail[]): VulnDetail[] {
  const groups: VulnDetail[][] = [];
  const idsOf = (v: VulnDetail) => [v.id, ...v.aliases];
  for (const v of vulns) {
    const mine = new Set(idsOf(v));
    const hit = groups.filter((g) => g.some((x) => idsOf(x).some((i) => mine.has(i))));
    if (!hit.length) { groups.push([v]); continue; }
    const [first, ...rest] = hit;
    first.push(v);
    for (const g of rest) { first.push(...g); groups.splice(groups.indexOf(g), 1); }
  }
  const rank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  return groups.map((g) => {
    const best = g.reduce((a, b) => (rank[b.severity] > rank[a.severity] || (b.severity === a.severity && (b.score ?? 0) > (a.score ?? 0)) ? b : a));
    const rep = g.find((x) => x.id.startsWith("GHSA-")) ?? best;
    const all = [...new Set(g.flatMap(idsOf))].filter((i) => i !== rep.id);
    all.sort((a, b) => Number(/^CVE-/.test(b)) - Number(/^CVE-/.test(a)));
    return { ...rep, severity: best.severity, ...(best.score !== undefined ? { score: best.score } : {}), aliases: all.slice(0, 6), fixedIn: [...new Set(g.flatMap((x) => x.fixedIn))], cwe: [...new Set(g.flatMap((x) => x.cwe))] };
  });
}
