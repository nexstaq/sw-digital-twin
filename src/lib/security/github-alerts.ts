import { SEVERITY_RANK, type Finding, type FindingSet, type Severity } from "./types";
import { fingerprint } from "./util";

type Source = NonNullable<FindingSet["sources"]>[string];
export interface Alerts { findings: Finding[]; sources: Record<string, Source>; /** built-in findings that Dependabot independently confirmed */ confirmed: Map<string, string[]> }

const apiBase = () => (process.env.GITHUB_API_URL ?? "https://api.github.com").replace(/\/$/, "");
type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown) => (typeof v === "string" ? v : "");
const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : undefined);
const https = (v: unknown) => (/^https:\/\/[^\s"'<>]+$/.test(str(v)) ? str(v) : undefined);
const sevOf = (v: unknown): Severity => { const s = str(v).toLowerCase(); return s === "critical" ? "critical" : s === "high" ? "high" : s === "medium" || s === "moderate" ? "medium" : s === "low" ? "low" : "medium"; };
const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
const worst = (a: Severity, b: Severity) => (SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b);

/** Dependabot's ecosystem names -> ours, so an alert and our own finding about the same package can be recognised as one. */
const ECOSYSTEM: Record<string, string> = { npm: "npm", pip: "PyPI", rust: "crates.io", cargo: "crates.io", go: "Go", gomod: "Go" };
export const depKey = (eco: string, name: string) => `${ECOSYSTEM[eco.toLowerCase()] ?? eco}:${name.toLowerCase()}`;

// ---------- fetching, with every outcome stated ----------

type PageResult = { ok: true; items: unknown[] } | { ok: false; status: number; message: string };

async function getAll(path: string, token: string | undefined, f: typeof fetch): Promise<PageResult> {
  const items: unknown[] = [];
  for (let page = 1; page <= 3; page++) {
    let res: Response;
    try {
      res = await f(`${apiBase()}${path}${path.includes("?") ? "&" : "?"}per_page=100&page=${page}`, {
        headers: { accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "sw-digital-twin", ...(token ? { authorization: `Bearer ${token}` } : {}) },
        cache: "no-store", signal: AbortSignal.timeout(15_000),
      });
    } catch { return { ok: false, status: 0, message: "GitHub could not be reached." }; }
    if (!res.ok) return { ok: false, status: res.status, message: str(obj(await res.json().catch(() => null)).message) };
    const batch = arr(await res.json().catch(() => []));
    items.push(...batch);
    if (batch.length < 100) break;
  }
  return { ok: true, items };
}

/** One honest sentence for why a source gave nothing, and what to do about it. */
export function explainUnavailable(name: string, status: number, message: string): string {
  const what = name === "dependabot" ? "Dependabot alerts" : name === "code-scanning" ? "code scanning alerts" : "secret scanning alerts";
  const perm = name === "dependabot" ? "Dependabot alerts" : name === "code-scanning" ? "Code scanning alerts" : "Secret scanning alerts";
  if (status === 0 || status >= 500 || status === 429) return `GitHub could not be asked for ${what} right now. Scan again in a minute.`;
  if (/not accessible by integration/i.test(message)) return `The GitHub App is not allowed to read ${what}. In the App's settings, give it the "${perm}: Read-only" repository permission, then accept the update on the installation.`;
  if (/disabled|not enabled|must be enabled|advanced security|not available/i.test(message)) return `${what[0].toUpperCase()}${what.slice(1)} are not switched on for this repository (GitHub offers them free on public repositories, and on private ones with GitHub Advanced Security).`;
  if (status === 404 || status === 403) return `${what[0].toUpperCase()}${what.slice(1)} are unavailable: they may be switched off for this repository, or the GitHub App may lack the "${perm}" permission.`;
  return `${what[0].toUpperCase()}${what.slice(1)} could not be read (GitHub answered ${status}).`;
}

// ---------- mapping (pure) ----------

export function mapDependabot(items: unknown[]): Finding[] {
  const groups = new Map<string, { eco: string; name: string; manifest: string; worst: Severity; url?: string; vulns: NonNullable<Finding["detail"]["vulns"]>; cwe: Set<string>; direct: boolean; dev: boolean; fixes: string[]; unfixed: boolean }>();
  for (const raw of items) {
    const a = obj(raw);
    if (str(a.state) && str(a.state) !== "open") continue;
    const dep = obj(obj(a.dependency).package), vuln = obj(a.security_vulnerability), adv = obj(a.security_advisory);
    const name = str(dep.name) || str(obj(vuln.package).name), eco = str(dep.ecosystem) || str(obj(vuln.package).ecosystem);
    if (!name) continue;
    const manifest = str(obj(a.dependency).manifest_path) || "(manifest)";
    const key = `${depKey(eco, name)}@${manifest}`;
    const sev = sevOf(vuln.severity || adv.severity);
    const fixed = str(obj(vuln.first_patched_version).identifier);
    const g = groups.get(key) ?? groups.set(key, { eco, name, manifest, worst: "low", vulns: [], cwe: new Set(), direct: str(obj(a.dependency).relationship) !== "transitive", dev: str(obj(a.dependency).scope) === "development", fixes: [], unfixed: false }).get(key)!;
    g.worst = worst(g.worst, sev);
    g.url ??= https(a.html_url);
    if (fixed) g.fixes.push(fixed); else g.unfixed = true;
    for (const c of arr(adv.cwes)) { const id = str(obj(c).cwe_id); if (id) g.cwe.add(id.toUpperCase()); }
    g.vulns.push({ id: str(adv.ghsa_id) || `alert-${num(a.number) ?? "?"}`, aliases: str(adv.cve_id) ? [str(adv.cve_id)] : [], summary: clip(str(adv.summary) || "No description published.", 200), severity: sev, ...(num(obj(adv.cvss).score) ? { score: num(obj(adv.cvss).score) } : {}), fixedIn: fixed ? [fixed] : [], ...(https(a.html_url) ? { url: https(a.html_url) } : {}) });
  }
  return [...groups.values()].map((g) => {
    const top = g.vulns[0];
    return {
      id: fingerprint("dependabot", depKey(g.eco, g.name), g.manifest), ruleId: "dependabot/alert", category: "dependency", severity: g.worst,
      title: `${g.name} has ${g.vulns.length} open Dependabot alert${g.vulns.length === 1 ? "" : "s"}`, path: g.manifest,
      reason: `${top.summary}${top.aliases[0] ? ` (${top.aliases[0]})` : ""}${g.vulns.length > 1 ? ` and ${g.vulns.length - 1} more` : ""}. Reported by GitHub Dependabot.`,
      fix: g.fixes.length && !g.unfixed ? `Upgrade ${g.name} to ${[...g.fixes].sort().at(-1)} or later (Dependabot can open this pull request for you).` : "No patched version is available for at least one of these yet. Watch the advisory, or replace the package.",
      cwe: [...g.cwe].slice(0, 4), owasp: "A06:2021 Vulnerable and Outdated Components", confidence: "high",
      detail: { source: "dependabot", ...(g.url ? { url: g.url } : {}), package: g.name, ecosystem: ECOSYSTEM[g.eco.toLowerCase()] ?? g.eco, direct: g.direct, dev: g.dev, vulns: g.vulns.slice(0, 20) },
    } satisfies Finding;
  });
}

export function mapCodeScanning(items: unknown[]): Finding[] {
  const out: Finding[] = [];
  for (const raw of items) {
    const a = obj(raw);
    if (str(a.state) && str(a.state) !== "open") continue;
    const rule = obj(a.rule), loc = obj(obj(a.most_recent_instance).location), tool = str(obj(a.tool).name) || "code scanning";
    const path = str(loc.path);
    if (!path || path.startsWith("/") || path.split("/").includes("..")) continue;
    const level = str(rule.security_severity_level) || (str(rule.severity) === "error" ? "high" : str(rule.severity) === "warning" ? "medium" : "low");
    const line = num(loc.start_line), endLine = num(loc.end_line);
    const slug = tool.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "scanner";
    out.push({
      id: fingerprint("gh-code-scanning", slug, str(rule.id), path), ruleId: `${slug}/${clip(str(rule.id) || "alert", 80)}`, category: "code", severity: sevOf(level),
      title: clip(str(rule.description) || str(rule.name) || str(rule.id) || "Code scanning alert", 120), path, ...(line ? { line } : {}), ...(endLine && line && endLine >= line ? { endLine } : {}),
      reason: clip(str(obj(obj(a.most_recent_instance).message).text) || str(rule.description) || "Reported by GitHub code scanning.", 600),
      fix: "Open the alert on GitHub for this rule's guidance and a suggested fix.",
      cwe: [...new Set(arr(rule.tags).map(str).flatMap((t) => [...t.matchAll(/cwe[-/_ ]?(\d{1,5})/gi)].map((m) => `CWE-${m[1]}`)))].slice(0, 4),
      confidence: "high", detail: { source: "codeql", ...(https(a.html_url) ? { url: https(a.html_url) } : {}) },
    });
  }
  return out;
}

/** `locations` maps an alert number to its first location. The secret VALUE (`secret`) is never read, copied or stored. */
export function mapSecretScanning(items: unknown[], locations: Map<number, { path: string; line?: number }>): Finding[] {
  const out: Finding[] = [];
  for (const raw of items) {
    const a = obj(raw);
    if (str(a.state) && str(a.state) !== "open") continue;
    const n = num(a.number);
    if (n === undefined) continue;
    const kind = clip(str(a.secret_type_display_name) || str(a.secret_type) || "Secret", 80);
    const loc = locations.get(n);
    const active = str(a.validity) === "active";
    out.push({
      id: fingerprint("gh-secret", String(n)), ruleId: `secret-scanning/${clip(str(a.secret_type) || "secret", 60)}`, category: "secret", severity: active ? "critical" : "high",
      title: `${kind} found by GitHub secret scanning`, path: loc?.path ?? "(location not provided by GitHub)", ...(loc?.line ? { line: loc.line } : {}),
      reason: `GitHub's secret scanning found a ${kind} committed to this repository${active ? ", and reports it is still ACTIVE" : ""}. Anyone who can read the repository can use it.`,
      fix: "Treat it as leaked: revoke or rotate it with the provider now, then remove it from the code. Deleting it from the latest commit does not remove it from history.",
      cwe: ["CWE-798"], owasp: "A07:2021 Identification and Authentication Failures", confidence: "high",
      detail: { source: "secret-scanning", secretKind: kind, masked: "(value not stored)", ...(https(a.html_url) ? { url: https(a.html_url) } : {}) },
    });
  }
  return out;
}

// ---------- the whole thing ----------

/**
 * Pulls open alerts from GitHub's three security features for one repository. Each is independent and reports its own status,
 * so "Dependabot gave 4 alerts, code scanning is not switched on, secret scanning needs a permission" is what the person sees,
 * never a silent empty list.
 */
export async function fetchGithubAlerts(repo: string, token: string | undefined, builtIn: Finding[], f: typeof fetch = fetch): Promise<Alerts> {
  const sources: Record<string, Source> = {};
  const findings: Finding[] = [];
  const confirmed = new Map<string, string[]>();
  const now = Date.now();
  const fail = (name: string, r: { status: number; message: string }): Source => ({ status: "unavailable", count: 0, message: explainUnavailable(name, r.status, r.message), importedAt: now, via: "github" });

  const [dep, code, sec] = await Promise.all([
    getAll(`/repos/${repo}/dependabot/alerts?state=open`, token, f),
    getAll(`/repos/${repo}/code-scanning/alerts?state=open`, token, f),
    getAll(`/repos/${repo}/secret-scanning/alerts?state=open`, token, f),
  ]);

  if (!dep.ok) sources.dependabot = fail("dependabot", dep);
  else {
    const mapped = mapDependabot(dep.items);
    const ours = new Map<string, Finding>();
    for (const b of builtIn) if (b.category === "dependency" && b.detail.package && !b.detail.source) ours.set(depKey(b.detail.ecosystem ?? "", b.detail.package), b);
    for (const m of mapped) {
      const mine = ours.get(depKey(m.detail.ecosystem ?? "", m.detail.package ?? ""));
      if (mine) confirmed.set(mine.id, [...(confirmed.get(mine.id) ?? []), "dependabot"]); // the same flaw, seen twice: one finding with more evidence
      else findings.push(m);
    }
    sources.dependabot = { status: "ok", count: dep.items.length, importedAt: now, via: "github" };
  }

  if (!code.ok) {
    // "no analysis found" means code scanning is on but has not run: that is a state, not a failure
    sources["code-scanning"] = code.status === 404 && /no analysis found/i.test(code.message)
      ? { status: "ok", count: 0, message: "Code scanning is on, but no analysis has run yet.", importedAt: now, via: "github" }
      : fail("code-scanning", code);
  } else { findings.push(...mapCodeScanning(code.items)); sources["code-scanning"] = { status: "ok", count: code.items.length, importedAt: now, via: "github" }; }

  if (!sec.ok) sources["secret-scanning"] = fail("secret-scanning", sec);
  else {
    const locations = new Map<number, { path: string; line?: number }>();
    await Promise.all(sec.items.slice(0, 20).map(async (it) => {
      const n = num(obj(it).number);
      if (n === undefined) return;
      const r = await getAll(`/repos/${repo}/secret-scanning/alerts/${n}/locations`, token, f);
      if (!r.ok) return;
      const d = obj(obj(r.items[0]).details);
      const path = str(d.path);
      if (path && !path.startsWith("/") && !path.split("/").includes("..")) locations.set(n, { path, ...(num(d.start_line) ? { line: num(d.start_line) } : {}) });
    }));
    findings.push(...mapSecretScanning(sec.items, locations));
    sources["secret-scanning"] = { status: "ok", count: sec.items.length, importedAt: now, via: "github" };
  }
  return { findings, sources, confirmed };
}
