import type { Finding, SecurityContext, Severity, Vuln } from "../types";
import { SEVERITY_RANK } from "../types";
import { fingerprint, lineOf } from "../util";
import { parseLockfiles, type Pkg } from "./lockfiles";
import { fetchVulns, mergeVulns, normalizeVuln, queryBatch, type OsvOpts, type VulnDetail } from "./osv";

const SOURCE = /\.(?:[cm]?[jt]sx?|py|go)$/;
const MAX_SOURCE_FILES = 2500;
const PY_MODULE: Record<string, string> = { pyyaml: "yaml", pillow: "PIL", beautifulsoup4: "bs4", "scikit-learn": "sklearn", "python-dateutil": "dateutil", "opencv-python": "cv2", "pyjwt": "jwt", "python-dotenv": "dotenv", protobuf: "google.protobuf" };

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Numeric, good-enough version compare ("4.17.21" > "4.17.9"). Pre-release tags sort below the release. */
export function cmpVersion(a: string, b: string): number {
  const seg = (v: string) => v.replace(/^v/, "").split(/[.+-]/).map((x) => (/^\d+$/.test(x) ? Number(x) : -1));
  const x = seg(a), y = seg(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] ?? 0) - (y[i] ?? 0); if (d) return d; }
  return 0;
}

/** The smallest published fix that is newer than what you have, preferring one on your current major version. */
export function pickFix(current: string, fixed: string[]): string | undefined {
  const major = (v: string) => v.replace(/^v/, "").split(".")[0];
  const newer = fixed.filter((f) => cmpVersion(f, current) > 0).sort(cmpVersion);
  return newer.find((f) => major(f) === major(current)) ?? newer[0];
}

/** Which of these packages does your own source actually import? (npm, PyPI and Go; others report "unknown".) */
export async function findUsage(ctx: SecurityContext, pkgs: Pkg[]): Promise<Map<string, string[]>> {
  const used = new Map<string, string[]>();
  const probes = pkgs.filter((p) => p.ecosystem === "npm" || p.ecosystem === "PyPI" || p.ecosystem === "Go").map((p) => {
    const mod = p.ecosystem === "PyPI" ? PY_MODULE[p.name] ?? p.name.replace(/-/g, "_") : p.name;
    const re = p.ecosystem === "npm" ? new RegExp(`(?:from\\s+|import\\s+|require\\(\\s*|import\\(\\s*)["']${esc(mod)}(?:/[^"']*)?["']`)
      : p.ecosystem === "PyPI" ? new RegExp(`^\\s*(?:import|from)\\s+${esc(mod)}\\b`, "m")
      : new RegExp(`"${esc(mod)}(?:/[^"]*)?"`);
    return { key: `${p.ecosystem}:${p.name}`, mod, re, eco: p.ecosystem };
  });
  if (!probes.length) return used;
  let n = 0;
  for (const path of ctx.files) {
    if (!SOURCE.test(path) || /(^|\/)(node_modules|vendor)\//.test(path)) continue;
    if (++n > MAX_SOURCE_FILES) break;
    const isPy = path.endsWith(".py"), isGo = path.endsWith(".go");
    const text = await ctx.read(path);
    if (!text) continue;
    for (const p of probes) {
      if ((p.eco === "PyPI") !== isPy || (p.eco === "Go") !== isGo) continue;
      if (!text.includes(p.mod.split(".")[0])) continue;
      if (p.re.test(text)) { const l = used.get(p.key) ?? []; if (l.length < 5) l.push(path); used.set(p.key, l); }
    }
  }
  return used;
}

function whereIs(p: Pkg, files: Map<string, string | null>, manifest: { path: string; text: string | null } | undefined): { path: string; line?: number } {
  if (p.line) return { path: p.path, line: p.line };
  const lock = files.get(p.path) ?? null;
  if (p.direct && manifest?.text && p.ecosystem === "npm") { const line = lineOf(manifest.text, `"${p.name}"`); if (line) return { path: manifest.path, line }; }
  if (lock) {
    const line = p.ecosystem === "npm" ? lineOf(lock, `node_modules/${p.name}"`) ?? lineOf(lock, new RegExp(`^\\s*['"]?/?${esc(p.name)}@${esc(p.version)}`)) ?? lineOf(lock, new RegExp(`^\\s*['"]?/?${esc(p.name)}@`)) ?? lineOf(lock, `"${p.name}"`)
      : lineOf(lock, new RegExp(`name\\s*=\\s*"${esc(p.name)}"`));
    if (line) return { path: p.path, line };
  }
  return { path: p.path };
}

export interface DepResult { findings: Finding[]; packages: number; lockfiles: number; warnings: string[] }

export async function analyzeDependencies(ctx: SecurityContext, o: OsvOpts = {}): Promise<DepResult> {
  const { packages, lockfiles, warnings, manifests } = await parseLockfiles(ctx);
  if (!packages.length) return { findings: [], packages: 0, lockfiles, warnings };

  let hits: string[][];
  try { hits = await queryBatch(packages, o); } catch (e) {
    return { findings: [], packages: packages.length, lockfiles, warnings: [...warnings, `Could not reach the vulnerability database (${e instanceof Error ? e.message : "network error"}), so dependencies were NOT checked. This is not an all-clear.`] };
  }
  const vulnerable = packages.map((p, i) => ({ p, ids: hits[i] })).filter((x) => x.ids.length);
  if (!vulnerable.length) return { findings: [], packages: packages.length, lockfiles, warnings };

  const { byId, skipped, failed } = await fetchVulns(vulnerable.flatMap((x) => x.ids), o);
  if (skipped) warnings.push(`${skipped} more advisories were not looked up (the first 200 were).`);
  if (failed) warnings.push(`${failed} advisories could not be fetched; those packages may be missing details.`);

  const usage = await findUsage(ctx, vulnerable.map((x) => x.p));
  const cache = new Map<string, string | null>();
  for (const x of vulnerable) if (!cache.has(x.p.path)) cache.set(x.p.path, await ctx.read(x.p.path));

  const findings: Finding[] = [];
  for (const { p, ids } of vulnerable) {
    const vulns: VulnDetail[] = mergeVulns(ids.map((id) => byId.get(id)).filter((v): v is NonNullable<typeof v> => !!v).map((v) => normalizeVuln(v, p)).filter((v) => !v.withdrawn));
    if (!vulns.length) continue;
    vulns.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (b.score ?? 0) - (a.score ?? 0));
    const worst: Severity = vulns[0].severity;
    const fixes = vulns.map((v) => pickFix(p.version, v.fixedIn)).filter((f): f is string => !!f);
    const best = fixes.length === vulns.length ? fixes.sort(cmpVersion).at(-1) : undefined; // only promise a version that fixes everything
    const used = usage.get(`${p.ecosystem}:${p.name}`);
    const supportsUsage = p.ecosystem === "npm" || p.ecosystem === "PyPI" || p.ecosystem === "Go";
    const loc = whereIs(p, cache, manifests.get(p.path.includes("/") ? p.path.slice(0, p.path.lastIndexOf("/")) : ""));

    const chain = p.via?.length ? ` It comes in through ${p.via.join(" → ")}.` : "";
    const reach = p.dev ? `It is a development-only dependency (a build or test tool), so it does not ship to production, but it runs on developer machines and in CI.${chain}`
      : used?.length ? `Your code imports it (${used.slice(0, 3).join(", ")}${used.length > 3 ? ", …" : ""}), so the vulnerable code is reachable.`
      : p.direct ? (supportsUsage ? "You declare it directly, but no import was found in your source. It may be used indirectly or only by tooling, so check before treating this as urgent." : "You declare it directly.")
      : `It is pulled in by another package rather than declared by you.${chain}`;
    const top = vulns[0];
    const majorJump = best !== undefined && best.replace(/^v/, "").split(".")[0] !== p.version.replace(/^v/, "").split(".")[0];
    const jumpNote = majorJump ? " That is a major-version jump, so read the changelog; the advisories above list fixes on older branches too." : "";
    const parent = p.via?.[0] ? `\`${p.via[0]}\`` : "the package that depends on it";
    const nothingFixed = fixes.length === 0;
    const fix = best
      ? p.direct ? `Upgrade ${p.name} to ${best} or later.${jumpNote}` : `Update ${parent}, which brings in ${p.name}, or force ${best} or later (npm \`overrides\`, yarn \`resolutions\`, pnpm \`overrides\`).${jumpNote}`
      : nothingFixed
        ? p.direct
          ? "No fixed version has been published yet. Watch the advisory for one, check whether your code reaches the affected function, or replace the package."
          : `No fixed version has been published yet, and you do not control ${p.name} directly. Check whether your code reaches the affected function, and update ${parent} once it ships a release that pulls in a fixed ${p.name} (it arrives through ${p.via?.length ? p.via.join(" → ") : "another package"}).`
        : "No single published version fixes all of these. Check each advisory for a workaround, or replace the package."; 

    findings.push({
      id: fingerprint("dependency", p.ecosystem, p.name, p.version, p.path), ruleId: "SCA/known-vulnerability", category: "dependency", severity: worst,
      title: `${p.name}@${p.version} has ${vulns.length} known ${vulns.length === 1 ? "vulnerability" : "vulnerabilities"}`,
      path: loc.path, line: loc.line,
      reason: `${top.summary}${top.aliases.length ? ` (${top.aliases[0]})` : ` (${top.id})`}${vulns.length > 1 ? ` and ${vulns.length - 1} more.` : "."} ${reach}`,
      fix, cwe: [...new Set(vulns.flatMap((v) => v.cwe))].slice(0, 4), owasp: "A06:2021 Vulnerable and Outdated Components",
      confidence: p.dev || (supportsUsage && !used?.length && !p.direct) ? "medium" : "high",
      detail: {
        package: p.name, ecosystem: p.ecosystem, version: p.version, direct: !!p.direct, dev: !!p.dev, ...(p.via ? { via: p.via } : {}), ...(supportsUsage ? { usedIn: used ?? [] } : {}),
        vulns: vulns.map(({ cwe: _c, withdrawn: _w, ...v }): Vuln => v), // eslint-disable-line @typescript-eslint/no-unused-vars
      },
    });
  }
  return { findings, packages: packages.length, lockfiles, warnings };
}
