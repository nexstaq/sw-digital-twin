import { redactLine } from "./analyzers/secrets";
import type { Category, Finding, Severity } from "./types";
import { fingerprint } from "./util";

export const MAX_SARIF_BYTES = 5_000_000;
export const MAX_RESULTS = 2000;

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string => (typeof v === "string" ? v : "");
const num = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) ? v : typeof v === "string" && /^\d+(\.\d+)?$/.test(v) ? Number(v) : undefined);

/** Lowercase, no punctuation: used in ids and to recognise well-known tools. */
export const toolSlug = (name: string) => name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "tool";

const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
/** Everything we keep from a tool's text goes through here: bounded, one line of whitespace, and any secret-shaped value blanked. */
const clean = (s: string, n: number) => clip(redactLine(s.replace(/\s+/g, " ").trim()), n);

function severityOf(score: number | undefined, level: string): Severity {
  if (score !== undefined) return score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : score > 0 ? "low" : "info";
  return level === "error" ? "high" : level === "warning" ? "medium" : level === "note" ? "low" : level === "none" ? "info" : "medium";
}

/** A location we can safely show: a repo-relative path, or an http(s) URL WITHOUT its query string or fragment (those can carry tokens). */
export function cleanLocation(uri: string): { path: string; isUrl: boolean } | null {
  const u = uri.trim();
  if (!u) return null;
  if (/^https?:\/\//i.test(u)) {
    try { const x = new URL(u); return { path: `${x.origin}${x.pathname}`.slice(0, 300), isUrl: true }; } catch { return null; }
  }
  let p = u.replace(/^file:\/\//i, "").replace(/^%SRCROOT%\/?/i, "").replace(/^\.\//, "").replace(/\\/g, "/");
  if (p.startsWith("/") || /^[a-z]:\//i.test(p) || p.split("/").some((s) => s === "..")) return null; // absolute or escaping: not a repo path
  try { p = decodeURIComponent(p); } catch { /* keep as is */ }
  return p && p.length <= 300 ? { path: p, isUrl: false } : null;
}

function categoryFor(tool: string, ruleId: string, tags: string[], isUrl: boolean): Category {
  if (isUrl) return "runtime";
  const hay = `${tool} ${ruleId} ${tags.join(" ")}`.toLowerCase();
  if (/gitleaks|trufflehog|secret|credential|detect-secrets/.test(hay)) return "secret";
  if (/trivy|grype|osv|snyk|dependabot|dependency|sca\b|npm-audit|pip-audit/.test(hay)) return "dependency";
  if (/hadolint|dockle|docker|container|checkov|tfsec|terrascan|kics|iac/.test(hay)) return "container";
  if (/actionlint|zizmor|workflow/.test(hay)) return "pipeline";
  return "code";
}

export interface ParsedSarif { tool: string; slug: string; findings: Finding[]; skipped: number; warnings: string[] }

/**
 * SARIF 2.1.0 results from any tool (Semgrep, CodeQL, Trivy, ZAP, Nuclei, gitleaks…) become findings. It never throws: anything
 * malformed is skipped and counted. Only what a person needs is kept (rule, message, location); code snippets are ignored.
 */
export function parseSarif(input: unknown): ParsedSarif {
  const warnings: string[] = [];
  const findings: Finding[] = [];
  let skipped = 0;
  let toolName = "";
  const doc = obj(input);
  const runs = arr(doc.runs);
  if (!Array.isArray(doc.runs) || !runs.length) return { tool: "", slug: "", findings, skipped, warnings: ["This does not look like SARIF: it has no `runs`."] };
  if (doc.version !== undefined && !/^2\.1/.test(String(doc.version))) warnings.push(`SARIF version ${String(doc.version)} is not 2.1; results were read on a best-effort basis.`);

  for (const runRaw of runs) {
    const run = obj(runRaw);
    const driver = obj(obj(run.tool).driver);
    const tool = clean(str(driver.name) || "unknown tool", 60);
    toolName ||= tool;
    const slug = toolSlug(tool);
    const rules = new Map<string, Obj>();
    arr(driver.rules).forEach((r, i) => { const o = obj(r); rules.set(str(o.id) || String(i), o); });
    const ruleList = arr(driver.rules).map(obj);

    for (const rawResult of arr(run.results)) {
      if (findings.length >= MAX_RESULTS) { skipped++; continue; }
      const res = obj(rawResult);
      const ruleIdx = num(res.ruleIndex);
      const ruleId = str(res.ruleId) || str(obj(res.rule).id) || (ruleIdx !== undefined ? str(ruleList[ruleIdx]?.id) : "");
      const rule = rules.get(ruleId) ?? (ruleIdx !== undefined ? ruleList[ruleIdx] : undefined) ?? {};
      const message = clean(str(obj(res.message).text) || str(obj(res.message).markdown), 600);
      const loc = obj(obj(arr(res.locations)[0]).physicalLocation);
      const where = cleanLocation(str(obj(loc.artifactLocation).uri));
      if (!ruleId && !message) { skipped++; continue; }
      if (!where) { skipped++; continue; } // a finding with no usable location cannot be shown or mapped

      const region = obj(loc.region);
      const line = num(region.startLine), endLine = num(region.endLine);
      const props = obj(res.properties), ruleProps = obj(rule.properties);
      const tags = arr(ruleProps.tags).map(str).filter(Boolean);
      const score = num(props["security-severity"]) ?? num(ruleProps["security-severity"]);
      const level = str(res.level) || str(obj(rule.defaultConfiguration).level) || "warning";
      const cwe = [...new Set([...tags, str(ruleProps.cwe)].flatMap((t) => [...t.matchAll(/cwe[-/_ ]?(\d{1,5})/gi)].map((m) => `CWE-${m[1]}`)))].slice(0, 4);
      const precision = str(ruleProps.precision).toLowerCase();
      const fp = Object.values(obj(res.partialFingerprints)).find((v) => typeof v === "string" && v) as string | undefined;
      const title = clean(str(obj(rule.shortDescription).text) || str(rule.name) || ruleId || message, 120);
      const help = clean(str(obj(rule.help).text) || str(obj(rule.fullDescription).text), 500);
      const helpUri = str(rule.helpUri);

      findings.push({
        id: fingerprint("sarif", slug, ruleId, where.path, fp ?? message.slice(0, 80)),
        ruleId: `${slug}/${clean(ruleId || "finding", 80)}`,
        category: categoryFor(tool, ruleId, tags, where.isUrl),
        severity: severityOf(score, level),
        title: title || "Finding reported by " + tool,
        path: where.path, ...(line && line > 0 ? { line: Math.floor(line) } : {}), ...(endLine && line && endLine >= line ? { endLine: Math.floor(endLine) } : {}),
        reason: message || title,
        fix: help || "See the reporting tool's documentation for this rule.",
        cwe, confidence: precision.includes("high") ? "high" : precision === "low" ? "low" : "medium",
        detail: { source: `sarif:${slug}`, sourceName: tool, ...(/^https:\/\/[^\s"'<>]+$/.test(helpUri) ? { url: helpUri } : {}) },
      });
    }
  }
  if (skipped) warnings.push(`${skipped} result${skipped === 1 ? " was" : "s were"} skipped (no usable location, malformed, or over the ${MAX_RESULTS} limit).`);
  return { tool: toolName, slug: toolSlug(toolName), findings, skipped, warnings };
}

/** Replaces everything this tool reported before with its newest report, leaving every other source untouched. */
export function mergeImport(existing: Finding[], parsed: ParsedSarif): Finding[] {
  const key = `sarif:${parsed.slug}`;
  const seen = new Set<string>();
  return [...existing.filter((f) => f.detail.source !== key), ...parsed.findings.filter((f) => !seen.has(f.id) && !!seen.add(f.id))];
}
