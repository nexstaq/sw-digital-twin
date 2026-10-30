import type { TwinGraph } from "@/lib/graph/types";
import { mapFindings, posture, priority } from "./map";
import { attackPaths } from "./paths";
import { describeDelta } from "./trend";
import { CATEGORIES, SEVERITIES, type Finding, type FindingSet, type Severity } from "./types";

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
/** A URL we are willing to put in an href: https only, so an advisory link can never be `javascript:`. */
const safeUrl = (u: string | undefined) => (u && /^https:\/\/[^\s"'<>]+$/.test(u) ? u : undefined);

const CATEGORY_NAME = { dependency: "Dependencies", secret: "Secrets", pipeline: "CI pipelines", container: "Containers", code: "Source code" } as const;
const SEV_NAME: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const SEV_COLOR: Record<Severity, string> = { critical: "#b4161b", high: "#d1242f", medium: "#9a6700", low: "#57606a", info: "#8c959f" };

const blob = (repo: string, sha: string, path: string, line?: number) => `https://github.com/${repo}/blob/${sha}/${path.split("/").map(encodeURIComponent).join("/")}${line ? `#L${line}` : ""}`;

export interface ReportInput { set: FindingSet; graph?: TwinGraph; generatedAt?: number }

function findingHtml(f: Finding, repo: string, sha: string): string {
  const d = f.detail;
  const vulns = d.vulns?.length
    ? `<table class="vulns"><thead><tr><th>Advisory</th><th>Severity</th><th>CVSS</th><th>Fixed in</th></tr></thead><tbody>${d.vulns.map((v) => {
        const url = safeUrl(v.url);
        const id = esc(v.aliases[0] ?? v.id);
        return `<tr><td>${url ? `<a href="${esc(url)}">${id}</a>` : id}<div class="muted">${esc(v.summary)}</div></td><td>${esc(SEV_NAME[v.severity])}</td><td>${v.score ?? ""}</td><td>${esc(v.fixedIn.join(", ") || "none yet")}</td></tr>`;
      }).join("")}</tbody></table>` : "";
  const via = d.via?.length ? `<p><b>How it got here:</b> ${[...d.via, d.package ?? ""].map(esc).join(" → ")}</p>` : "";
  const used = d.usedIn !== undefined ? `<p><b>Used by your code:</b> ${d.usedIn.length ? esc(d.usedIn.join(", ")) : "no import found"}</p>` : "";
  const secret = d.secretKind ? `<p><b>Type:</b> ${esc(d.secretKind)} (starts with <code>${esc(d.masked)}</code>). The value is not stored or shown.</p>` : "";
  const std = [...f.cwe.map(esc), ...(f.owasp ? [`OWASP ${esc(f.owasp)}`] : [])].join(" · ");
  return `<article class="finding" style="--c:${SEV_COLOR[f.severity]}">
  <h4><span class="sev">${esc(SEV_NAME[f.severity])}</span> ${esc(f.title)}</h4>
  <p class="loc"><a href="${esc(blob(repo, sha, f.path, f.line))}">${esc(f.path)}${f.line ? `:${f.line}` : ""}</a> <span class="muted">· ${esc(f.ruleId)} · ${esc(f.confidence)} confidence${d.dev ? " · dev tool only" : ""}</span></p>
  <p><b>Why it matters.</b> ${esc(f.reason)}</p>
  <p><b>How to fix it.</b> ${esc(f.fix)}</p>${vulns}${via}${used}${secret}
  ${std ? `<p class="muted">${std}</p>` : ""}
</article>`;
}

/** A self-contained, print-ready HTML report. Every dynamic value is escaped: package names, paths and advisories are untrusted text. */
export function renderReportHtml({ set, graph, generatedAt = Date.now() }: ReportInput): string {
  const p = posture(set.findings, true);
  const sorted = [...set.findings].sort((a, b) => priority(b) - priority(a));
  const top = sorted.slice(0, 5);
  const paths = graph ? attackPaths(graph, set.findings, mapFindings(graph, set.findings), set.exposure).slice(0, 3) : [];
  const label = (id: string) => graph?.nodes.find((n) => n.id === id)?.label ?? id;
  const bySev = SEVERITIES.map((s) => [s, sorted.filter((f) => f.severity === s)] as const).filter(([, l]) => l.length);

  const css = `body{font:15px/1.55 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1f2328;max-width:860px;margin:2rem auto;padding:0 1.25rem}
h1{font-size:1.7rem;margin:.2rem 0}h2{font-size:1.2rem;margin:2rem 0 .6rem;border-bottom:1px solid #d1d9e0;padding-bottom:.3rem}h3{margin:1.4rem 0 .5rem}h4{margin:0 0 .3rem;font-size:1rem}
.muted{color:#57606a;font-size:.88em}code{background:#f6f8fa;padding:.1em .35em;border-radius:4px}a{color:#0969da}
.grade{display:inline-grid;place-items:center;width:64px;height:64px;border-radius:50%;border:5px solid #d1242f;font:700 28px sans-serif;margin-right:1rem}
.summary{display:flex;align-items:center;margin:1rem 0}.counts span{display:inline-block;margin:.15rem .6rem .15rem 0}
.finding{border:1px solid #d1d9e0;border-left:5px solid var(--c);border-radius:6px;padding:.7rem 1rem;margin:.8rem 0;break-inside:avoid}
.sev{display:inline-block;background:var(--c);color:#fff;border-radius:10px;padding:0 .55rem;font-size:.78em;margin-right:.35rem}.loc{margin:.1rem 0 .5rem}
table{border-collapse:collapse;width:100%;font-size:.9em}th,td{border:1px solid #d1d9e0;padding:.3rem .5rem;text-align:left;vertical-align:top}th{background:#f6f8fa}
.path{border:1px solid #d1d9e0;border-radius:6px;padding:.5rem .8rem;margin:.5rem 0}.note{background:#fff8c5;border:1px solid #d4a72c;border-radius:6px;padding:.6rem .9rem}
@media print{body{margin:0;max-width:none}a{color:inherit;text-decoration:none}.noprint{display:none}}`;

  const head = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Security report: ${esc(set.repo)}</title><style>${css}</style></head><body>`;

  const summary = `<h1>Security report</h1>
<p class="muted"><b>${esc(set.repo)}</b> · commit <code>${esc(set.sha.slice(0, 7))}</code> · scanned ${esc(new Date(set.scannedAt).toISOString().slice(0, 16).replace("T", " "))} UTC · report generated ${esc(new Date(generatedAt).toISOString().slice(0, 16).replace("T", " "))} UTC</p>
<p class="noprint muted">To save as a PDF, use your browser's Print command and choose "Save as PDF".</p>
<h2>Summary</h2>
<div class="summary"><div class="grade" style="border-color:${p.grade <= "B" ? "#1a7f37" : p.grade === "C" ? "#9a6700" : "#d1242f"}">${p.grade}</div><div><b>${esc(p.headline)}</b><div class="muted">Safety score ${p.score}/100 · ${set.findings.length} finding${set.findings.length === 1 ? "" : "s"}</div></div></div>
<p class="counts">${SEVERITIES.filter((s) => p.counts[s]).map((s) => `<span><b style="color:${SEV_COLOR[s]}">${p.counts[s]}</b> ${SEV_NAME[s].toLowerCase()}</span>`).join("") || "No findings."}</p>
${set.delta ? `<p><b>${esc(describeDelta(set.delta))}</b></p>` : ""}
<p class="muted">${CATEGORIES.filter((c) => p.byCategory[c]).map((c) => `${esc(CATEGORY_NAME[c])}: ${p.byCategory[c]}`).join(" · ")}</p>
${top.length ? `<h3>Fix these first</h3><ol>${top.map((f) => `<li><b>${esc(f.title)}</b> <span class="muted">(${esc(SEV_NAME[f.severity])}, ${esc(f.path)}${f.line ? `:${f.line}` : ""})</span><br>${esc(f.fix)}</li>`).join("")}</ol>` : ""}
${paths.length ? `<h3>How an attacker could get in</h3><p class="muted">Routes from where an outsider can knock to what they could reach, using the application map's connections.</p>${paths.map((x) => `<div class="path"><b>${x.nodes.map((id) => esc(label(id))).join(" → ")}</b><ul>${x.facts.map((f) => `<li>${esc(f)}</li>`).join("")}</ul></div>`).join("")}` : ""}`;

  const detail = bySev.length
    ? `<h2>Findings in detail</h2>${bySev.map(([s, list]) => `<h3>${esc(SEV_NAME[s])} (${list.length})</h3>${list.map((f) => findingHtml(f, set.repo, set.sha)).join("")}`).join("")}`
    : `<h2>Findings in detail</h2><p>Nothing was found. That means these checks passed, not that the software is proven secure.</p>`;

  const warnings = set.warnings.length ? `<div class="note"><b>Not everything could be checked:</b><ul>${set.warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul></div>` : "";

  const method = `<h2>What was checked, and what was not</h2>
<ul>
<li><b>Dependencies:</b> ${set.stats.packages} package${set.stats.packages === 1 ? "" : "s"} from ${set.stats.lockfiles} lockfile${set.stats.lockfiles === 1 ? "" : "s"} were looked up in the OSV.dev vulnerability database, with whether your code imports each one.</li>
<li><b>Secrets:</b> ${set.stats.files} files were searched for keys, tokens and credentials. Values are never stored or shown.</li>
<li><b>CI pipelines and containers:</b> GitHub Actions workflows, Dockerfiles and compose files were checked for risky settings.</li>
<li><b>Source code:</b> JavaScript, TypeScript and Python were parsed and checked for injection, unsafe execution, weak cryptography and disabled security controls.</li></ul>
<p class="muted"><b>Limits.</b> These are automated, best-effort checks. They can report things that are not real problems, and they can miss real ones. They do not test a running system, do not look through git history for secrets that were removed, and cannot prove software is secure. Code excerpts are not stored; open a finding's link to see the lines. Findings marked "low confidence" are the most likely to be false alarms.</p>`;

  return `${head}${summary}${warnings}${detail}${method}<p class="muted">Generated by Mission Control for Code.</p></body></html>`;
}

// ---------- SARIF 2.1.0 ----------

const LEVEL: Record<Severity, "error" | "warning" | "note"> = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
/** GitHub's `security-severity` scale (0 to 10): it sorts alerts by this. */
const SECURITY_SEVERITY: Record<Severity, string> = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "0.5" };

/** SARIF is the standard interchange format: GitHub code scanning, Azure DevOps and most tools read it. */
export function toSarif(set: FindingSet) {
  const rules = new Map<string, Finding>();
  for (const f of set.findings) if (!rules.has(f.ruleId)) rules.set(f.ruleId, f);
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "Mission Control for Code", informationUri: "https://github.com/nexstaq/sw-digital-twin",
          rules: [...rules.values()].map((f) => ({
            id: f.ruleId, name: f.ruleId.replace(/[^A-Za-z0-9]+/g, ""),
            shortDescription: { text: f.title.slice(0, 120) },
            help: { text: f.fix, markdown: f.fix },
            defaultConfiguration: { level: LEVEL[f.severity] },
            properties: { tags: ["security", ...f.cwe.map((c) => `external/cwe/${c.toLowerCase()}`)], "security-severity": SECURITY_SEVERITY[f.severity], precision: f.confidence === "high" ? "high" : f.confidence === "medium" ? "medium" : "low" },
          })),
        },
      },
      results: set.findings.map((f) => ({
        ruleId: f.ruleId, level: LEVEL[f.severity],
        message: { text: `${f.title}. ${f.reason}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.path, uriBaseId: "%SRCROOT%" }, ...(f.line ? { region: { startLine: f.line, ...(f.endLine && f.endLine >= f.line ? { endLine: f.endLine } : {}) } } : {}) } }],
        partialFingerprints: { "missionControl/v1": f.id },
        properties: { "security-severity": SECURITY_SEVERITY[f.severity], category: f.category, confidence: f.confidence },
      })),
      versionControlProvenance: [{ repositoryUri: `https://github.com/${set.repo}`, revisionId: set.sha }],
    }],
  };
}
