import { describe, expect, it } from "vitest";
import { renderReportHtml, toSarif } from "./report";
import type { Finding, FindingSet, Severity } from "./types";
import type { TwinGraph, TwinNode } from "@/lib/graph/types";

const AWS = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE";
const F = (id: string, severity: Severity, extra: Partial<Finding> = {}): Finding => ({ id, ruleId: `R/${id}`, category: "code", severity, title: `Title ${id}`, path: `src/${id}.ts`, line: 7, reason: `Because ${id} is risky here, an attacker could do harm.`, fix: `Do the safe thing for ${id} instead.`, cwe: ["CWE-89"], owasp: "A03:2021 Injection", confidence: "high", detail: {}, ...extra });
const SET = (findings: Finding[], extra: Partial<FindingSet> = {}): FindingSet => ({ repo: "acme/shop", sha: "a".repeat(40), scannedAt: Date.UTC(2026, 9, 30, 12, 0), findings, stats: { files: 120, packages: 340, lockfiles: 1 }, warnings: [], ...extra });
const NOW = Date.UTC(2026, 9, 30, 13, 0);

describe("renderReportHtml", () => {
  const html = renderReportHtml({ set: SET([F("a", "critical"), F("b", "high"), F("c", "low")]), generatedAt: NOW });

  it("is a complete document with the summary an executive needs first", () => {
    expect(html).toMatch(/^<!doctype html>/);
    expect(html).toContain("<title>Security report: acme/shop</title>");
    expect(html).toContain("commit <code>aaaaaaa</code>");
    expect(html).toContain("2026-10-30 12:00 UTC");
    expect(html).toContain("1 critical issue to fix first, then 1 high");
    expect(html).toMatch(/Safety score \d+\/100 · 3 findings/);
    expect(html.indexOf("<h2>Summary</h2>")).toBeLessThan(html.indexOf("Findings in detail"));
    expect(html).toContain("Fix these first");
  });
  it("lists findings worst first, with location link, reason, fix and standards", () => {
    expect(html.indexOf("Critical (1)")).toBeLessThan(html.indexOf("High (1)"));
    expect(html.indexOf("High (1)")).toBeLessThan(html.indexOf("Low (1)"));
    expect(html).toContain('href="https://github.com/acme/shop/blob/' + "a".repeat(40) + '/src/a.ts#L7"');
    expect(html).toContain("<b>Why it matters.</b> Because a is risky here");
    expect(html).toContain("<b>How to fix it.</b> Do the safe thing for a instead.");
    expect(html).toContain("CWE-89");
    expect(html).toContain("OWASP A03:2021 Injection");
  });
  it("is print-ready and honest about its limits", () => {
    expect(html).toContain("@media print");
    expect(html).toContain("Save as PDF");
    expect(html).toContain("cannot prove software is secure");
    expect(html).toContain("low confidence");
    expect(html).toContain("340 packages from 1 lockfile");
  });
  it("says what changed since the previous scan, when there is a previous scan", () => {
    const out = renderReportHtml({ set: SET([F("a", "high")], { delta: { newIds: ["a"], fixed: 2, previousSha: "b".repeat(40), previousScannedAt: 1 } }), generatedAt: NOW });
    expect(out).toContain("Since the previous scan: 1 new, 2 fixed.");
    expect(html).not.toContain("Since the previous scan");
  });
  it("names the source of each finding, and lists every source including the ones that were unavailable", () => {
    const out = renderReportHtml({ set: SET([
      F("d", "high", { category: "dependency", detail: { source: "dependabot", alsoReportedBy: [], url: "https://github.com/acme/shop/security/dependabot/1" } }),
      F("o", "high", { detail: { alsoReportedBy: ["dependabot"] } }),
    ], { sources: { dependabot: { status: "ok", count: 3, via: "github" }, "code-scanning": { status: "unavailable", count: 0, message: "Code scanning is not switched on." }, "sarif:nuclei": { status: "ok", label: "Nuclei", count: 2, via: "ci" } } }), generatedAt: NOW });
    expect(out).toContain("Reported by GitHub Dependabot.");
    expect(out).toContain("Also confirmed by GitHub Dependabot.");
    expect(out).toContain('<a href="https://github.com/acme/shop/security/dependabot/1">Open it there</a>');
    expect(out).toContain("<b>GitHub Dependabot:</b> 3 findings included.");
    expect(out).toContain("<b>Nuclei (imported report):</b> 2 findings included (sent by a CI workflow).");
    expect(out).toContain("<b>GitHub code scanning:</b> <b>not available.</b>"); // the source is keyed \"code-scanning\", its findings \"codeql\": both read the same
    expect(out).toContain("<b>not available.</b> Code scanning is not switched on.");
  });
  it("a live-test finding points at a URL, never at a made-up GitHub file link", () => {
    const out = renderReportHtml({ set: SET([F("u", "medium", { category: "runtime", path: "https://staging.example.com/admin", line: undefined })]), generatedAt: NOW });
    expect(out).toContain("<code>https://staging.example.com/admin</code>");
    expect(out).not.toContain("github.com/acme/shop/blob/" + "a".repeat(40) + "/https");
    expect(out).toContain("Live testing: 1");
  });
  it("maps findings to the OWASP Top 10 and says which categories it cannot assess", () => {
    const out = renderReportHtml({ set: SET([F("a", "high", { owasp: "A03:2021 Injection" }), F("b", "low", { cwe: ["CWE-327"], owasp: undefined })]), generatedAt: NOW });
    expect(out).toContain("<h2>Standards mapping</h2>");
    expect(out).toMatch(/<b>A03<\/b> Injection<\/td><td>1<\/td>/);
    expect(out).toMatch(/<b>A02<\/b> Cryptographic Failures<\/td><td>1<\/td>/); // derived from CWE-327
    expect(out).toMatch(/<b>A04<\/b> Insecure Design<\/td><td>n\/a<\/td><td>not assessed<\/td>/);
    expect(out).toMatch(/<b>A09<\/b> Security Logging[^<]*<\/td><td>n\/a<\/td><td>not assessed<\/td>/);
    expect(out).toMatch(/<b>A01<\/b> Broken Access Control<\/td><td>0<\/td><td>none found<\/td>/);
    expect(out).toContain("CWE-327 (1)");
  });
  it("a clean scan says what that does and does not mean", () => {
    const clean = renderReportHtml({ set: SET([]), generatedAt: NOW });
    expect(clean).toContain("Nothing was found. That means these checks passed, not that the software is proven secure.");
    expect(clean).toContain(">A</div>");
  });
  it("warnings about what could not be checked are shown prominently, never hidden", () => {
    const w = renderReportHtml({ set: SET([], { warnings: ["Could not reach the vulnerability database, so dependencies were NOT checked."] }), generatedAt: NOW });
    expect(w).toContain("Not everything could be checked");
    expect(w).toContain("NOT checked");
  });

  it("escapes every untrusted value: package names, paths, titles and advisory text cannot inject markup", () => {
    const evil = '<script>alert(1)</script><img src=x onerror=alert(2)>';
    const set = SET([F("x", "high", {
      title: evil, path: `src/${evil}.ts`, reason: evil, fix: evil, ruleId: evil, cwe: [evil], owasp: evil,
      detail: { package: evil, version: evil, via: [evil], usedIn: [evil], vulns: [{ id: evil, aliases: [evil], summary: evil, severity: "high", score: 7, fixedIn: [evil], url: "https://osv.dev/x" }] },
    })], { repo: "acme/shop", warnings: [evil] });
    const out = renderReportHtml({ set, generatedAt: NOW });
    expect(out).not.toContain("<script>");
    expect(out).not.toMatch(/<img\s/i);
    expect(out).not.toMatch(/<[^>]*\bonerror\s*=/i); // the text may appear escaped, but never inside a real tag
    expect(out).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });
  it("only https links are ever written into an href", () => {
    const out = renderReportHtml({ set: SET([F("x", "high", { detail: { package: "p", version: "1", vulns: [
      { id: "A", aliases: [], summary: "s", severity: "high", fixedIn: [], url: "javascript:alert(1)" },
      { id: "B", aliases: [], summary: "s", severity: "high", fixedIn: [], url: "https://osv.dev/B" },
      { id: "C", aliases: [], summary: "s", severity: "high", fixedIn: [], url: 'https://x.dev/"><script>' },
    ] } })]), generatedAt: NOW });
    expect(out).not.toMatch(/href="javascript:/i);
    expect(out).toContain('href="https://osv.dev/B"');
    expect(out).not.toContain('"><script>');
  });
  it("never contains a secret value", () => {
    const out = renderReportHtml({ set: SET([F("s", "critical", { category: "secret", detail: { secretKind: "AWS access key ID", masked: "AKIA…(20 chars)" } })]), generatedAt: NOW });
    expect(out).toContain("AKIA…(20 chars)");
    expect(out).not.toContain(AWS);
  });
  it("includes attack paths when a map is available", () => {
    const n = (id: string, kind: TwinNode["kind"], level: 0 | 1, parentId: string | undefined, paths: string[]): TwinNode => ({ id, level, parentId, kind, label: id === "web" ? "Web app" : id, summary: "", state: "nominal", score: 1, spark: [], reasons: [], evidence: paths.map((path) => ({ path })), criticality: 2 });
    const graph: TwinGraph = { repo: "acme/shop", deploys: [], nodes: [n("web", "service", 0, undefined, ["package.json"]), n("ep", "endpoint", 1, "web", ["src/a.ts"]), n("db", "datastore", 0, undefined, [])], edges: [{ id: "e", from: "web", to: "db", kind: "reads", throughput: 0.5, errorRate: 0 }] };
    const out = renderReportHtml({ set: SET([F("a", "high")]), graph, generatedAt: NOW });
    expect(out).toContain("How an attacker could get in");
    expect(out).toContain("Web app → db");
    expect(renderReportHtml({ set: SET([F("a", "high")]), generatedAt: NOW })).not.toContain("How an attacker could get in");
  });
});

describe("toSarif", () => {
  const set = SET([F("a", "critical", { endLine: 9, category: "dependency" }), F("b", "high"), F("c", "medium"), F("d", "low"), F("a2", "critical", { ruleId: "R/a" })]);
  const s = toSarif(set);
  const run = s.runs[0];

  it("is SARIF 2.1.0 with one result per finding and one rule per distinct rule id", () => {
    expect(s.version).toBe("2.1.0");
    expect(run.results).toHaveLength(5);
    const ids = run.tool.driver.rules.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toEqual(expect.arrayContaining(["R/a", "R/b", "R/c", "R/d"]));
    expect(ids).toHaveLength(4);
    for (const r of run.results) expect(ids).toContain(r.ruleId);
  });
  it("maps severity to level and to GitHub's security-severity score", () => {
    const by = Object.fromEntries(run.results.map((r) => [r.ruleId + r.locations[0].physicalLocation.artifactLocation.uri, r]));
    expect(by["R/asrc/a.ts"]).toMatchObject({ level: "error", properties: { "security-severity": "9.5" } });
    expect(by["R/bsrc/b.ts"].level).toBe("error");
    expect(by["R/csrc/c.ts"].level).toBe("warning");
    expect(by["R/dsrc/d.ts"].level).toBe("note");
  });
  it("pins location with path, start and end line, and carries a stable fingerprint", () => {
    const r = run.results.find((x) => x.ruleId === "R/a" && x.locations[0].physicalLocation.artifactLocation.uri === "src/a.ts")!;
    expect(r.locations[0].physicalLocation).toMatchObject({ artifactLocation: { uri: "src/a.ts" }, region: { startLine: 7, endLine: 9 } });
    expect(r.partialFingerprints["missionControl/v1"]).toBe("a");
  });
  it("carries the CWE as a tag, the fix as help, and the commit it describes", () => {
    const rule = run.tool.driver.rules.find((r) => r.id === "R/b")!;
    expect(rule.properties.tags).toContain("external/cwe/cwe-89");
    expect(rule.help.text).toContain("Do the safe thing");
    expect(run.versionControlProvenance[0]).toEqual({ repositoryUri: "https://github.com/acme/shop", revisionId: "a".repeat(40) });
  });
  it("a finding with no line has a location without a region, and no secret values appear", () => {
    const out = toSarif(SET([F("n", "low", { line: undefined, detail: { secretKind: "AWS", masked: "AKIA…(20 chars)" } })]));
    expect(out.runs[0].results[0].locations[0].physicalLocation).not.toHaveProperty("region");
    expect(JSON.stringify(toSarif(SET([F("s", "critical", { category: "secret", detail: { masked: "AKIA…" } })])))).not.toContain(AWS);
  });
  it("an empty scan is valid SARIF with no results", () => {
    const e = toSarif(SET([]));
    expect(e.runs[0].results).toEqual([]);
    expect(e.runs[0].tool.driver.rules).toEqual([]);
  });
});
