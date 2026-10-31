import { describe, expect, it } from "vitest";
import { cleanLocation, mergeImport, parseSarif, toolSlug } from "./sarif-import";
import { toSarif } from "./report";
import type { Finding, FindingSet } from "./types";

const AWS = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE";
const doc = (results: unknown[], rules: unknown[] = [], tool = "Semgrep") => ({ version: "2.1.0", runs: [{ tool: { driver: { name: tool, rules } }, results }] });
const res = (o: Record<string, unknown> = {}) => ({ ruleId: "sql-injection", level: "error", message: { text: "Tainted SQL" }, locations: [{ physicalLocation: { artifactLocation: { uri: "src/db.ts" }, region: { startLine: 12, endLine: 14 } } }], ...o });

describe("parseSarif", () => {
  it("turns results into findings with rule, message, location and a stable id", () => {
    const p = parseSarif(doc([res()], [{ id: "sql-injection", shortDescription: { text: "SQL injection" }, help: { text: "Use bound parameters." }, properties: { tags: ["security", "external/cwe/cwe-89"], precision: "high" } }]));
    expect(p.tool).toBe("Semgrep");
    expect(p.findings).toHaveLength(1);
    expect(p.findings[0]).toMatchObject({
      ruleId: "semgrep/sql-injection", category: "code", severity: "high", title: "SQL injection", reason: "Tainted SQL", fix: "Use bound parameters.",
      path: "src/db.ts", line: 12, endLine: 14, cwe: ["CWE-89"], confidence: "high", detail: { source: "sarif:semgrep", sourceName: "Semgrep" },
    });
    const again = parseSarif(doc([res({ locations: [{ physicalLocation: { artifactLocation: { uri: "src/db.ts" }, region: { startLine: 99 } } }], partialFingerprints: {} })]));
    expect(again.findings[0].id).toBe(p.findings[0].id); // the line moved, the finding did not
  });

  it("severity: security-severity score wins, then level", () => {
    const sev = (r: unknown, rules: unknown[] = []) => parseSarif(doc([r], rules)).findings[0].severity;
    expect(sev(res({ properties: { "security-severity": "9.8" } }))).toBe("critical");
    expect(sev(res({ properties: { "security-severity": "7.5" } }))).toBe("high");
    expect(sev(res({ properties: { "security-severity": "5.0" }, level: "error" }))).toBe("medium");
    expect(sev(res({ level: "warning" }))).toBe("medium");
    expect(sev(res({ level: "note" }))).toBe("low");
    expect(sev(res({ level: undefined }), [{ id: "sql-injection", defaultConfiguration: { level: "error" } }])).toBe("high");
    expect(sev(res({ level: undefined }), [{ id: "sql-injection", properties: { "security-severity": "3.1" } }])).toBe("low");
  });

  it("URLs become 'live testing' findings, with the query string and fragment removed (they can carry tokens)", () => {
    const p = parseSarif(doc([res({ locations: [{ physicalLocation: { artifactLocation: { uri: "https://staging.example.com/api/users?token=SECRETVALUE&x=1#frag" } } }] })], [], "Nuclei"));
    expect(p.findings[0]).toMatchObject({ category: "runtime", path: "https://staging.example.com/api/users" });
    expect(JSON.stringify(p.findings)).not.toContain("SECRETVALUE");
  });

  it("guesses the category from the tool", () => {
    const cat = (tool: string, ruleId = "r") => parseSarif(doc([res({ ruleId })], [], tool)).findings[0].category;
    expect(cat("Trivy")).toBe("dependency");
    expect(cat("gitleaks")).toBe("secret");
    expect(cat("Hadolint")).toBe("container");
    expect(cat("actionlint")).toBe("pipeline");
    expect(cat("CodeQL")).toBe("code");
  });

  it("redacts anything secret-shaped from messages and titles, and ignores code snippets entirely", () => {
    const p = parseSarif(doc([res({ message: { text: `Found key ${AWS} in config` }, locations: [{ physicalLocation: { artifactLocation: { uri: "a.ts" }, region: { startLine: 1, snippet: { text: `const k = "${AWS}"` } }, contextRegion: { snippet: { text: AWS } } } }] })]));
    expect(JSON.stringify(p.findings)).not.toContain(AWS);
    expect(p.findings[0].reason).toContain("redacted");
  });

  it("bounds every string it keeps", () => {
    const p = parseSarif(doc([res({ message: { text: "x".repeat(5000) } })], [{ id: "sql-injection", shortDescription: { text: "t".repeat(900) }, help: { text: "h".repeat(9000) } }]));
    expect(p.findings[0].reason.length).toBeLessThanOrEqual(600);
    expect(p.findings[0].title.length).toBeLessThanOrEqual(120);
    expect(p.findings[0].fix.length).toBeLessThanOrEqual(500);
  });

  it("refuses paths that are absolute or escape the repository, and skips results with no location", () => {
    for (const bad of ["/etc/passwd", "../../secret", "a/../../b", "C:/Windows/x", ""]) expect(cleanLocation(bad), bad).toBeNull();
    expect(cleanLocation("file:///src/a.ts")).toBeNull(); // a bare absolute path
    expect(cleanLocation("file://src/a.ts")?.path).toBe("src/a.ts");
    expect(cleanLocation("%SRCROOT%/src/a.ts")?.path).toBe("src/a.ts");
    expect(cleanLocation("./src/a%20b.ts")?.path).toBe("src/a b.ts");
    const p = parseSarif(doc([res({ locations: [] }), res({ locations: [{ physicalLocation: { artifactLocation: { uri: "/etc/passwd" } } }] }), res()]));
    expect(p.findings).toHaveLength(1);
    expect(p.skipped).toBe(2);
    expect(p.warnings.join(" ")).toMatch(/2 results were skipped/);
  });

  it("only https help links are kept", () => {
    const rules = (helpUri: string) => [{ id: "sql-injection", helpUri }];
    expect(parseSarif(doc([res()], rules("https://docs.example.com/r"))).findings[0].detail.url).toBe("https://docs.example.com/r");
    expect(parseSarif(doc([res()], rules("javascript:alert(1)"))).findings[0].detail.url).toBeUndefined();
  });

  it("never throws on garbage, and says what is wrong", () => {
    for (const junk of [null, undefined, 42, "x", [], {}, { runs: "nope" }, { runs: [null, 5, { tool: 3, results: "x" }] }, { runs: [{ results: [null, 7, {}] }] }]) {
      expect(() => parseSarif(junk), JSON.stringify(junk)).not.toThrow();
    }
    expect(parseSarif({}).warnings[0]).toContain("does not look like SARIF");
    expect(parseSarif({ version: "1.0.0", runs: [{ tool: { driver: { name: "x" } }, results: [res()] }] }).warnings[0]).toContain("not 2.1");
  });

  it("caps how many results it will take", () => {
    const p = parseSarif(doc(Array.from({ length: 2100 }, (_, i) => res({ message: { text: `m${i}` }, locations: [{ physicalLocation: { artifactLocation: { uri: `f${i}.ts` } } }] }))));
    expect(p.findings).toHaveLength(2000);
    expect(p.skipped).toBe(100);
  });

  it("round-trips our own SARIF export (so another instance's report can be imported)", () => {
    const f: Finding = { id: "i", ruleId: "R/x", category: "code", severity: "high", title: "T", path: "a.ts", line: 3, reason: "because", fix: "do this", cwe: ["CWE-89"], confidence: "high", detail: {} };
    const set: FindingSet = { repo: "a/b", sha: "a".repeat(40), scannedAt: 1, findings: [f], stats: { files: 1, packages: 0, lockfiles: 0 }, warnings: [] };
    const p = parseSarif(toSarif(set));
    expect(p.findings[0]).toMatchObject({ severity: "high", path: "a.ts", line: 3, cwe: ["CWE-89"] });
  });
});

describe("mergeImport / toolSlug", () => {
  const F = (id: string, source?: string): Finding => ({ id, ruleId: "R", category: "code", severity: "low", title: id, path: "a.ts", reason: "r", fix: "f", cwe: [], confidence: "high", detail: source ? { source } : {} });
  it("a new report from a tool replaces that tool's earlier one and leaves everything else alone", () => {
    const existing = [F("own"), F("old-semgrep", "sarif:semgrep"), F("trivy", "sarif:trivy"), F("dependabot", "dependabot")];
    const parsed = parseSarif(doc([res()]));
    const merged = mergeImport(existing, parsed);
    expect(merged.map((f) => f.id)).toContain("own");
    expect(merged.map((f) => f.id)).toContain("trivy");
    expect(merged.map((f) => f.id)).toContain("dependabot");
    expect(merged.map((f) => f.id)).not.toContain("old-semgrep");
    expect(merged.filter((f) => f.detail.source === "sarif:semgrep")).toHaveLength(1);
  });
  it("duplicates inside one report collapse", () => {
    const p = parseSarif(doc([res(), res()]));
    expect(mergeImport([], p)).toHaveLength(1);
  });
  it("names are made safe for ids", () => {
    expect(toolSlug("Semgrep OSS 1.2")).toBe("semgrep-oss-1-2");
    expect(toolSlug("../../x")).toBe("x");
    expect(toolSlug("")).toBe("tool");
  });
});
