import { describe, expect, it } from "vitest";
import { cweSummary, OWASP, owaspOf, owaspSummary } from "./owasp";
import type { Finding, Severity } from "./types";

const F = (id: string, severity: Severity, extra: Partial<Finding> = {}): Finding => ({ id, ruleId: "R", category: "code", severity, title: id, path: `${id}.ts`, reason: "r", fix: "f", cwe: [], confidence: "high", detail: {}, ...extra });

describe("owaspOf", () => {
  it("trusts the category an analyzer assigned", () => {
    expect(owaspOf({ owasp: "A03:2021 Injection", cwe: ["CWE-1"] })).toBe("A03");
    expect(owaspOf({ owasp: "A10:2021 Server-Side Request Forgery", cwe: [] })).toBe("A10");
  });
  it("derives it from the CWE when the tool did not say, using OWASP's own lists", () => {
    for (const [cwe, id] of [["CWE-89", "A03"], ["CWE-79", "A03"], ["CWE-22", "A01"], ["CWE-327", "A02"], ["CWE-798", "A07"], ["CWE-295", "A07"], ["CWE-306", "A07"], ["CWE-502", "A08"], ["CWE-918", "A10"], ["CWE-942", "A05"], ["CWE-1104", "A06"], ["CWE-532", "A09"], ["CWE-611", "A05"]] as const) {
      expect(owaspOf({ cwe: [cwe] }), cwe).toBe(id);
    }
  });
  it("accepts the spellings tools use for a CWE, and takes the first one it knows", () => {
    expect(owaspOf({ cwe: ["cwe-089"] })).toBe("A03");
    expect(owaspOf({ cwe: ["CWE-99999", "CWE-79"] })).toBe("A03");
  });
  it("returns null rather than guessing", () => {
    expect(owaspOf({ cwe: [] })).toBeNull();
    expect(owaspOf({ cwe: ["CWE-99999"] })).toBeNull();
    expect(owaspOf({ owasp: "not a category", cwe: [] })).toBeNull();
  });
});

describe("owaspSummary", () => {
  it("always lists all ten categories, so a gap shows as a gap", () => {
    const { rows } = owaspSummary([]);
    expect(rows.map((r) => r.id)).toEqual(["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]);
    expect(rows.every((r) => r.total === 0 && r.worst === null)).toBe(true);
  });
  it("categories no scan can judge are flagged NOT ASSESSED, never implied clean", () => {
    const rows = owaspSummary([]).rows;
    expect(rows.filter((r) => !r.assessed).map((r) => r.id)).toEqual(["A04", "A09"]);
    expect(rows.find((r) => r.id === "A04")!.how).toMatch(/design/i);
  });
  it("counts findings per category with the worst severity, and keeps their ids", () => {
    const { rows, unmapped } = owaspSummary([
      F("a", "high", { owasp: "A03:2021 Injection" }), F("b", "critical", { cwe: ["CWE-89"] }), F("c", "low", { cwe: ["CWE-327"] }), F("d", "medium"),
    ]);
    const a03 = rows.find((r) => r.id === "A03")!;
    expect(a03).toMatchObject({ total: 2, worst: "critical", findings: ["a", "b"] });
    expect(a03.counts).toMatchObject({ critical: 1, high: 1 });
    expect(rows.find((r) => r.id === "A02")).toMatchObject({ total: 1, worst: "low" });
    expect(unmapped).toBe(1); // "d" has neither: it is counted, not hidden
  });
  it("every category an analyzer in this product can emit is mapped, so nothing built-in lands in 'unmapped'", () => {
    const emitted = ["A01:2021 Broken Access Control", "A02:2021 Cryptographic Failures", "A03:2021 Injection", "A05:2021 Security Misconfiguration", "A06:2021 Vulnerable and Outdated Components", "A07:2021 Identification and Authentication Failures", "A08:2021 Software and Data Integrity Failures", "A10:2021 Server-Side Request Forgery"];
    for (const o of emitted) expect(owaspOf({ owasp: o, cwe: [] }), o).not.toBeNull();
  });
});

describe("cweSummary", () => {
  it("ranks weaknesses worst first, then by how often they occur", () => {
    const rows = cweSummary([F("a", "low", { cwe: ["CWE-89"] }), F("b", "high", { cwe: ["CWE-89", "CWE-79"] }), F("c", "high", { cwe: ["CWE-79"] }), F("d", "critical", { cwe: ["CWE-798"] })]);
    expect(rows.map((r) => r.cwe)).toEqual(["CWE-798", "CWE-79", "CWE-89"]);
    expect(rows[1]).toMatchObject({ count: 2, worst: "high", owasp: "A03" });
  });
  it("normalises spellings, ignores junk, and respects the limit", () => {
    const rows = cweSummary([F("a", "low", { cwe: ["cwe-089", "CWE-89", "nonsense"] })]);
    expect(rows).toEqual([{ cwe: "CWE-89", count: 2, worst: "low", owasp: "A03" }]);
    expect(cweSummary(Array.from({ length: 20 }, (_, i) => F(`f${i}`, "low", { cwe: [`CWE-${1000 + i}`] })), 5)).toHaveLength(5);
  });
});

describe("the table", () => {
  it("has ten categories with a name and an honest description of how they are assessed", () => {
    expect(OWASP).toHaveLength(10);
    for (const c of OWASP) { expect(c.name.length).toBeGreaterThan(5); expect(c.how.length).toBeGreaterThan(20); }
  });
});
