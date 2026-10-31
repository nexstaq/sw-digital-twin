import { describe, expect, it } from "vitest";
import { combine } from "./external";
import type { Alerts } from "./github-alerts";
import type { Finding, FindingSet, Severity } from "./types";

const F = (id: string, severity: Severity = "high", source?: string): Finding => ({ id, ruleId: "R", category: "code", severity, title: id, path: `${id}.ts`, reason: "r", fix: "f", cwe: [], confidence: "high", detail: source ? { source } : {} });
const SET = (findings: Finding[], extra: Partial<FindingSet> = {}): FindingSet => ({ repo: "a/b", sha: "a".repeat(40), scannedAt: 1, findings, stats: { files: 1, packages: 0, lockfiles: 0 }, warnings: [], ...extra });
const ALERTS = (findings: Finding[], confirmed: [string, string[]][] = [], sources: Alerts["sources"] = { dependabot: { status: "ok", count: findings.length, via: "github" } }): Alerts => ({ findings, confirmed: new Map(confirmed), sources });

describe("combine", () => {
  it("a re-scan keeps what CI or an upload imported, and replaces only our own findings", () => {
    const prev = SET([F("old-own"), F("nuclei-1", "high", "sarif:nuclei")], { sources: { "sarif:nuclei": { status: "ok", count: 1, via: "ci" } } });
    const out = combine(SET([F("new-own")]), prev, null);
    expect(out.findings.map((f) => f.id).sort()).toEqual(["new-own", "nuclei-1"]);
    expect(out.sources!["sarif:nuclei"]).toMatchObject({ via: "ci" });
  });
  it("GitHub's alerts are taken fresh each time, never carried over from the last scan", () => {
    const prev = SET([F("stale-alert", "high", "dependabot")], { sources: { dependabot: { status: "ok", count: 1, via: "github" } } });
    const out = combine(SET([]), prev, ALERTS([F("fresh-alert", "high", "dependabot")]));
    expect(out.findings.map((f) => f.id)).toEqual(["fresh-alert"]);
    expect(out.sources!.dependabot.count).toBe(1);
  });
  it("marks our own finding as confirmed by Dependabot, without duplicating it", () => {
    const out = combine(SET([F("mine")]), null, ALERTS([], [["mine", ["dependabot"]]]));
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0].detail.alsoReportedBy).toEqual(["dependabot"]);
  });
  it("an alert unavailable still shows up as a source with its explanation", () => {
    const out = combine(SET([]), null, ALERTS([], [], { "code-scanning": { status: "unavailable", count: 0, message: "Code scanning is not switched on." } }));
    expect(out.sources!["code-scanning"]).toMatchObject({ status: "unavailable", message: "Code scanning is not switched on." });
  });
  it("never lists the same finding twice, and orders worst first", () => {
    const out = combine(SET([F("a", "low")]), SET([F("a", "low", "sarif:x"), F("b", "critical", "sarif:x")]), ALERTS([F("a", "low")]));
    expect(out.findings.map((f) => f.id)).toEqual(["b", "a"]);
  });
  it("no external sources: the result has no `sources` key at all", () => {
    expect(combine(SET([F("a")]), null, null)).not.toHaveProperty("sources");
  });
  it("does not mutate its inputs", () => {
    const fresh = SET([F("mine")]);
    const snapshot = JSON.stringify(fresh);
    combine(fresh, null, ALERTS([], [["mine", ["dependabot"]]]));
    expect(JSON.stringify(fresh)).toBe(snapshot);
  });
});
