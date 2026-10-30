import { describe, expect, it } from "vitest";
import { describeDelta, withHistory } from "./trend";
import type { Finding, FindingSet, Severity } from "./types";

const F = (id: string, severity: Severity = "high"): Finding => ({ id, ruleId: "R", category: "code", severity, title: id, path: `${id}.ts`, line: 1, reason: "r", fix: "f", cwe: [], confidence: "high", detail: {} });
const SET = (ids: string[], at: number, sha = String(at).padEnd(40, "0"), extra: Partial<FindingSet> = {}): FindingSet => ({ repo: "a/b", sha, scannedAt: at, findings: ids.map((i) => F(i)), stats: { files: 1, packages: 0, lockfiles: 0 }, warnings: [], ...extra });

describe("withHistory", () => {
  it("the first scan has a one-point trend and no delta", () => {
    const s = withHistory(SET(["a", "b"], 100), null);
    expect(s.trend).toHaveLength(1);
    expect(s.trend![0]).toMatchObject({ scannedAt: 100, total: 2, counts: { high: 2 } });
    expect(s.delta).toBeUndefined();
  });
  it("reports what is new and how many were fixed since the previous scan", () => {
    const first = withHistory(SET(["a", "b", "c"], 100), null);
    const second = withHistory(SET(["b", "c", "d", "e"], 200), first);
    expect(second.delta).toMatchObject({ newIds: ["d", "e"], fixed: 1, previousSha: first.sha, previousScannedAt: 100 });
    expect(second.trend!.map((t) => t.total)).toEqual([3, 4]);
  });
  it("an unchanged scan says so", () => {
    const first = withHistory(SET(["a"], 100), null);
    const second = withHistory(SET(["a"], 200), first);
    expect(second.delta).toMatchObject({ newIds: [], fixed: 0 });
    expect(describeDelta(second.delta!)).toBe("No change since the previous scan.");
  });
  it("re-scanning the SAME commit replaces its point rather than adding a duplicate", () => {
    const sha = "c".repeat(40);
    const a = withHistory(SET(["x"], 100, sha), null);
    const b = withHistory(SET(["x", "y"], 200, sha), a);
    expect(b.trend).toHaveLength(1);
    expect(b.trend![0]).toMatchObject({ scannedAt: 200, total: 2 });
    expect(b.delta!.newIds).toEqual(["y"]);
  });
  it("keeps only the last 30 points", () => {
    let s: FindingSet | null = null;
    for (let i = 1; i <= 40; i++) s = withHistory(SET(["a"], i * 1000), s);
    expect(s!.trend).toHaveLength(30);
    expect(s!.trend![0].scannedAt).toBe(11_000);
    expect(s!.trend!.at(-1)!.scannedAt).toBe(40_000);
  });
  it("copes with a stored scan from before history existed", () => {
    const legacy = SET(["a", "b"], 100); // no trend, no delta
    const next = withHistory(SET(["b"], 200), legacy);
    expect(next.trend).toHaveLength(1);
    expect(next.delta).toMatchObject({ newIds: [], fixed: 1 });
  });
  it("does not mutate its inputs", () => {
    const prev = withHistory(SET(["a"], 100), null);
    const frozen = JSON.stringify(prev);
    const cur = SET(["a", "b"], 200);
    withHistory(cur, prev);
    expect(JSON.stringify(prev)).toBe(frozen);
    expect(cur.trend).toBeUndefined();
  });
  it("a better score shows as a rising trend", () => {
    const bad = withHistory({ ...SET([], 100), findings: [F("a", "critical"), F("b", "critical")] }, null);
    const good = withHistory(SET([], 200), bad);
    expect(good.trend![1].score).toBeGreaterThan(good.trend![0].score);
  });
});

describe("describeDelta", () => {
  it("is one plain sentence", () => {
    expect(describeDelta({ newIds: ["a", "b"], fixed: 0, previousSha: "x", previousScannedAt: 1 })).toBe("Since the previous scan: 2 new.");
    expect(describeDelta({ newIds: [], fixed: 3, previousSha: "x", previousScannedAt: 1 })).toBe("Since the previous scan: 3 fixed.");
    expect(describeDelta({ newIds: ["a"], fixed: 3, previousSha: "x", previousScannedAt: 1 })).toBe("Since the previous scan: 1 new, 3 fixed.");
  });
});
