import { posture } from "./map";
import type { FindingSet, Severity } from "./types";

type Point = NonNullable<FindingSet["trend"]>[number];
const MAX_POINTS = 30;
const MAX_NEW_IDS = 300;

/**
 * Adds history to a fresh scan: what is NEW since the previous scan, how many were FIXED, and the score over time.
 * "New" is judged by finding id, which is stable across line shifts (see `fingerprint`), so editing a file does not make an old
 * problem look new. Pure.
 */
export function withHistory(set: FindingSet, prev: FindingSet | null): FindingSet {
  const p = posture(set.findings, true);
  const point: Point = { sha: set.sha, scannedAt: set.scannedAt, score: p.score, total: p.total, counts: p.counts as Record<Severity, number> };

  // re-scanning the same commit replaces its point instead of adding a duplicate
  const history = [...(prev?.trend ?? [])];
  if (history.at(-1)?.sha === set.sha) history.pop();
  const trend = [...history, point].slice(-MAX_POINTS);

  if (!prev) return { ...set, trend };
  const before = new Set(prev.findings.map((f) => f.id));
  const now = new Set(set.findings.map((f) => f.id));
  return {
    ...set, trend,
    delta: {
      newIds: set.findings.filter((f) => !before.has(f.id)).map((f) => f.id).slice(0, MAX_NEW_IDS),
      fixed: prev.findings.filter((f) => !now.has(f.id)).length,
      previousSha: prev.sha, previousScannedAt: prev.scannedAt,
    },
  };
}

/** After findings were added to or removed from the current scan (an import), bring its trend point up to date. Same commit only. */
export function refreshTrend(set: FindingSet): FindingSet {
  const last = set.trend?.at(-1);
  if (!set.trend || !last || last.sha !== set.sha) return set;
  const p = posture(set.findings, true);
  return { ...set, trend: [...set.trend.slice(0, -1), { ...last, score: p.score, total: p.total, counts: p.counts as Record<Severity, number> }] };
}

/** One sentence for the posture card and the report. */
export function describeDelta(d: NonNullable<FindingSet["delta"]>): string {
  if (d.newIds.length === 0 && d.fixed === 0) return "No change since the previous scan.";
  const parts = [];
  if (d.newIds.length) parts.push(`${d.newIds.length} new`);
  if (d.fixed) parts.push(`${d.fixed} fixed`);
  return `Since the previous scan: ${parts.join(", ")}.`;
}
