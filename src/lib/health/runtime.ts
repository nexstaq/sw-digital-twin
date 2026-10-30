import type { Status } from "@/lib/graph/types";
import { ewmaAnomaly } from "./anomaly";
import type { RuntimeBucket } from "./signals";

const WINDOW = 12 * 3_600_000; // history used for the baseline
const MIN_FRESH = 45 * 60_000; // older than this (or 2.5 sampling steps, for hourly sources) and we say nothing rather than guess
const ERR_FAIL = 0.05;
const ERR_WARN = 0.02;

export interface RuntimeVerdict { state: Status; score: number; reasons: string[]; spark: number[]; links: { label: string; url: string; ok?: boolean }[] }

const pct = (x: number) => `${x >= 0.1 ? Math.round(x * 100) : (x * 100).toFixed(1)}%`;
const ms = (x: number) => (x >= 1000 ? `${(x / 1000).toFixed(1)}s` : `${Math.round(x)}ms`);
const num = (x: number) => (x >= 10 ? String(Math.round(x)) : x.toFixed(1));
const worse = (a: Status, b: Status): Status => (["failing", "degraded", "nominal", "unknown"] as const).find((s) => a === s || b === s)!;

/**
 * Health of one service from its runtime buckets as of time `t`. Absolute thresholds for error rate (when we know the
 * request volume), EWMA z-score for everything, so a service that is "normally noisy" is judged against itself.
 * Returns null when there is no recent data: unknown, never green.
 */
export function runtimeHealth(all: RuntimeBucket[], t: number): RuntimeVerdict | null {
  const b = all.filter((x) => x.ts <= t && x.ts > t - WINDOW).sort((x, y) => x.ts - y.ts);
  if (!b.length) return null;
  const gaps = b.slice(-10).slice(1).map((x, i) => x.ts - b.slice(-10)[i].ts).sort((x, y) => x - y);
  const step = gaps.length ? gaps[Math.floor(gaps.length / 2)] : 0;
  if (t - b[b.length - 1].ts > Math.max(MIN_FRESH, step * 2.5)) return null;

  let state: Status = "nominal";
  const reasons: string[] = [];

  const rate = b.filter((x) => x.requests && x.requests > 0 && x.errors !== undefined).map((x) => x.errors! / x.requests!);
  if (rate.length >= 2) {
    const last2 = rate.slice(-2);
    const a = ewmaAnomaly(rate, { floor: 0.002 });
    const base = a ? a.mean : 0;
    if (last2.every((r) => r >= ERR_FAIL)) { state = "failing"; reasons.push(`Error rate ${pct(rate.at(-1)!)}${a ? ` (normally ${pct(base)})` : ""}`); }
    else if (last2.every((r) => r >= ERR_WARN) || a?.anomalous) { state = worse(state, "degraded"); reasons.push(`Error rate ${pct(rate.at(-1)!)}${a ? ` (normally ${pct(base)})` : ""}`); }
  } else {
    const errs = b.filter((x) => x.errors !== undefined).map((x) => x.errors!);
    const a = ewmaAnomaly(errs, { floor: 0.5 });
    if (a?.anomalous && a.ratio >= 2) {
      state = a.z >= 4 && a.ratio >= 8 ? "failing" : "degraded";
      reasons.push(`${num(a.latest)} errors/min (normally ${num(a.mean)})`);
    }
  }

  const lat = b.filter((x) => x.p95Ms !== undefined).map((x) => x.p95Ms!);
  const la = ewmaAnomaly(lat, { floor: 5 });
  if (la?.anomalous && la.ratio >= 1.5) {
    state = worse(state, la.ratio >= 5 ? "failing" : "degraded");
    reasons.push(`p95 latency ${ms(la.latest)} (normally ${ms(la.mean)})`);
  }

  const last = b[b.length - 1];
  const links = state === "nominal" ? [] : (last.top ?? []).slice(0, 3).map((i) => ({ label: `${i.title} · ${i.count}`, url: i.url, ok: false }));
  const series = rate.length >= 2 ? rate.map((r) => Math.min(1, r / 0.1)) : b.map((x) => x.errors ?? 0);
  const max = Math.max(...series, 1e-9);
  const spark = (rate.length >= 2 ? series : series.map((v) => v / max)).slice(-12).map((v) => Math.min(1, Math.max(0, v)));
  return { state, score: state === "failing" ? 0.15 : state === "degraded" ? 0.6 : 0.96, reasons, spark: spark.length >= 2 ? spark : [0.05, 0.05], links };
}
