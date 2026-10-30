/**
 * Exponentially weighted moving average + z-score, the simplest detector that is still explainable
 * ("12% errors, normally 0.4%") and needs no training.
 *
 * The baseline is learned from everything EXCEPT the last `hold` points, and skips points that are themselves anomalous,
 * so a spike (even a long one) cannot hide itself by dragging the baseline up. A reading is anomalous only if every one of the last `hold` points exceeds the threshold (so one blip
 * does not flip a node red).
 */
export interface Anomaly {
  /** z-score of the latest point against the baseline */
  z: number;
  mean: number;
  std: number;
  latest: number;
  /** latest / baseline mean (Infinity-safe) */
  ratio: number;
  anomalous: boolean;
}

export interface AnomalyOptions {
  alpha?: number;
  /** z-score needed on each of the last `hold` points */
  threshold?: number;
  hold?: number;
  /** baseline points needed before we trust it */
  minBaseline?: number;
  /** smallest std we will divide by; stops a perfectly flat baseline from making every wiggle "infinite sigma" */
  floor?: number;
}

export function ewmaAnomaly(series: number[], o: AnomalyOptions = {}): Anomaly | null {
  const { alpha = 0.3, threshold = 3, hold = 2, minBaseline = 6, floor = 0 } = o;
  if (series.length < minBaseline + hold) return null;
  const base = series.slice(0, series.length - hold);
  const spread = (v: number, m: number) => Math.max(Math.sqrt(v), floor, Math.abs(m) * 0.05, 1e-9);

  // Learn the baseline, but never from a point that is itself anomalous. A plain EWMA absorbs a sustained spike within
  // a few samples and the problem "heals" on its own while it is still happening; freezing on outliers prevents that.
  let mean = base[0];
  let variance = 0;
  let used = 1;
  for (let i = 1; i < base.length; i++) {
    const x = base[i];
    if (used >= minBaseline && (x - mean) / spread(variance, mean) >= threshold) continue;
    const d = x - mean;
    mean += alpha * d;
    variance = (1 - alpha) * (variance + alpha * d * d);
    used++;
  }
  if (used < minBaseline) return null;

  const std = spread(variance, mean);
  const zs = series.slice(-hold).map((x) => (x - mean) / std);
  const latest = series[series.length - 1];
  return { z: zs[zs.length - 1], mean, std, latest, ratio: mean > 0 ? latest / mean : latest > 0 ? Infinity : 1, anomalous: zs.every((z) => z >= threshold) };
}
