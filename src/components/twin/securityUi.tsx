"use client";

import { Info, OctagonX, ShieldAlert, TriangleAlert, type LucideIcon } from "lucide-react";
import { SEVERITIES, type Category, type Finding, type Severity } from "@/lib/security/types";
import type { Posture } from "@/lib/security/map";

/** Every severity has a shape AND a word, never colour alone. */
export const SEV: Record<Severity, { label: string; Icon: LucideIcon; cls: string; bar: string }> = {
  critical: { label: "Critical", Icon: OctagonX, cls: "bg-failing text-void", bar: "bg-failing" },
  high: { label: "High", Icon: ShieldAlert, cls: "border border-failing/60 bg-failing/10 text-failing", bar: "bg-failing/70" },
  medium: { label: "Medium", Icon: TriangleAlert, cls: "border border-degraded/60 bg-degraded/10 text-degraded", bar: "bg-degraded" },
  low: { label: "Low", Icon: Info, cls: "border border-line bg-raised text-ink-dim", bar: "bg-ink-faint" },
  info: { label: "Info", Icon: Info, cls: "border border-line bg-raised text-ink-faint", bar: "bg-line" },
};

export const CATEGORY_LABEL: Record<Category, string> = { dependency: "Dependencies", secret: "Secrets", pipeline: "Pipelines", container: "Containers", code: "Code" };

export function SeverityBadge({ severity, compact }: { severity: Severity; compact?: boolean }) {
  const s = SEV[severity];
  return <span className={`inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold ${s.cls}`}><s.Icon size={11} aria-hidden />{compact ? s.label[0] : s.label}{compact && <span className="sr-only">{s.label.slice(1)}</span>}</span>;
}

export const where = (f: Pick<Finding, "path" | "line">) => (f.line ? `${f.path}:${f.line}` : f.path);

/** One finding as a row: what, how bad, where. `isNew` marks one that was not in the previous scan. */
export function FindingRow({ f, onOpen, isNew }: { f: Finding; onOpen: (f: Finding) => void; isNew?: boolean }) {
  return (
    <button onClick={() => onOpen(f)} className="flex w-full items-start gap-2 rounded-lg bg-raised px-2.5 py-2 text-left hover:ring-1 hover:ring-accent/50">
      <SeverityBadge severity={f.severity} />
      <span className="min-w-0 flex-1">
        <span className="block truncate text-xs text-ink">{isNew && <span className="mr-1.5 rounded bg-accent/20 px-1 py-px text-[9px] font-semibold uppercase tracking-wide text-accent">New</span>}{f.title}</span>
        <span className="block truncate font-mono text-[11px] text-ink-faint">{where(f)}</span>
      </span>
    </button>
  );
}

const GRADE_COLOR = { A: "var(--color-nominal)", B: "var(--color-nominal)", C: "var(--color-degraded)", D: "var(--color-failing)", F: "var(--color-failing)" } as const;

/** A dial: the arc is the safety score, the letter is the grade. */
export function GradeRing({ posture, size = 64 }: { posture: Posture; size?: number }) {
  const r = size / 2 - 5, c = 2 * Math.PI * r;
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} role="img" aria-label={`Security grade ${posture.grade}, score ${posture.score} out of 100`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--color-line)" strokeWidth={5} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={GRADE_COLOR[posture.grade]} strokeWidth={5} strokeLinecap="round" strokeDasharray={`${(posture.score / 100) * c} ${c}`} />
      </svg>
      <div className="absolute inset-0 grid place-items-center text-xl font-bold" style={{ color: GRADE_COLOR[posture.grade] }}>{posture.grade}</div>
    </div>
  );
}

/** The mix of severities as one bar, so "mostly low" and "mostly critical" read differently at a glance. */
export function SeverityBar({ counts }: { counts: Record<Severity, number> }) {
  const total = SEVERITIES.reduce((n, s) => n + counts[s], 0);
  if (!total) return <div className="h-2 rounded-full bg-nominal/30" role="img" aria-label="No findings" />;
  return (
    <div>
      <div className="flex h-2 overflow-hidden rounded-full bg-raised" role="img" aria-label={SEVERITIES.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`).join(", ")}>
        {SEVERITIES.filter((s) => counts[s]).map((s) => <div key={s} className={SEV[s].bar} style={{ width: `${(counts[s] / total) * 100}%` }} />)}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-ink-dim">
        {SEVERITIES.filter((s) => counts[s]).map((s) => <span key={s} className="flex items-center gap-1"><span className={`h-2 w-2 rounded-sm ${SEV[s].bar}`} aria-hidden />{counts[s]} {SEV[s].label.toLowerCase()}</span>)}
      </div>
    </div>
  );
}

/** The safety score over the last scans. The final dot is today; higher is safer. */
export function TrendLine({ points, w = 120, h = 28 }: { points: { score: number }[]; w?: number; h?: number }) {
  if (points.length < 2) return null;
  const xs = (i: number) => 3 + (i * (w - 6)) / (points.length - 1);
  const ys = (v: number) => h - 3 - (Math.max(0, Math.min(100, v)) / 100) * (h - 6);
  const pts = points.map((p, i) => `${xs(i).toFixed(1)},${ys(p.score).toFixed(1)}`).join(" ");
  const first = points[0].score, last = points.at(-1)!.score;
  const color = last > first ? "var(--color-nominal)" : last < first ? "var(--color-failing)" : "var(--color-unknown)";
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`Safety score over the last ${points.length} scans: ${first} then ${last}${last > first ? ", improving" : last < first ? ", getting worse" : ", unchanged"}`}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth={1.8} strokeLinejoin="round" strokeLinecap="round" opacity={0.9} />
      <circle cx={xs(points.length - 1)} cy={ys(last)} r={3} fill={color} />
    </svg>
  );
}
