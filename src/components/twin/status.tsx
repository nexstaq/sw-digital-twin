import { CircleCheck, CircleHelp, OctagonX, TriangleAlert, type LucideIcon } from "lucide-react";
import type { Status } from "@/lib/graph/types";

export const STATUS: Record<Status, {
  label: string; Icon: LucideIcon; text: string; bg: string; border: string; color: string;
}> = {
  nominal:  { label: "Nominal",  Icon: CircleCheck,   text: "text-nominal",  bg: "bg-nominal/10",  border: "border-nominal/40",  color: "var(--color-nominal)" },
  degraded: { label: "Degraded", Icon: TriangleAlert, text: "text-degraded", bg: "bg-degraded/10", border: "border-degraded/50", color: "var(--color-degraded)" },
  failing:  { label: "Failing",  Icon: OctagonX,      text: "text-failing",  bg: "bg-failing/10",  border: "border-failing/60",  color: "var(--color-failing)" },
  unknown:  { label: "No signal", Icon: CircleHelp,   text: "text-unknown",  bg: "bg-unknown/10",  border: "border-unknown/40",  color: "var(--color-unknown)" },
};

/** Icon in a ring; pulses when something needs attention. */
export function StatusRing({ status, size = 28 }: { status: Status; size?: number }) {
  const s = STATUS[status];
  return (
    <span
      className={`relative inline-flex shrink-0 items-center justify-center rounded-full ${s.bg} ${s.text}`}
      style={{ width: size, height: size }}
      role="img"
      aria-label={s.label}
    >
      {(status === "failing" || status === "degraded") && (
        <span className="pulse-ring absolute inset-0 rounded-full border" style={{ borderColor: s.color }} />
      )}
      <s.Icon size={size * 0.62} strokeWidth={2.2} />
    </span>
  );
}

export function Sparkline({ values, status, w = 84, h = 22 }: { values: number[]; status: Status; w?: number; h?: number }) {
  if (!values.length) return null;
  const step = w / (values.length - 1);
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(h - 2 - v * (h - 4)).toFixed(1)}`);
  const color = STATUS[status].color;
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden>
      <polyline points={`0,${h} ${pts.join(" ")} ${w},${h}`} fill={color} opacity={0.12} />
      <polyline points={pts.join(" ")} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}
