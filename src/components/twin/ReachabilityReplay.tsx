"use client";

import { useEffect, useState } from "react";
import { Crown, Pause, Play, ShieldCheck, ShieldOff, Waypoints } from "lucide-react";
import type { TwinGraph } from "@/lib/graph/types";
import type { Finding, FindingSet } from "@/lib/security/types";
import { buildReplaySteps, type ReplayStep } from "@/lib/security/replay";
import { useTwin } from "@/lib/store";

/** A shape per outcome, never colour alone: a reachability path that reaches a crown jewel, one that does not, a genuine
 * detection, and a miss all look different even in greyscale. */
const ICON: Record<ReplayStep["icon"], { Icon: typeof Crown; cls: string; word: string }> = {
  crown: { Icon: Crown, cls: "text-failing", word: "reaches a crown jewel" },
  path: { Icon: Waypoints, cls: "text-accent", word: "reachable" },
  detected: { Icon: ShieldCheck, cls: "text-nominal", word: "the health engine noticed" },
  missed: { Icon: ShieldOff, cls: "text-degraded", word: "the health engine missed this" },
};
const STEP_MS = 1400;

/** Replays a scan's reachability (X6) and detection (X7) results on the canvas: each step highlights its block there
 * (the same mechanism "Show path" and the Simulate lens already use), one at a time, with a shape-coded step list and
 * a discrete step scrubber. There is no real clock here (every step already happened, deterministically, in the same
 * run), so the scrubber moves step to step rather than pretending to show elapsed time. */
export function ReachabilityReplay({ graph, findings, blue }: { graph: TwinGraph; findings: Finding[]; blue?: NonNullable<FindingSet["simulated"]>["blue"] }) {
  const steps = buildReplaySteps(graph, findings, blue?.coverage ?? []);
  const [i, setI] = useState(0);
  const ci = Math.min(i, Math.max(0, steps.length - 1)); // clamp at render time, so a shorter step list after a re-run never reads past its end
  const [playing, setPlaying] = useState(false);
  const setHighlight = useTwin((s) => s.setHighlight);

  useEffect(() => {
    if (!playing) return;
    const t = setInterval(() => {
      setI((x) => {
        const next = x + 1;
        if (next >= steps.length) { clearInterval(t); setPlaying(false); return x; }
        return next;
      });
    }, STEP_MS);
    return () => clearInterval(t);
  }, [playing, steps.length]);
  useEffect(() => {
    const s = steps[ci];
    if (!s || !s.nodeIds.length) { setHighlight(null); return; }
    setHighlight({ mode: "impact", focusId: s.nodeIds[0], ids: s.nodeIds.slice(1), path: [], source: "rules", title: s.title, detail: s.detail });
    return () => setHighlight(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ci, steps.length]);

  if (!steps.length) return <p role="status" className="text-xs text-ink-dim">Nothing to replay yet: no reachable path and no detection check ran on the last &quot;Verify by simulation&quot;.</p>;

  const s = steps[ci];
  const { Icon, cls } = ICON[s.icon];
  const play = () => { if (!playing && ci >= steps.length - 1) setI(0); setPlaying((p) => !p); };

  return (
    <div role="region" aria-label="Reachability and detection replay" className="space-y-2 rounded-lg border border-line bg-raised/60 p-2.5">
      <div className="flex items-center gap-2">
        <button onClick={play} aria-label={playing ? "Pause replay" : "Play replay"} className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-accent/20 text-accent hover:bg-accent/30">
          {playing ? <Pause size={14} aria-hidden /> : <Play size={14} aria-hidden />}
        </button>
        <input
          type="range" aria-label="Replay step" min={0} max={Math.max(0, steps.length - 1)} step={1} value={ci}
          onChange={(e) => { setPlaying(false); setI(Number(e.target.value)); }}
          className="h-1.5 flex-1 cursor-pointer appearance-none rounded-full bg-line accent-accent"
        />
        <span className="w-16 shrink-0 text-right font-mono text-[11px] text-ink-faint">{ci + 1}/{steps.length}</span>
      </div>
      <div aria-live="polite" className="flex items-start gap-2 rounded-md bg-surface/60 p-2">
        <Icon size={16} className={`mt-0.5 shrink-0 ${cls}`} aria-hidden />
        <div className="min-w-0">
          <div className="text-xs font-medium text-ink">{s.title}</div>
          <div className="text-xs text-ink-dim">{s.detail}</div>
        </div>
      </div>
      <ol aria-label="All steps" className="flex flex-wrap gap-1.5">
        {steps.map((st, n) => {
          const { Icon: I2 } = ICON[st.icon];
          return (
            <li key={st.id}>
              <button
                onClick={() => { setPlaying(false); setI(n); }} aria-current={n === ci ? "step" : undefined}
                aria-label={`Step ${n + 1}: ${st.title}`}
                className={`flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] ${n === ci ? "border-accent bg-accent/10 text-accent" : "border-line text-ink-dim hover:text-ink"}`}
              >
                <I2 size={11} aria-hidden /> {n + 1}
              </button>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
