"use client";

import { useEffect, useMemo } from "react";
import { ArrowRight, Pause, Play, X } from "lucide-react";
import { ancestry } from "@/lib/graph/nav";
import type { TwinGraph } from "@/lib/graph/types";
import type { Incident } from "@/lib/health/incident";
import { useTwin } from "@/lib/store";
import { StatusRing } from "./status";
import { HOUR } from "./useHealthView";

const TICK_MS = 200;
const VIRTUAL_MS = 2 * 60_000; // 2 minutes of incident time per tick at 1x
const LEAD = 20 * 60_000;
const clock = (t: number) => new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

/** Plays an incident back: the clock runs, parts go red in the order they really failed, the failure's path lights up. */
export function ReplayBar({ graph, incident, anchor }: { graph: TwinGraph; incident: Incident; anchor: number }) {
  const replay = useTwin((s) => s.replay);
  const scrub = useTwin((s) => s.scrub);
  const setScrub = useTwin((s) => s.setScrub);
  const setReplay = useTwin((s) => s.setReplay);
  const setHighlight = useTwin((s) => s.setHighlight);

  const t = anchor - scrub * HOUR;
  const end = Math.min(anchor, (incident.endTs ?? anchor) + LEAD);
  const label = (id: string) => graph.nodes.find((n) => n.id === id)?.label ?? id;

  // clock
  useEffect(() => {
    if (!replay?.playing) return;
    const id = setInterval(() => {
      const cur = anchor - useTwin.getState().scrub * HOUR;
      const next = cur + VIRTUAL_MS * (useTwin.getState().replay?.speed ?? 1);
      if (next >= end) { setScrub((anchor - end) / HOUR); setReplay({ playing: false, speed: useTwin.getState().replay?.speed ?? 1 }); return; }
      setScrub((anchor - next) / HOUR);
    }, TICK_MS);
    return () => clearInterval(id);
  }, [replay?.playing, anchor, end, setScrub, setReplay]);

  const reached = useMemo(() => incident.path.filter((s) => s.ts <= t), [incident, t]);
  const latest = reached.at(-1);

  // the canvas shows where it started and how far it has travelled
  const reachedKey = reached.map((r) => r.nodeId).join("|");
  useEffect(() => {
    if (!reached.length) { setHighlight(null); return; }
    const first = incident.first.nodeId;
    setHighlight({
      mode: "impact", focusId: first, ids: reached.filter((r) => r.nodeId !== first).map((r) => r.nodeId), path: ancestry(graph, first), source: "rules",
      title: `${label(first)} went bad first`, detail: reached.length > 1 ? `${reached.length - 1} more affected so far` : undefined,
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reachedKey]);

  const exit = () => { setReplay(null); setHighlight(null); setScrub(0); };
  const restart = () => { setScrub((anchor - (incident.startTs - LEAD)) / HOUR); setReplay({ playing: true, speed: replay?.speed ?? 1 }); };
  const atEnd = t >= end - 1000;

  return (
    <div role="region" aria-label="Incident replay" className="absolute bottom-3 left-1/2 z-20 w-[min(46rem,calc(100%-2rem))] -translate-x-1/2 rounded-2xl border border-line bg-surface/95 p-3 shadow-2xl backdrop-blur">
      <div className="flex items-center gap-3">
        <button onClick={() => (atEnd ? restart() : setReplay({ playing: !replay?.playing, speed: replay?.speed ?? 1 }))} aria-label={replay?.playing ? "Pause replay" : atEnd ? "Replay again" : "Play replay"} className="grid h-9 w-9 shrink-0 place-items-center rounded-full bg-accent/20 text-accent hover:bg-accent/30">
          {replay?.playing ? <Pause size={16} /> : <Play size={16} />}
        </button>
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-2">
            <span className="font-mono text-lg tabular-nums text-ink">{clock(t)}</span>
            <span className="text-xs text-ink-faint">incident replay</span>
          </div>
          <div aria-live="polite" className="truncate text-xs text-ink-dim">
            {latest ? `${label(latest.nodeId)}: ${latest.reason ?? latest.state}` : "All quiet. Watching for the first sign of trouble…"}
          </div>
        </div>
        {([1, 2, 4] as const).map((sp) => (
          <button key={sp} onClick={() => setReplay({ playing: replay?.playing ?? false, speed: sp })} aria-pressed={replay?.speed === sp} className={`hidden rounded px-1.5 py-0.5 font-mono text-[11px] sm:block ${replay?.speed === sp ? "bg-raised text-ink" : "text-ink-faint hover:text-ink"}`}>{sp}x</button>
        ))}
        <button onClick={exit} aria-label="Exit replay" className="rounded p-1 text-ink-dim hover:bg-raised hover:text-ink"><X size={16} /></button>
      </div>

      <ol aria-label="How it spread" className="mt-3 flex flex-wrap items-center gap-1.5">
        {incident.path.map((s, i) => {
          const on = s.ts <= t;
          const cur = graph.nodes.find((n) => n.id === s.nodeId);
          return (
            <li key={s.nodeId} className="flex items-center gap-1.5">
              {i > 0 && <ArrowRight size={12} className={on ? "text-failing" : "text-ink-faint"} aria-hidden />}
              <span className={`flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs transition-colors ${on ? "border-failing/60 bg-failing/10 text-ink" : "border-line text-ink-faint"}`}>
                {on && cur ? <StatusRing status={cur.state === "unknown" ? s.state : cur.state} size={14} /> : <span className="h-2 w-2 rounded-full bg-line" aria-hidden />}
                {label(s.nodeId)}{on && <span className="font-mono text-[10px] text-ink-faint">{clock(s.ts)}</span>}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
