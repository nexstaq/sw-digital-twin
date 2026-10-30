"use client";

import { useEffect, useMemo } from "react";
import { ChevronLeft, ChevronRight, Pause, Play, X } from "lucide-react";
import { ruleStory } from "@/lib/narrate/rules";
import type { TwinGraph } from "@/lib/graph/types";
import { useTwin } from "@/lib/store";
import { useReducedMotion } from "./AnimatedEdge";

const STEP_MS = 7000;

/** The steps to show: the model's validated tour if there is one, otherwise one derived from the analysis. */
export function useTourSteps(graph: TwinGraph) {
  return useMemo(() => (graph.story?.tour.length ? graph.story : ruleStory(graph)), [graph]);
}

export function TourPlayer({ graph, onExit }: { graph: TwinGraph; onExit: () => void }) {
  const story = useTourSteps(graph);
  const reduced = useReducedMotion();
  const step = useTwin((s) => s.tourStep);
  const playing = useTwin((s) => s.tourPlaying);
  const setTour = useTwin((s) => s.setTour);
  const total = story.tour.length;
  const cur = story.tour[Math.min(step, total - 1)];
  const node = graph.nodes.find((n) => n.id === cur?.nodeId);

  // autoplay; never for people who asked for reduced motion
  useEffect(() => {
    if (!playing || reduced || step >= total - 1) return;
    const t = setTimeout(() => setTour(step + 1), STEP_MS);
    return () => clearTimeout(t);
  }, [playing, reduced, step, total, setTour]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "ArrowRight") setTour(Math.min(total - 1, useTwin.getState().tourStep + 1), false);
      if (e.key === "ArrowLeft") setTour(Math.max(0, useTwin.getState().tourStep - 1), false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setTour, total]);

  if (!cur) return null;
  const last = step >= total - 1;

  return (
    <div role="region" aria-label="Guided tour" aria-live="polite"
      className="absolute inset-x-3 bottom-3 z-10 mx-auto max-w-2xl rounded-2xl border border-line bg-surface/95 p-4 shadow-2xl backdrop-blur">
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <div className="text-[11px] uppercase tracking-wider text-ink-faint">
            {step === 0 ? story.headline : `Step ${step + 1} of ${total}`}
          </div>
          <h2 className="mt-0.5 text-base font-semibold">{cur.title}</h2>
          <p className="mt-1 text-sm text-ink-dim">{cur.caption}</p>
          {node && <p className="mt-1.5 font-mono text-[11px] text-ink-faint">{node.label}</p>}
        </div>
        <button onClick={onExit} aria-label="Exit tour" className="rounded p-1 text-ink-dim hover:bg-raised hover:text-ink"><X size={16} /></button>
      </div>
      <div className="mt-3 flex items-center gap-3">
        <button onClick={() => setTour(Math.max(0, step - 1), false)} disabled={step === 0} aria-label="Previous step" className="rounded-md border border-line p-1.5 text-ink-dim enabled:hover:text-ink disabled:opacity-30"><ChevronLeft size={16} /></button>
        <button onClick={() => (last ? setTour(0, true) : setTour(step, !playing))} aria-label={playing ? "Pause" : "Play"} className="rounded-md border border-line p-1.5 text-ink-dim hover:text-ink">
          {playing && !last && !reduced ? <Pause size={16} /> : <Play size={16} />}
        </button>
        <button onClick={() => setTour(Math.min(total - 1, step + 1), false)} disabled={last} aria-label="Next step" className="rounded-md border border-line p-1.5 text-ink-dim enabled:hover:text-ink disabled:opacity-30"><ChevronRight size={16} /></button>
        <div className="flex flex-1 items-center gap-1" aria-hidden>
          {story.tour.map((t, i) => (
            <button key={t.nodeId} tabIndex={-1} onClick={() => setTour(i, false)}
              className={`h-1.5 flex-1 rounded-full transition-colors ${i === step ? "bg-accent" : i < step ? "bg-accent/40" : "bg-raised"}`} />
          ))}
        </div>
        <span className="text-[11px] text-ink-faint">{story.source === "ai" ? "AI-written" : "Auto-generated"}</span>
      </div>
    </div>
  );
}
