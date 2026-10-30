"use client";

import { Sparkles, X, Zap } from "lucide-react";
import { ancestry } from "@/lib/graph/nav";
import type { TwinGraph } from "@/lib/graph/types";
import { useTwin } from "@/lib/store";
import { StatusRing } from "./status";

/** What the last ⌘K question found, with one-click jumps to each result. */
export function HighlightBar({ graph }: { graph: TwinGraph }) {
  const h = useTwin((s) => s.highlight);
  const setHighlight = useTwin((s) => s.setHighlight);
  const setPath = useTwin((s) => s.setPath);
  const select = useTwin((s) => s.select);
  if (!h) return null;

  const jump = (id: string) => { setPath(ancestry(graph, id)); select(id); };
  const chips = (h.mode === "set" ? h.ids : h.ids).map((id) => graph.nodes.find((n) => n.id === id)).filter((n): n is NonNullable<typeof n> => !!n).slice(0, 6);

  return (
    <div role="status" className="absolute bottom-3 left-1/2 z-20 flex max-w-[min(46rem,calc(100%-2rem))] -translate-x-1/2 flex-col gap-2 rounded-2xl border border-line bg-surface/95 px-4 py-2.5 shadow-2xl backdrop-blur">
      <div className="flex items-center gap-2.5">
        {h.mode === "impact" ? <Zap size={15} className="shrink-0 text-failing" aria-hidden /> : <Sparkles size={15} className="shrink-0 text-accent" aria-hidden />}
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-medium text-ink">{h.title}</div>
          {h.detail && <div className="truncate text-xs text-ink-dim">{h.detail}</div>}
        </div>
        {h.source === "ai" && <span className="shrink-0 rounded-full bg-raised px-2 py-0.5 text-[10px] text-ink-faint">AI</span>}
        <button onClick={() => setHighlight(null)} aria-label="Clear highlight" className="shrink-0 rounded p-1 text-ink-dim hover:bg-raised hover:text-ink"><X size={15} /></button>
      </div>
      {chips.length > 1 && h.mode === "set" && (
        <div className="flex flex-wrap gap-1.5" aria-label="Jump to a result">
          {chips.map((n) => (
            <button key={n.id} onClick={() => jump(n.id)} className="flex items-center gap-1.5 rounded-full border border-line bg-raised px-2 py-0.5 text-xs text-ink-dim hover:text-ink">
              <StatusRing status={n.state} size={14} />{n.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
