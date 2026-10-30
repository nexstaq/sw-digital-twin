"use client";

import { useEffect, useRef, useState } from "react";
import { ArrowRight, ChevronDown } from "lucide-react";
import type { TwinGraph } from "@/lib/graph/types";
import { explainVerdict, type Blocker } from "@/lib/graph/verdict";
import { StatusRing } from "./status";

const TONE = {
  nominal: "border-nominal/50 text-nominal bg-nominal/10",
  degraded: "border-degraded/60 text-degraded bg-degraded/10",
  failing: "border-failing/70 text-failing bg-failing/10",
  unknown: "border-unknown/50 text-unknown bg-unknown/10",
};

/** The launch verdict. Click it to see the rule that produced it and what is holding the launch. */
export function GoNoGoBanner({ graph, onShow }: { graph: TwinGraph; onShow?: (b: Blocker) => void }) {
  const v = explainVerdict(graph);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const away = (e: PointerEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") { e.stopPropagation(); setOpen(false); } };
    document.addEventListener("pointerdown", away);
    document.addEventListener("keydown", esc, true);
    return () => { document.removeEventListener("pointerdown", away); document.removeEventListener("keydown", esc, true); };
  }, [open]);

  return (
    <div ref={ref} className="relative flex items-center gap-3">
      <button
        onClick={() => setOpen((o) => !o)} aria-expanded={open} aria-haspopup="dialog"
        aria-label={`${v.word}. ${v.why}. Show why.`}
        className="flex items-center gap-3 rounded-lg text-left"
      >
        <span role="status" aria-live="polite" className={`rounded-lg border px-4 py-1.5 font-mono text-xl font-bold tracking-[0.2em] whitespace-nowrap ${TONE[v.tone]}`}>{v.word}</span>
        <span className="hidden text-sm text-ink-dim sm:flex sm:items-center sm:gap-1">{v.why}<ChevronDown size={14} aria-hidden className={`transition-transform ${open ? "rotate-180" : ""}`} /></span>
      </button>

      {open && (
        <div role="dialog" aria-label="Why this verdict" className="absolute left-0 top-full z-30 mt-2 w-[min(26rem,calc(100vw-2rem))] rounded-xl border border-line bg-surface p-4 shadow-2xl">
          <p className="text-sm text-ink">{v.rule}</p>
          <p className="mt-1 text-xs text-ink-faint">{v.coverage.known} of {v.coverage.total} top-level areas report a live signal.</p>
          {v.blockers.length > 0 ? (
            <ul className="mt-3 space-y-1.5">
              {v.blockers.slice(0, 6).map((b) => (
                <li key={b.id}>
                  <button onClick={() => { setOpen(false); onShow?.(b); }} className="flex w-full items-center gap-2.5 rounded-lg bg-raised px-2.5 py-2 text-left hover:bg-raised/70">
                    <StatusRing status={b.state} size={20} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[13px] font-medium text-ink">{b.label}</span>
                      <span className="block truncate text-xs text-ink-dim">{b.reason}</span>
                    </span>
                    <ArrowRight size={14} className="shrink-0 text-ink-faint" aria-hidden /><span className="sr-only">Show on map</span>
                  </button>
                </li>
              ))}
              {v.blockers.length > 6 && <li className="px-1 text-xs text-ink-faint">+{v.blockers.length - 6} more</li>}
            </ul>
          ) : (
            <p className="mt-3 text-sm text-ink-dim">Nothing needs attention.</p>
          )}
        </div>
      )}
    </div>
  );
}
