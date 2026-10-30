"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { CornerDownLeft, Loader2, Search, Sparkles, Zap } from "lucide-react";
import { toDigest } from "@/lib/ask/digest";
import { answerLocal, searchNodes } from "@/lib/ask/query";
import type { AskResult } from "@/lib/ask/types";
import { ancestry } from "@/lib/graph/nav";
import type { TwinGraph } from "@/lib/graph/types";
import { useTwin } from "@/lib/store";
import { StatusRing } from "./status";

const SUGGESTIONS = ["Show failing things", "What changed in the last deploy?", "Which areas have no live signal?"];

/** ⌘K. Answers by changing the canvas, not by printing text: highlight, impact, jump. */
export function CommandPalette({ graph }: { graph: TwinGraph }) {
  const open = useTwin((s) => s.paletteOpen);
  const setOpen = useTwin((s) => s.setPalette);
  const setHighlight = useTwin((s) => s.setHighlight);
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const abort = useRef<AbortController | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setOpen(!useTwin.getState().paletteOpen); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setOpen]);

  useEffect(() => { // resetting the draft when the palette closes; the guard keeps it from looping
    if (open) { input.current?.focus(); return; }
    abort.current?.abort();
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setQ(""); setNote(null); setBusy(false);
  }, [open]);

  const matches = useMemo(() => (q.trim().length > 1 ? searchNodes(graph, q, 5) : []), [graph, q]);

  const apply = (r: AskResult) => {
    if (r.ok) { setHighlight(r.highlight); setOpen(false); } else setNote(r.message);
  };

  const submit = async (text: string) => {
    const question = text.trim();
    if (!question || busy) return;
    setNote(null);
    const local = answerLocal(graph, question);
    if (local.ok || !local.unrecognised) return apply(local);
    // nothing we can answer by rule: let the AI agent try
    setBusy(true);
    abort.current?.abort();
    const ac = (abort.current = new AbortController());
    try {
      const res = await fetch("/api/ask", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ mode: "query", question, digest: toDigest(graph) }), signal: ac.signal });
      const body = (await res.json()) as AskResult;
      apply(body.ok ? body : { ok: false, message: body.message });
    } catch (e) {
      if ((e as Error).name !== "AbortError") setNote("Couldn't reach the assistant. Try a name, or “show failing things”.");
    } finally { setBusy(false); }
  };

  const jump = (id: string) => {
    setHighlight({ title: graph.nodes.find((n) => n.id === id)?.label ?? id, mode: "info", ids: [id], focusId: id, path: ancestry(graph, id), source: "rules" });
    setOpen(false);
  };

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-50 flex items-start justify-center bg-void/70 px-4 pt-[14vh] backdrop-blur-sm"
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.12 }}
          onPointerDown={(e) => { if (e.target === e.currentTarget) setOpen(false); }}
        >
          <div role="dialog" aria-modal="true" aria-label="Ask or jump" className="w-full max-w-xl overflow-hidden rounded-2xl border border-line bg-surface shadow-2xl">
            <form onSubmit={(e) => { e.preventDefault(); void submit(q); }} className="flex items-center gap-3 border-b border-line px-4">
              {busy ? <Loader2 size={17} className="animate-spin text-accent" aria-hidden /> : <Search size={17} className="text-ink-faint" aria-hidden />}
              <input
                ref={input} autoFocus value={q} onChange={(e) => { setQ(e.target.value); setNote(null); }} spellCheck={false} autoComplete="off"
                onKeyDown={(e) => { if (e.key === "Escape") { e.stopPropagation(); setOpen(false); } }}
                placeholder="Ask about your system, or jump to a part…" aria-label="Ask or jump"
                className="h-14 min-w-0 flex-1 bg-transparent text-[15px] outline-none placeholder:text-ink-faint"
              />
              <kbd className="hidden rounded border border-line px-1.5 py-0.5 font-mono text-[10px] text-ink-faint sm:block">esc</kbd>
            </form>

            <div className="max-h-[50vh] overflow-y-auto p-2">
              {note && <p role="alert" className="m-1 rounded-lg bg-degraded/10 px-3 py-2 text-sm text-degraded">{note}</p>}
              {matches.length > 0 && (
                <ul aria-label="Matching parts">
                  {matches.map((n) => (
                    <li key={n.id}>
                      <button onClick={() => jump(n.id)} className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left hover:bg-raised focus-visible:bg-raised">
                        <StatusRing status={n.state} size={22} />
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-sm text-ink">{n.label}</span>
                          <span className="block truncate text-xs capitalize text-ink-faint">{n.kind}{n.level > 0 ? ` · inside ${graph.nodes.find((p) => p.id === n.parentId)?.label ?? ""}` : ""}</span>
                        </span>
                        <span className="text-[11px] text-ink-faint">Jump</span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              {q.trim() && (
                <button onClick={() => void submit(q)} className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left hover:bg-raised">
                  <Sparkles size={16} className="text-accent" aria-hidden />
                  <span className="min-w-0 flex-1 truncate text-sm text-ink-dim">Ask: “{q.trim()}”</span>
                  <CornerDownLeft size={14} className="text-ink-faint" aria-hidden />
                </button>
              )}
              {!q.trim() && (
                <div className="p-2">
                  <p className="px-1 pb-1.5 text-[11px] font-medium uppercase tracking-wider text-ink-faint">Try</p>
                  {[...SUGGESTIONS, "What breaks if … is down?"].map((s, i) => (
                    <button key={s} onClick={() => (i < 3 ? void submit(s) : setQ("What breaks if  is down"))} className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm text-ink-dim hover:bg-raised hover:text-ink">
                      <Zap size={14} className="text-ink-faint" aria-hidden />{s}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
