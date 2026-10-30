"use client";

import { AnimatePresence, motion } from "framer-motion";
import { useState, type ReactNode } from "react";
import { FileCode2, X, ArrowRight, ExternalLink, Loader2, SendHorizontal } from "lucide-react";
import { Sparkles } from "lucide-react";
import { describeFor, displayName } from "@/lib/graph/display";
import type { TwinNode } from "@/lib/graph/types";
import type { Lens } from "@/lib/store";
import { Sparkline, StatusRing, STATUS, useStatusLabel, useVocab } from "./status";

type Ev = TwinNode["evidence"][number];
const evidenceKey = (e: Ev) => `${e.path}:${JSON.stringify(e.lines ?? null)}:${e.runId ?? ""}`;
/** several detectors can cite the same file for one node; show each citation once */
const uniqueEvidence = (all: Ev[]) => [...new Map(all.map((e) => [evidenceKey(e), e])).values()];

const IDEAS = ["Why is this here?", "What depends on this?", "What should I check first?"];

/** Free-text question about one node. The answer is prose, so it lives in the drawer rather than on the canvas. */
function AskBox({ onAsk }: { onAsk: (q: string) => Promise<{ ok: true; text: string } | { ok: false; message: string }> }) {
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [out, setOut] = useState<{ ok: boolean; text: string } | null>(null);
  const ask = async (text: string) => {
    if (!text.trim() || busy) return;
    setBusy(true); setOut(null);
    try { const r = await onAsk(text.trim()); setOut(r.ok ? { ok: true, text: r.text } : { ok: false, text: r.message }); }
    catch { setOut({ ok: false, text: "Couldn't reach the assistant." }); }
    finally { setBusy(false); }
  };
  return (
    <section>
      <h3 className="mb-1.5 flex items-center gap-1 text-[11px] font-medium uppercase tracking-wider text-ink-faint"><Sparkles size={11} aria-hidden /> Ask AI about this</h3>
      <form onSubmit={(e) => { e.preventDefault(); void ask(q); }} className="flex gap-1.5">
        <input value={q} onChange={(e) => setQ(e.target.value)} maxLength={300} placeholder="e.g. what should I check first?" aria-label="Ask AI about this node"
          className="min-w-0 flex-1 rounded-lg border border-line bg-raised px-2.5 py-1.5 text-xs outline-none placeholder:text-ink-faint focus:border-accent" />
        <button disabled={busy || !q.trim()} aria-label="Ask" className="grid w-8 place-items-center rounded-lg bg-accent/15 text-accent enabled:hover:bg-accent/25 disabled:opacity-40">
          {busy ? <Loader2 size={14} className="animate-spin" /> : <SendHorizontal size={14} />}
        </button>
      </form>
      {!out && !busy && <div className="mt-1.5 flex flex-wrap gap-1.5">{IDEAS.map((i) => <button key={i} onClick={() => { setQ(i); void ask(i); }} className="rounded-full border border-line px-2 py-0.5 text-[11px] text-ink-dim hover:text-ink">{i}</button>)}</div>}
      {out && <p role={out.ok ? "status" : "alert"} className={`mt-2 whitespace-pre-wrap rounded-lg px-2.5 py-2 text-xs leading-relaxed ${out.ok ? "bg-raised text-ink-dim" : "bg-degraded/10 text-degraded"}`}>{out.text}</p>}
    </section>
  );
}

export function SideDrawer({ node, childCount, lens, onClose, onDrill, onAsk, editor }: {
  /** "correct this node" form, offered to people with push access */
  editor?: ReactNode;
  node: TwinNode | null; childCount: number; lens: Lens; onClose: () => void; onDrill: () => void;
  onAsk?: (nodeId: string, question: string) => Promise<{ ok: true; text: string } | { ok: false; message: string }>;
}) {
  const statusLabel = useStatusLabel();
  const vocab = useVocab();
  return (
    <AnimatePresence>
      {node && (
        <motion.aside
          key={node.id}
          initial={{ x: 40, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: 40, opacity: 0 }}
          transition={{ duration: 0.18 }}
          className="absolute right-3 top-3 bottom-3 z-10 flex w-[340px] max-w-[calc(100%-1.5rem)] flex-col overflow-hidden rounded-2xl border border-line bg-surface/95 shadow-2xl backdrop-blur"
          aria-label={`${node.label} details`}
        >
          <header className="flex items-start gap-3 border-b border-line p-4">
            <StatusRing status={node.state} size={34} label={statusLabel(node.state)} />
            <div className="min-w-0 flex-1">
              <h2 className="truncate text-base font-semibold">{displayName(node, lens)}</h2>
              <p className={`text-xs ${STATUS[node.state].text}`}>{statusLabel(node.state)} · {vocab === "security" ? "safety" : "health"} {Math.round(node.score * 100)}</p>
            </div>
            <button onClick={onClose} aria-label="Close" className="rounded p-1 text-ink-dim hover:bg-raised hover:text-ink">
              <X size={16} />
            </button>
          </header>

          <div className="flex-1 space-y-5 overflow-y-auto p-4 text-sm">
            <p className="text-ink-dim">{describeFor(node, lens)}</p>
            {node.narrative && (
              <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-ink-faint">
                <span className="flex items-center gap-1"><Sparkles size={11} aria-hidden /> AI-written · {node.narrative.confidence} confidence</span>
                {displayName(node, lens) !== node.label && <span className="font-mono">{node.label}</span>}
              </p>
            )}

            <section>
              <h3 className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-ink-faint">Last 24 hours</h3>
              <Sparkline values={node.spark} status={node.state} w={300} h={44} />
            </section>

            {node.reasons.length > 0 && (
              <section>
                <h3 className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-ink-faint">Why</h3>
                <ul className="space-y-1.5">
                  {node.reasons.map((r) => (
                    <li key={r} className="flex gap-2"><span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: STATUS[node.state].color }} />{r}</li>
                  ))}
                </ul>
              </section>
            )}

            {node.links && node.links.length > 0 && (
              <section>
                <h3 className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-ink-faint">Recent runs</h3>
                <div className="space-y-1.5">
                  {node.links.map((l) => (
                    <a key={l.url} href={l.url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 rounded-lg bg-raised px-2.5 py-1.5 text-xs text-ink-dim hover:text-ink">
                      <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: l.ok === undefined ? "var(--color-unknown)" : l.ok ? "var(--color-nominal)" : "var(--color-failing)" }} aria-hidden />
                      <span className="min-w-0 flex-1 truncate">{l.label}</span>
                      <ExternalLink size={12} aria-hidden /><span className="sr-only">(opens GitHub)</span>
                    </a>
                  ))}
                </div>
              </section>
            )}

            <section>
              <h3 className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-ink-faint">Evidence</h3>
              {uniqueEvidence(node.evidence).map((ev) => (
                <div key={evidenceKey(ev)} className="flex items-center gap-2 rounded-lg bg-raised px-2.5 py-1.5 font-mono text-xs text-ink-dim">
                  <FileCode2 size={13} aria-hidden /> <span className="truncate">{ev.path}</span>
                </div>
              ))}
            </section>

            {onAsk && <AskBox key={node.id} onAsk={(q) => onAsk(node.id, q)} />}
            {editor}

            {node.owners && (
              <section>
                <h3 className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-ink-faint">Owners</h3>
                <div className="flex gap-1.5">{node.owners.map((o) => <span key={o} className="rounded-full bg-raised px-2 py-0.5 text-xs">{o}</span>)}</div>
              </section>
            )}
          </div>

          {childCount > 0 && (
            <footer className="border-t border-line p-3">
              <button onClick={onDrill} className="flex w-full items-center justify-center gap-2 rounded-lg bg-accent/15 py-2 text-sm font-medium text-accent hover:bg-accent/25">
                Open {childCount} inner parts <ArrowRight size={15} />
              </button>
            </footer>
          )}
        </motion.aside>
      )}
    </AnimatePresence>
  );
}
