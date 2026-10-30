"use client";

import { useEffect, useRef, useState } from "react";
import { ArrowRight, Check, Plug, X } from "lucide-react";
import type { ConnectorStatus } from "@/lib/connectors/types";
import type { Proposal } from "@/lib/connectors/match";
import type { TwinGraph } from "@/lib/graph/types";

/** "backend (in Infrastructure)": the same name often exists under several parents */
const nodeName = (g: TwinGraph, id: string) => {
  const n = g.nodes.find((x) => x.id === id);
  const parent = n?.parentId ? g.nodes.find((x) => x.id === n.parentId)?.label : undefined;
  return n ? (parent ? `${n.label} (in ${parent})` : n.label) : id;
};
const DOT = { ok: "bg-nominal", off: "bg-unknown", error: "bg-failing" } as const;
const CONF = { high: "text-nominal", medium: "text-degraded", low: "text-ink-faint" } as const;

/** Where live signals come from, and the one-time "is this service that node?" confirmations. */
export function SourcesPanel({ status, proposals, graph, onConfirm, onForget, shared }: {
  status: ConnectorStatus[]; proposals: Proposal[]; graph: TwinGraph; onConfirm: (m: Record<string, string>) => void; onForget: (id: string) => void;
  /** true: saved for everyone who can see the repo; false/null: saved in this browser only */
  shared?: boolean | null;
}) {
  const [open, setOpen] = useState(false);
  const [picks, setPicks] = useState<Record<string, string>>({});
  const ref = useRef<HTMLDivElement>(null);
  const pending = proposals.filter((p) => !p.confirmed);
  const options = graph.nodes.filter((n) => ["service", "package", "datastore", "external", "queue", "env"].includes(n.kind));

  useEffect(() => {
    if (!open) return;
    const away = (e: PointerEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") { e.stopPropagation(); setOpen(false); } };
    document.addEventListener("pointerdown", away);
    document.addEventListener("keydown", esc, true);
    return () => { document.removeEventListener("pointerdown", away); document.removeEventListener("keydown", esc, true); };
  }, [open]);

  return (
    <div ref={ref} className="relative">
      <button onClick={() => setOpen((o) => !o)} aria-expanded={open} aria-haspopup="dialog" className="relative flex items-center gap-2 rounded-lg border border-line bg-surface px-2.5 py-1.5 text-[13px] text-ink-dim hover:text-ink">
        <Plug size={14} aria-hidden /><span className="hidden lg:inline">Sources</span>
        {pending.length > 0 && <span className="grid h-4 min-w-4 place-items-center rounded-full bg-accent px-1 text-[10px] font-semibold text-void" aria-label={`${pending.length} to confirm`}>{pending.length}</span>}
      </button>

      {open && (
        <div role="dialog" aria-label="Live sources" className="absolute right-0 top-full z-40 mt-2 w-[min(28rem,calc(100vw-2rem))] max-h-[70vh] overflow-y-auto rounded-xl border border-line bg-surface p-4 shadow-2xl">
          <h2 className="text-sm font-semibold">Live sources</h2>
          <ul className="mt-2 space-y-1.5">
            <li className="flex items-center gap-2 text-xs text-ink-dim"><span className="h-2 w-2 rounded-full bg-nominal" aria-hidden />GitHub Actions &amp; deployments <span className="ml-auto text-ink-faint">on</span></li>
            {status.map((c) => (
              <li key={c.id} className="flex items-start gap-2 text-xs text-ink-dim">
                <span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${DOT[c.state]}`} aria-hidden />
                <span className="min-w-0 flex-1"><span className="text-ink">{c.label}</span>{c.message && <span className="block text-ink-faint">{c.message}</span>}</span>
                <span className="text-ink-faint">{c.state === "ok" ? "on" : c.state === "error" ? "error" : "off"}</span>
              </li>
            ))}
          </ul>

          {proposals.length > 0 && (
            <>
              <div className="mt-4 flex items-center justify-between">
                <h3 className="text-[11px] font-medium uppercase tracking-wider text-ink-faint" title={shared ? "Saved for everyone who can see this repository" : "Saved in this browser. Sign in with write access to share"}>Match services to parts · {shared ? "shared" : "this browser only"}</h3>
                {pending.some((p) => p.confidence === "high") && (
                  <button onClick={() => onConfirm(Object.fromEntries(pending.filter((p) => p.confidence === "high").map((p) => [p.id, p.nodeId])))} className="text-xs text-accent hover:underline">Confirm all high-confidence</button>
                )}
              </div>
              <ul className="mt-2 space-y-2">
                {proposals.map((p) => (
                  <li key={p.id} className="rounded-lg bg-raised p-2.5">
                    <div className="flex items-center gap-2 text-xs">
                      <span className="min-w-0 flex-1 truncate font-mono text-ink-dim" title={p.id}>{p.id}</span>
                      <ArrowRight size={12} className="shrink-0 text-ink-faint" aria-hidden />
                      <select
                        aria-label={`Part for ${p.id}`} value={picks[p.id] ?? p.nodeId} disabled={p.confirmed}
                        onChange={(e) => setPicks((x) => ({ ...x, [p.id]: e.target.value }))}
                        className="min-w-0 max-w-[45%] rounded border border-line bg-surface px-1.5 py-1 text-xs text-ink disabled:opacity-80"
                      >
                        {[p.nodeId, ...options.map((n) => n.id).filter((id) => id !== p.nodeId)].map((id) => <option key={id} value={id}>{nodeName(graph, id)}</option>)}
                      </select>
                    </div>
                    <div className="mt-1.5 flex items-center justify-between text-[11px]">
                      {p.confirmed ? <span className="flex items-center gap-1 text-nominal"><Check size={12} aria-hidden />Confirmed</span> : <span className={CONF[p.confidence]}>{p.confidence} confidence match</span>}
                      {p.confirmed
                        ? <button onClick={() => onForget(p.id)} className="flex items-center gap-1 text-ink-faint hover:text-ink"><X size={11} aria-hidden />Undo</button>
                        : <button onClick={() => onConfirm({ [p.id]: picks[p.id] ?? p.nodeId })} className="rounded bg-accent/20 px-2 py-0.5 text-accent hover:bg-accent/30">Confirm</button>}
                    </div>
                  </li>
                ))}
              </ul>
            </>
          )}
          {!status.some((c) => c.state === "ok") && <p className="mt-3 text-xs text-ink-faint">Add a source to light up the parts GitHub can&apos;t see: services, databases, third parties. See docs/CONNECTORS.md.</p>}
        </div>
      )}
    </div>
  );
}
