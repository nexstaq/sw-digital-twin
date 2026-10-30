"use client";

import { useState } from "react";
import { EyeOff, Pencil, RotateCcw } from "lucide-react";
import type { Override } from "@/lib/graph/overrides";
import type { TwinNode } from "@/lib/graph/types";

/** "Correct this node": rename, re-describe or hide. Saved for the whole team and kept across re-scans. */
export function NodeEditor({ node, current, onSave, error }: { node: TwinNode; current?: Override; onSave: (o: Override) => void; error: string | null }) {
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState(node.label);
  const [summary, setSummary] = useState(node.summary);
  const field = "w-full rounded-lg border border-line bg-raised px-2.5 py-1.5 text-xs outline-none focus:border-accent";

  return (
    <section>
      <h3 className="mb-1.5 flex items-center gap-1 text-[11px] font-medium uppercase tracking-wider text-ink-faint"><Pencil size={11} aria-hidden /> Correct this</h3>
      {!open ? (
        <div className="flex flex-wrap gap-1.5">
          <button onClick={() => setOpen(true)} className="rounded-full border border-line px-2.5 py-1 text-xs text-ink-dim hover:text-ink">Rename or re-describe</button>
          <button onClick={() => onSave({ ...current, hidden: true })} className="flex items-center gap-1 rounded-full border border-line px-2.5 py-1 text-xs text-ink-dim hover:text-ink"><EyeOff size={12} aria-hidden /> Not a real part, hide it</button>
          {current && <button onClick={() => onSave({})} className="flex items-center gap-1 rounded-full border border-line px-2.5 py-1 text-xs text-ink-dim hover:text-ink"><RotateCcw size={12} aria-hidden /> Undo my edits</button>}
        </div>
      ) : (
        <form onSubmit={(e) => { e.preventDefault(); onSave({ ...current, label: label.trim() || undefined, summary: summary.trim() || undefined }); setOpen(false); }} className="space-y-1.5">
          <input value={label} onChange={(e) => setLabel(e.target.value)} maxLength={80} aria-label="Name" className={field} />
          <textarea value={summary} onChange={(e) => setSummary(e.target.value)} maxLength={400} rows={3} aria-label="Description" className={field} />
          <div className="flex gap-1.5">
            <button className="rounded-lg bg-accent/15 px-3 py-1 text-xs font-medium text-accent hover:bg-accent/25">Save for the team</button>
            <button type="button" onClick={() => setOpen(false)} className="rounded-lg px-3 py-1 text-xs text-ink-dim hover:text-ink">Cancel</button>
          </div>
        </form>
      )}
      {error && <p role="alert" className="mt-1.5 text-xs text-failing">{error}</p>}
    </section>
  );
}
