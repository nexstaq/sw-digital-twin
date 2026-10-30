"use client";

import { useState } from "react";
import { EyeOff, RotateCcw } from "lucide-react";
import type { Override, Overrides } from "@/lib/graph/overrides";
import type { TwinGraph } from "@/lib/graph/types";

/** Nodes someone hid as "not a real part". Without this a hidden node could never be found again to undo it. */
export function HiddenPanel({ scanned, overrides, onEdit }: { scanned: TwinGraph; overrides: Overrides; onEdit: (id: string, o: Override) => void }) {
  const [open, setOpen] = useState(false);
  const hidden = scanned.nodes.filter((n) => overrides[n.id]?.hidden);
  if (hidden.length === 0) return null;
  return (
    <div className="relative">
      <button onClick={() => setOpen((o) => !o)} aria-expanded={open} className="flex items-center gap-1.5 rounded-lg border border-line bg-surface/80 px-2.5 py-1.5 text-xs text-ink-dim hover:text-ink"><EyeOff size={13} aria-hidden /> {hidden.length} hidden</button>
      {open && (
        <ul role="dialog" aria-label="Hidden parts" className="absolute right-0 top-full z-40 mt-2 w-72 space-y-1 rounded-xl border border-line bg-surface p-2 text-xs shadow-2xl">
          {hidden.map((n) => (
            <li key={n.id} className="flex items-center gap-2 rounded-lg bg-raised px-2.5 py-1.5">
              <span className="min-w-0 flex-1 truncate">{overrides[n.id]?.label ?? n.label}</span>
              <button onClick={() => onEdit(n.id, { ...overrides[n.id], hidden: false })} className="flex items-center gap-1 text-accent hover:underline"><RotateCcw size={12} aria-hidden /> Show</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
