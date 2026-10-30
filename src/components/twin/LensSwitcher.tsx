"use client";

import { Activity, Compass, GitBranch, LayoutGrid, ShieldAlert, type LucideIcon } from "lucide-react";
import { useTwin, type Lens } from "@/lib/store";

const LENSES: { id: Lens; label: string; hint: string; Icon: LucideIcon }[] = [
  { id: "overview", label: "Overview", hint: "Big picture for leaders", Icon: LayoutGrid },
  { id: "flow", label: "Flow", hint: "How code gets shipped", Icon: GitBranch },
  { id: "ops", label: "Ops", hint: "Only what needs attention", Icon: Activity },
  { id: "risk", label: "Risk", hint: "Security exposure", Icon: ShieldAlert },
  { id: "tour", label: "Tour", hint: "Guided walkthrough", Icon: Compass },
];

export function LensSwitcher() {
  const lens = useTwin((s) => s.lens);
  const setLens = useTwin((s) => s.setLens);
  return (
    <div role="tablist" aria-label="Lens" className="flex rounded-lg border border-line bg-surface p-0.5">
      {LENSES.map(({ id, label, hint, Icon }) => (
        <button
          key={id}
          role="tab"
          aria-selected={lens === id}
          title={hint}
          onClick={() => setLens(id)}
          className={`flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-[13px] transition-colors ${
            lens === id ? "bg-raised text-ink shadow-[inset_0_0_0_1px_var(--color-line)]" : "text-ink-dim hover:text-ink"
          }`}
        >
          <Icon size={14} aria-hidden />
          <span className="hidden md:inline">{label}</span>
        </button>
      ))}
    </div>
  );
}
