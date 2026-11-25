"use client";

import { useState } from "react";
import { FlaskConical, Loader2, Square } from "lucide-react";
import type { FindingSet } from "@/lib/security/types";
import { SIM } from "./securityUi";

const WORD: Record<string, string> = { confirmed: "confirmed", mitigated: "look mitigated", unreachable: "not reachable", "not-reproduced": "not reproduced" };

/** "Verify by simulation": try each code finding against a simulated copy of the system. Needs a scan first; reads source only if asked. */
export function SimulationSection({ set, simulating, error, onSimulate, onStop }: { set: FindingSet; simulating: boolean; error: string | null; onSimulate: (source: boolean) => void; onStop: () => void }) {
  const [source, setSource] = useState(false);
  const last = set.simulated;
  const summary = last ? Object.entries(last.counts).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${WORD[k] ?? k}`).join(", ") : "";
  return (
    <section aria-label="Verify by simulation" className="space-y-2 rounded-lg border border-line bg-raised/60 p-2.5">
      <h3 className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-ink-faint"><FlaskConical size={12} aria-hidden /> Verify by simulation</h3>
      <p className="leading-snug text-ink-dim">Tries each code finding against a simulated copy of your system: can an outside request reach it, and what does it reach then? It also tests access control from the outside (roles, who owns what, sessions, attempt limits, steps) for weaknesses that imported reports describe. Nothing real is touched.</p>
      <label className="flex cursor-pointer items-start gap-2 text-[11px] leading-snug text-ink-dim">
        <input type="checkbox" checked={source} onChange={(e) => setSource(e.target.checked)} disabled={simulating} className="mt-0.5 accent-[var(--color-accent)]" />
        <span><span className="text-ink">Let it read the few lines around each finding.</span> It looks for protection already in the code and proposes patches as diffs to read. Read with your own GitHub access; not stored, not sent to an AI.</span>
      </label>
      <div className="flex items-center gap-2">
        <button onClick={() => onSimulate(source)} disabled={simulating} className="flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent hover:bg-accent/20 disabled:opacity-60">
          {simulating ? <Loader2 size={13} className="animate-spin" aria-hidden /> : <FlaskConical size={13} aria-hidden />}
          {simulating ? "Simulating…" : last ? "Verify again" : "Verify by simulation"}
        </button>
        {simulating && <button onClick={onStop} className="flex items-center gap-1 rounded-lg border border-line px-2.5 py-1.5 text-xs text-ink-dim hover:text-ink"><Square size={11} aria-hidden /> Stop</button>}
      </div>
      {error && <p role="alert" className="text-failing">{error}</p>}
      {last && !simulating && (
        <div role="status" className="space-y-1 text-[11px] leading-snug text-ink-dim">
          <p><span className="text-ink">Last run {new Date(last.at).toLocaleString()}:</span> {summary || "nothing could be exercised"}. {last.sourceRead ? "Source was read." : "Source was not read."}</p>
          {last.notes.map((n) => <p key={n} className="text-ink-faint">{n}</p>)}
          <ul className="flex flex-wrap gap-1.5 pt-0.5" aria-label="What the verdicts mean">
            {(Object.keys(SIM) as (keyof typeof SIM)[]).map((k) => <li key={k} className="flex items-center gap-1 text-ink-faint">{(() => { const I = SIM[k].Icon; return <I size={10} aria-hidden />; })()}{SIM[k].label}</li>)}
          </ul>
        </div>
      )}
      <p className="text-[11px] leading-snug text-ink-faint">A verdict is evidence, not proof: the simulation is built from this scan&apos;s own findings. It reorders the fix-first list; it never changes a severity or the score.</p>
    </section>
  );
}
