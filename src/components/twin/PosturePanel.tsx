"use client";

import { Loader2, ScanLine, TriangleAlert } from "lucide-react";
import { posture as computePosture } from "@/lib/security/map";
import { CATEGORIES, type Category, type Finding, type FindingSet } from "@/lib/security/types";
import { CATEGORY_LABEL, FindingRow, GradeRing, SeverityBar } from "./securityUi";

/** The at-a-glance card: grade, severity mix, category filter that recolours the map, and the few things to fix first. */
export function PosturePanel({ set, filter, onFilter, visible, onOpen, onScan, scanning, scanError }: {
  set: FindingSet | null; filter: Category | null; onFilter: (c: Category | null) => void; visible: Finding[];
  onOpen: (f: Finding) => void; onScan: () => void; scanning: boolean; scanError: string | null;
}) {
  const p = computePosture(set?.findings ?? [], !!set);
  const top = visible.slice(0, 5);
  return (
    <div className="absolute left-4 top-[7.2rem] z-10 flex max-h-[calc(100%-13rem)] w-80 flex-col gap-3 overflow-y-auto rounded-xl border border-line bg-surface/92 p-3 text-xs backdrop-blur" aria-label="Security posture">
      <div className="flex items-center gap-3">
        {set ? <GradeRing posture={p} /> : <div className="grid h-16 w-16 shrink-0 place-items-center rounded-full border-2 border-dashed border-line text-ink-faint">?</div>}
        <div className="min-w-0">
          <div className="text-sm font-semibold text-ink">{set ? p.headline : "No security scan yet"}</div>
          {set && <div className="mt-0.5 text-ink-faint">Scanned commit <span className="font-mono">{set.sha.slice(0, 7)}</span> · {new Date(set.scannedAt).toLocaleString()}</div>}
        </div>
      </div>

      {set && <SeverityBar counts={p.counts} />}

      {set && (
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter the map by kind of finding">
          {CATEGORIES.map((c) => (
            <button key={c} onClick={() => onFilter(filter === c ? null : c)} aria-pressed={filter === c} disabled={!p.byCategory[c]}
              className={`rounded-full border px-2.5 py-1 text-[11px] disabled:opacity-40 ${filter === c ? "border-accent bg-accent/15 text-accent" : "border-line text-ink-dim hover:text-ink"}`}>
              {CATEGORY_LABEL[c]} <span className="font-mono">{p.byCategory[c]}</span>
            </button>
          ))}
        </div>
      )}

      {top.length > 0 && (
        <section>
          <h3 className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-ink-faint">Fix first</h3>
          <div className="space-y-1.5">{top.map((f) => <FindingRow key={f.id} f={f} onOpen={onOpen} />)}</div>
        </section>
      )}

      {set?.warnings.map((w) => <p key={w} className="flex gap-1.5 text-degraded"><TriangleAlert size={12} className="mt-0.5 shrink-0" aria-hidden />{w}</p>)}
      {scanError && <p role="alert" className="text-failing">{scanError}</p>}

      <button onClick={onScan} disabled={scanning} className="flex items-center justify-center gap-2 rounded-lg bg-accent/15 px-3 py-2 text-sm font-medium text-accent hover:bg-accent/25 disabled:opacity-60">
        {scanning ? <Loader2 size={14} className="animate-spin" aria-hidden /> : <ScanLine size={14} aria-hidden />}
        {scanning ? "Scanning…" : set ? "Scan again" : "Run security scan"}
      </button>
      <p className="text-[11px] leading-snug text-ink-faint">Tile colour is the worst finding inside it. The number is its safety score (100 = nothing found). Findings are visible to people with write access only.</p>
    </div>
  );
}
