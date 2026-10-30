"use client";

import { useState } from "react";
import { ArrowRight, Crosshair, FileText, Loader2, ScanLine, TriangleAlert } from "lucide-react";
import { posture as computePosture } from "@/lib/security/map";
import { describeDelta } from "@/lib/security/trend";
import type { AttackPath } from "@/lib/security/paths";
import { CATEGORIES, type Category, type Finding, type FindingSet } from "@/lib/security/types";
import { CATEGORY_LABEL, FindingRow, GradeRing, SeverityBar, SeverityBadge, TrendLine } from "./securityUi";

/** The at-a-glance card: grade, severity mix, category filter that recolours the map, and the few things to fix first. */
/** One way in: where an outsider can knock, what is reachable from there, and what is wrong on the way. */
function PathCard({ p, label, active, onShow }: { p: AttackPath; label: (id: string) => string; active: boolean; onShow: (p: AttackPath) => void }) {
  return (
    <li className={`rounded-lg border p-2.5 ${active ? "border-failing/60 bg-failing/10" : "border-line bg-raised"}`}>
      <ol className="flex flex-wrap items-center gap-1 text-[11px]" aria-label="Attack path">
        {p.nodes.map((id, i) => (
          <li key={id} className="flex items-center gap-1">
            <span className={`max-w-[9rem] truncate rounded-md px-1.5 py-0.5 font-medium ${i === 0 ? "bg-failing/15 text-failing" : i === p.nodes.length - 1 ? "bg-accent/15 text-accent" : "bg-surface text-ink-dim"}`} title={label(id)}>{label(id)}</span>
            {i < p.nodes.length - 1 && <ArrowRight size={11} className="text-ink-faint" aria-hidden />}
          </li>
        ))}
      </ol>
      <ul className="mt-1.5 space-y-0.5 text-[11px] leading-snug text-ink-dim">{p.facts.slice(0, 3).map((f) => <li key={f}>{f}</li>)}</ul>
      <div className="mt-2 flex items-center gap-2">
        {p.worst && <SeverityBadge severity={p.worst} />}
        <span className="text-[10px] uppercase tracking-wide text-ink-faint">{p.kind === "pipeline" ? "via pipeline" : "via web"}</span>
        <button onClick={() => onShow(p)} className="ml-auto flex items-center gap-1 rounded-md border border-line px-2 py-0.5 text-[11px] text-ink-dim hover:text-ink"><Crosshair size={11} aria-hidden /> Show on map</button>
      </div>
    </li>
  );
}

export function PosturePanel({ repo, set, filter, onFilter, visible, onOpen, onScan, scanning, scanError, paths, label, activePath, onShowPath }: {
  set: FindingSet | null; filter: Category | null; onFilter: (c: Category | null) => void; visible: Finding[];
  onOpen: (f: Finding) => void; onScan: () => void; scanning: boolean; scanError: string | null; repo: string;
  paths: AttackPath[]; label: (id: string) => string; activePath: string | null; onShowPath: (p: AttackPath) => void;
}) {
  const [morePaths, setMorePaths] = useState(false);
  const p = computePosture(set?.findings ?? [], !!set);
  const top = visible.slice(0, 5);
  const newIds = new Set(set?.delta?.newIds ?? []);
  const better = set?.delta ? set.delta.fixed > set.delta.newIds.length : false, worse = set?.delta ? set.delta.newIds.length > set.delta.fixed : false;
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

      {set?.delta && <p className={`text-[11px] leading-snug ${better ? "text-nominal" : worse ? "text-failing" : "text-ink-dim"}`} aria-label="Change since the previous scan">{better ? "▲ " : worse ? "▼ " : "● "}{describeDelta(set.delta)}</p>}
      {set?.trend && set.trend.length > 1 && <div className="flex items-center gap-2 text-[11px] text-ink-faint"><TrendLine points={set.trend} /><span>score over the last {set.trend.length} scans</span></div>}

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
          <div className="space-y-1.5">{top.map((f) => <FindingRow key={f.id} f={f} onOpen={onOpen} isNew={newIds.has(f.id)} />)}</div>
        </section>
      )}

      {set && paths.length > 0 && (
        <section aria-label="Attack paths">
          <h3 className="mb-1 text-[11px] font-medium uppercase tracking-wider text-ink-faint">Attack paths · {paths.length}</h3>
          <p className="mb-1.5 text-[11px] leading-snug text-ink-faint">Routes from where an outsider can knock to what they could reach, using the map&apos;s real connections.</p>
          <ul className="space-y-1.5">{(morePaths ? paths : paths.slice(0, 3)).map((p) => <PathCard key={p.id} p={p} label={label} active={activePath === p.id} onShow={onShowPath} />)}</ul>
          {paths.length > 3 && !morePaths && <button onClick={() => setMorePaths(true)} className="mt-1.5 text-[11px] text-accent hover:underline">Show {paths.length - 3} more</button>}
        </section>
      )}
      {set && paths.length === 0 && set.exposure && <p className="text-[11px] leading-snug text-ink-faint">No attack path found: nothing risky sits on a route from the outside to your data. A missing connection in the map would also show as none.</p>}

      {set?.warnings.map((w) => <p key={w} className="flex gap-1.5 text-degraded"><TriangleAlert size={12} className="mt-0.5 shrink-0" aria-hidden />{w}</p>)}
      {scanError && <p role="alert" className="text-failing">{scanError}</p>}

      <button onClick={onScan} disabled={scanning} className="flex items-center justify-center gap-2 rounded-lg bg-accent/15 px-3 py-2 text-sm font-medium text-accent hover:bg-accent/25 disabled:opacity-60">
        {scanning ? <Loader2 size={14} className="animate-spin" aria-hidden /> : <ScanLine size={14} aria-hidden />}
        {scanning ? "Scanning…" : set ? "Scan again" : "Run security scan"}
      </button>
      {set && (
        <div aria-label="Reports" className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px]">
          <FileText size={12} className="text-ink-faint" aria-hidden />
          <a href={`/api/security/report?repo=${encodeURIComponent(repo)}&format=html`} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">Open report</a>
          <a href={`/api/security/report?repo=${encodeURIComponent(repo)}&format=html&download=1`} className="text-ink-dim hover:text-ink">Download HTML</a>
          <a href={`/api/security/report?repo=${encodeURIComponent(repo)}&format=sarif&download=1`} className="text-ink-dim hover:text-ink" title="For GitHub code scanning and other tools">SARIF</a>
        </div>
      )}
      <p className="text-[11px] leading-snug text-ink-faint">Tile colour is the worst finding inside it. The number is its safety score (100 = nothing found). Findings are visible to people with write access only.</p>
    </div>
  );
}
