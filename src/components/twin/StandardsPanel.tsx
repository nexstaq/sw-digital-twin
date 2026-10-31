"use client";

import { useMemo, useState } from "react";
import { cweSummary, owaspSummary } from "@/lib/security/owasp";
import type { Finding } from "@/lib/security/types";
import { FindingRow, SEV } from "./securityUi";

const SHORT: Record<string, string> = { A01: "Access control", A02: "Cryptography", A03: "Injection", A04: "Insecure design", A05: "Misconfiguration", A06: "Vulnerable components", A07: "Authentication", A08: "Integrity", A09: "Logging & monitoring", A10: "SSRF" };

/** The findings grouped the way auditors and security teams ask for them. Categories no scan can judge say so instead of looking clean. */
export function StandardsPanel({ findings, onOpen, newIds }: { findings: Finding[]; onOpen: (f: Finding) => void; newIds: Set<string> }) {
  const { rows, unmapped } = useMemo(() => owaspSummary(findings), [findings]);
  const cwes = useMemo(() => cweSummary(findings, 8), [findings]);
  const [open, setOpen] = useState<string | null>(null);
  const byId = useMemo(() => new Map(findings.map((f) => [f.id, f])), [findings]);
  const sel = rows.find((r) => r.id === open);

  return (
    <details className="rounded-lg border border-line bg-raised/60 p-2.5" aria-label="Standards">
      <summary className="cursor-pointer select-none text-[11px] font-medium uppercase tracking-wider text-ink-faint">Standards · OWASP Top 10 (2021)</summary>
      <div className="mt-2 grid grid-cols-2 gap-1.5" role="group" aria-label="OWASP Top 10 categories">
        {rows.map((r) => {
          const tone = !r.assessed ? "border-dashed border-line text-ink-faint" : r.worst === "critical" || r.worst === "high" ? "border-failing/60 bg-failing/10 text-ink" : r.worst ? "border-degraded/60 bg-degraded/10 text-ink" : "border-line bg-surface text-ink-dim";
          return (
            <button key={r.id} onClick={() => setOpen(open === r.id ? null : r.id)} disabled={!r.total} aria-pressed={open === r.id}
              aria-label={`${r.id} ${r.name}: ${!r.assessed ? "not assessed" : r.total ? `${r.total} finding${r.total === 1 ? "" : "s"}, worst ${r.worst}` : "none found"}`}
              className={`rounded-lg border px-2 py-1.5 text-left text-[11px] leading-tight ${tone} ${r.total ? "hover:ring-1 hover:ring-accent/50" : "cursor-default"} ${open === r.id ? "ring-1 ring-accent" : ""}`}>
              <span className="flex items-center justify-between gap-1"><span className="font-mono font-semibold">{r.id}</span>{r.worst && <span className={`h-2 w-2 rounded-full ${SEV[r.worst].bar}`} aria-hidden />}</span>
              <span className="mt-0.5 block truncate">{SHORT[r.id]}</span>
              <span className="mt-0.5 block text-[10px] text-ink-faint">{!r.assessed ? "Not assessed" : r.total ? `${r.total} found` : "None found"}</span>
            </button>
          );
        })}
      </div>

      {sel && (
        <div className="mt-2 space-y-1.5" aria-label={`Findings in ${sel.id}`}>
          <p className="text-[11px] leading-snug text-ink-dim"><span className="font-medium text-ink">{sel.id} {sel.name}.</span> Checked here: {sel.how}.</p>
          {sel.findings.slice(0, 8).map((id) => { const f = byId.get(id); return f ? <FindingRow key={id} f={f} onOpen={onOpen} isNew={newIds.has(id)} /> : null; })}
          {sel.findings.length > 8 && <p className="text-[11px] text-ink-faint">and {sel.findings.length - 8} more</p>}
        </div>
      )}

      <p className="mt-2 text-[10.5px] leading-snug text-ink-faint">
        “Not assessed” means a scan of the repository cannot judge it (design review, operations); it does not mean fine. “None found” means these checks passed, not that the category is proven safe.{unmapped ? ` ${unmapped} finding${unmapped === 1 ? "" : "s"} carry no OWASP category.` : ""}
      </p>

      {cwes.length > 0 && (
        <div className="mt-2" aria-label="Most common weaknesses">
          <div className="mb-1 text-[10.5px] uppercase tracking-wider text-ink-faint">Most common weaknesses (CWE)</div>
          <div className="flex flex-wrap gap-1.5">
            {cwes.map((c) => (
              <a key={c.cwe} href={`https://cwe.mitre.org/data/definitions/${c.cwe.slice(4)}.html`} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1.5 rounded-full border border-line px-2 py-0.5 font-mono text-[10.5px] text-ink-dim hover:text-ink">
                {c.cwe}<span className="text-ink-faint">×{c.count}</span><span className={`h-1.5 w-1.5 rounded-full ${SEV[c.worst].bar}`} aria-hidden /><span className="sr-only">worst {c.worst}</span>
              </a>
            ))}
          </div>
        </div>
      )}
    </details>
  );
}
