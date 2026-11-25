"use client";

import { useState } from "react";
import { FileDiff, Loader2 } from "lucide-react";
import type { Finding } from "@/lib/security/types";
import { SIM, SimBadge } from "./securityUi";

type Patch = { id: string; state: "loading" } | { id: string; state: "ok"; diff: string; kind: string; retest: string } | { id: string; state: "error"; message: string };

const KIND: Record<string, string> = { "parameterise-query": "Use placeholders instead of pasting values into the query", "confine-path": "Reduce the request's value to a plain file name" };

/** What the simulation concluded about one finding, and the evidence behind it. The patch is fetched when asked for and never kept. */
export function SimulationDetail({ f, repo }: { f: Finding; repo: string }) {
  const [patch, setPatch] = useState<Patch | null>(null);
  const s = f.simulation;
  if (!s) return null;
  const mine = patch?.id === f.id ? patch : null;
  const load = async () => {
    setPatch({ id: f.id, state: "loading" });
    try {
      const r = await fetch(`/api/security/simulate/patch?repo=${encodeURIComponent(repo)}&finding=${encodeURIComponent(f.id)}`, { cache: "no-store" });
      const d = (await r.json()) as { diff?: string; kind?: string; retest?: string; error?: string };
      setPatch(r.ok && d.diff ? { id: f.id, state: "ok", diff: d.diff, kind: d.kind ?? "", retest: d.retest ?? "" } : { id: f.id, state: "error", message: d.error ?? "Could not make the patch." });
    } catch { setPatch({ id: f.id, state: "error", message: "Could not reach the server." }); }
  };

  return (
    <section aria-label="Simulation" className="space-y-3 rounded-lg border border-accent/30 bg-accent/5 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-[11px] font-medium uppercase tracking-wider text-ink-faint">Simulation</h3>
        <SimBadge sim={s} />
        <span className="text-[10.5px] text-ink-faint">
          {s.by === "graybox" ? "tested from the outside, with an account" : s.by === "redteam" ? "reachability checked from the public surface, with no credentials" : "tested with knowledge of the findings"}
        </span>
      </div>
      <p className="leading-relaxed text-ink">{s.summary}</p>
      {s.reaches.length > 0 && <p className="text-xs text-ink-dim"><span className="text-ink">Reaches:</span> {s.reaches.join(", ")}</p>}
      {s.source.mitigation && <p className="text-xs text-ink-dim"><span className="text-ink">Seen in the code:</span> {s.source.mitigation}.</p>}

      {s.test && (
        <details className="text-xs text-ink-dim">
          <summary className="cursor-pointer select-none text-ink-faint">The test ({s.test.steps.length} requests to the simulated copy)</summary>
          <ol className="mt-1.5 space-y-1.5">
            {s.test.steps.map((t) => (
              <li key={t.name} className="rounded bg-surface px-2 py-1.5">
                <span className="font-medium text-ink">{t.name}</span> · <code className="font-mono text-[11px]">{t.request.method} {t.request.path}</code> as {t.request.role}{t.request.payloadClass ? ` with a ${t.request.payloadClass} payload` : ""}
                <span className="block text-ink-faint">expect: {t.expect}</span>
              </li>
            ))}
          </ol>
        </details>
      )}

      {s.patch && (
        <div className="space-y-2">
          <p className="text-xs text-ink-dim"><span className="text-ink">A patch was proposed:</span> {KIND[s.patch.kind] ?? s.patch.kind}. The same test, run against a copy of the simulation with this weakness removed, was {s.patch.retest === "rejected" ? "refused" : "still accepted"}. That shows the test tells the two apart, not that the patch is correct.</p>
          {!mine ? (
            <button onClick={() => void load()} className="flex items-center gap-1.5 rounded-lg border border-line px-2.5 py-1.5 text-xs text-ink-dim hover:text-ink"><FileDiff size={13} aria-hidden /> Show the proposed patch</button>
          ) : mine.state === "loading" ? (
            <p role="status" className="flex items-center gap-1.5 text-xs text-ink-dim"><Loader2 size={13} className="animate-spin" aria-hidden /> Reading the file…</p>
          ) : mine.state === "error" ? (
            <p role="alert" className="text-xs text-degraded">{mine.message}</p>
          ) : (
            <div>
              <pre aria-label="Proposed patch" className="overflow-x-auto rounded-lg border border-line bg-void py-1.5 font-mono text-[11.5px] leading-relaxed">
                {mine.diff.split("\n").map((l, i) => (
                  <div key={i} className={`whitespace-pre px-3 ${l.startsWith("+") && !l.startsWith("+++") ? "bg-nominal/15 text-ink" : l.startsWith("-") && !l.startsWith("---") ? "bg-failing/15 text-ink" : "text-ink-dim"}`}>{l || " "}</div>
                ))}
              </pre>
              <p className="mt-1 text-[11px] text-ink-faint">Shown for you to read. Nothing was changed, nothing is stored, and nothing is pushed. Use the placeholder style your database driver expects.</p>
            </div>
          )}
        </div>
      )}

      <p className="text-[11px] leading-snug text-ink-faint">
        {s.source.read ? "A few lines of source were read for this." : "Source was not read."} This comes from a simulated copy built from the scan&apos;s own findings, so it shows whether an outside request can reach this weakness and what it then reaches. It does not independently prove the code is vulnerable.
        {" "}Evidence: audit steps {s.steps.map((n) => `#${n}`).join(" ")} of run <span className="font-mono">{s.runId}</span>.
      </p>
      <span className="sr-only">{SIM[s.verdict].label}</span>
    </section>
  );
}
