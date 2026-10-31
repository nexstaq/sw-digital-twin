"use client";

import { useEffect, useState } from "react";
import { ExternalLink, Loader2, Locate, Sparkles, X } from "lucide-react";
import type { Finding } from "@/lib/security/types";
import { CATEGORY_LABEL, SeverityBadge, isRepoFile, sourceLabel, where } from "./securityUi";

type Explained = { id: string; state: "loading" } | { id: string; state: "ok"; e: { summary: string; attack: string; steps: string[]; effort: string; model: string } } | { id: string; state: "off"; message: string };
interface Snippet { sha: string; highlight: number; lines: { n: number; text: string }[]; redacted?: string }

/** The deep dive: where it is, why it matters, how to fix it, and the actual lines (fetched now, never stored). */
export function FindingPanel({ finding: f, repo, sha, onClose, onLocate }: { finding: Finding; repo: string; sha: string; onClose: () => void; onLocate: () => void }) {
  const [snip, setSnip] = useState<{ id: string; data?: Snippet; error?: string } | null>(null);
  const [ai, setAi] = useState<Explained | null>(null);
  const line = f.line;

  useEffect(() => {
    if (!line || !isRepoFile(f.path)) return;
    const ctl = new AbortController();
    fetch(`/api/security/snippet?repo=${encodeURIComponent(repo)}&path=${encodeURIComponent(f.path)}&line=${line}`, { signal: ctl.signal, cache: "no-store" })
      .then(async (r) => (r.ok ? { id: f.id, data: (await r.json()) as Snippet } : { id: f.id, error: ((await r.json().catch(() => null)) as { error?: string } | null)?.error ?? "Could not load the code." }))
      .then(setSnip)
      .catch((e) => { if (!ctl.signal.aborted) setSnip({ id: f.id, error: e instanceof Error ? e.message : "Could not load the code." }); });
    return () => ctl.abort();
  }, [repo, f.id, f.path, line]);

  const mine = snip?.id === f.id ? snip : null; // never flash the previous finding's code
  const explained = ai?.id === f.id ? ai : null;
  const explain = async () => {
    setAi({ id: f.id, state: "loading" });
    try {
      const r = await fetch("/api/security/explain", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ repo, findingId: f.id }) });
      const d = (await r.json()) as { ok?: boolean; explanation?: { summary: string; attack: string; steps: string[]; effort: string; model: string }; message?: string; error?: string };
      setAi(d.ok && d.explanation ? { id: f.id, state: "ok", e: d.explanation } : { id: f.id, state: "off", message: d.message ?? d.error ?? "Could not explain this." });
    } catch { setAi({ id: f.id, state: "off", message: "Could not reach the explanation service." }); }
  };
  const d = f.detail;
  const file = isRepoFile(f.path);
  const gh = `https://github.com/${repo}/blob/${sha}/${f.path.split("/").map(encodeURIComponent).join("/")}${line ? `#L${line}` : ""}`;
  const from = sourceLabel(d.source, d.sourceName);
  const alsoBy = (d.alsoReportedBy ?? []).map((x) => sourceLabel(x));
  const ext = d.url && /^https:\/\//.test(d.url) ? d.url : undefined;

  return (
    <aside role="dialog" aria-label={`Finding: ${f.title}`} className="absolute bottom-3 right-3 top-3 z-40 flex w-[480px] max-w-[calc(100%-1.5rem)] flex-col overflow-hidden rounded-2xl border border-line bg-surface/98 shadow-2xl backdrop-blur">
      <header className="flex items-start gap-3 border-b border-line p-4">
        <div className="min-w-0 flex-1 space-y-1.5">
          <div className="flex flex-wrap items-center gap-1.5">
            <SeverityBadge severity={f.severity} />
            <span className="rounded-full border border-line px-2 py-0.5 text-[11px] text-ink-dim">{CATEGORY_LABEL[f.category]}</span>
            <span className="rounded-full border border-line px-2 py-0.5 text-[11px] text-ink-dim">{f.confidence} confidence</span>
            {f.detail.dev && <span className="rounded-full border border-line px-2 py-0.5 text-[11px] text-ink-dim">dev tool only</span>}
          </div>
          <h2 className="text-base font-semibold leading-snug">{f.title}</h2>
        </div>
        <button onClick={onClose} aria-label="Close finding" className="rounded p-1 text-ink-dim hover:bg-raised hover:text-ink"><X size={16} /></button>
      </header>

      <div className="flex-1 space-y-5 overflow-y-auto p-4 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          {file
            ? <a href={gh} target="_blank" rel="noopener noreferrer" className="flex min-w-0 items-center gap-1.5 rounded-lg bg-raised px-2.5 py-1.5 font-mono text-xs text-ink-dim hover:text-ink"><span className="truncate">{where(f)}</span><ExternalLink size={12} aria-hidden /><span className="sr-only">(opens GitHub)</span></a>
            : <span className="flex min-w-0 items-center gap-1.5 rounded-lg bg-raised px-2.5 py-1.5 font-mono text-xs text-ink-dim"><span className="truncate">{where(f)}</span></span>}
          {file && <button onClick={onLocate} className="flex items-center gap-1.5 rounded-lg border border-line px-2.5 py-1.5 text-xs text-ink-dim hover:text-ink"><Locate size={12} aria-hidden /> Show on map</button>}
        </div>

        {(from || alsoBy.length > 0) && (
          <p className="text-xs text-ink-dim" aria-label="Where this finding came from">
            {from && <>Reported by <span className="text-ink">{from}</span>.</>}{alsoBy.length > 0 && <> Also confirmed by <span className="text-ink">{alsoBy.join(", ")}</span>.</>}
            {ext && <> <a href={ext} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">Open it there</a>.</>}
          </p>
        )}

        {line && (
          <section aria-label="Code">
            <h3 className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-ink-faint">The code</h3>
            {!mine ? <p className="text-xs text-ink-faint">Loading the lines from GitHub…</p>
              : mine.error ? <p role="alert" className="text-xs text-degraded">{mine.error}</p>
              : (
                <>
                  <pre className="overflow-x-auto rounded-lg border border-line bg-void p-0 font-mono text-[11.5px] leading-relaxed">
                    {mine.data!.lines.map((l) => (
                      <div key={l.n} className={`flex gap-3 px-3 ${l.n === mine.data!.highlight ? "bg-failing/15" : ""}`}>
                        <span className="w-8 shrink-0 select-none text-right text-ink-faint">{l.n}</span>
                        <code className={`whitespace-pre ${l.n === mine.data!.highlight ? "text-ink" : "text-ink-dim"}`}>{l.text || " "}</code>
                      </div>
                    ))}
                  </pre>
                  {mine.data!.redacted && <p className="mt-1 text-[11px] text-ink-faint">{mine.data!.redacted}</p>}
                </>
              )}
          </section>
        )}

        <section aria-label="AI explanation">
          {!explained ? (
            <button onClick={() => void explain()} className="flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent hover:bg-accent/20"><Sparkles size={13} aria-hidden /> Explain this in plain English</button>
          ) : explained.state === "loading" ? (
            <p className="flex items-center gap-1.5 text-xs text-ink-dim" role="status"><Loader2 size={13} className="animate-spin" aria-hidden /> Writing an explanation…</p>
          ) : explained.state === "off" ? (
            <p role="alert" className="rounded-lg bg-degraded/10 px-3 py-2 text-xs leading-relaxed text-degraded">{explained.message}</p>
          ) : (
            <div className="space-y-3 rounded-lg border border-accent/30 bg-accent/5 p-3 text-sm">
              <p className="flex flex-wrap items-center gap-x-2 text-[11px] text-ink-faint"><Sparkles size={11} aria-hidden /> AI-written ({explained.e.model}) from this finding&apos;s facts. It has not read your code. Check before acting.</p>
              <p className="leading-relaxed text-ink">{explained.e.summary}</p>
              <div><h4 className="text-[11px] font-medium uppercase tracking-wider text-ink-faint">How it could be abused here</h4><p className="mt-0.5 leading-relaxed text-ink-dim">{explained.e.attack}</p></div>
              <div>
                <h4 className="text-[11px] font-medium uppercase tracking-wider text-ink-faint">Steps · about {explained.e.effort}</h4>
                <ol className="mt-0.5 list-decimal space-y-1 pl-5 text-ink-dim">{explained.e.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
              </div>
            </div>
          )}
        </section>

        <section><h3 className="mb-1 text-[11px] font-medium uppercase tracking-wider text-ink-faint">Why it matters</h3><p className="leading-relaxed text-ink-dim">{f.reason}</p></section>
        <section><h3 className="mb-1 text-[11px] font-medium uppercase tracking-wider text-ink-faint">How to fix it</h3><p className="leading-relaxed text-ink-dim">{f.fix}</p></section>

        {d.vulns && d.vulns.length > 0 && (
          <section>
            <h3 className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-ink-faint">Known vulnerabilities in {d.package}@{d.version}</h3>
            <ul className="space-y-1.5">
              {d.vulns.map((v) => (
                <li key={v.id} className="rounded-lg bg-raised p-2.5 text-xs">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <SeverityBadge severity={v.severity} />
                    <a href={v.url} target="_blank" rel="noopener noreferrer" className="font-mono text-accent hover:underline">{v.aliases[0] ?? v.id}</a>
                    {v.score !== undefined && <span className="font-mono text-ink-faint">CVSS {v.score}</span>}
                    {v.fixedIn.length > 0 && <span className="text-nominal">fixed in {v.fixedIn.join(", ")}</span>}
                  </div>
                  <p className="mt-1 text-ink-dim">{v.summary}</p>
                </li>
              ))}
            </ul>
            {d.via && d.via.length > 0 && (
              <div className="mt-2" aria-label="How it got into your project">
                <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-ink-faint">How it got into your project</div>
                <ol className="flex flex-wrap items-center gap-1 text-xs">
                  {[...d.via, `${d.package}`].map((n, i, all) => (
                    <li key={`${i}-${n}`} className="flex items-center gap-1">
                      <span className={`rounded-md px-2 py-0.5 font-mono ${i === all.length - 1 ? "bg-failing/15 text-failing" : "bg-raised text-ink-dim"}`}>{n}</span>
                      {i < all.length - 1 && <span className="text-ink-faint" aria-hidden>→</span>}
                    </li>
                  ))}
                </ol>
              </div>
            )}
            {d.usedIn !== undefined && (
              <p className="mt-2 text-xs text-ink-dim">{d.usedIn.length ? <>Imported by your code in <span className="font-mono">{d.usedIn.join(", ")}</span>.</> : "No import of it was found in your source."}</p>
            )}
          </section>
        )}

        {d.secretKind && (
          <section className="rounded-lg border border-line bg-raised p-2.5 text-xs text-ink-dim">
            <div>Type: <span className="text-ink">{d.secretKind}</span> · starts with <span className="font-mono text-ink">{d.masked}</span></div>
            <div className="mt-1 text-ink-faint">The value itself is never stored or shown by Mission Control.</div>
          </section>
        )}

        {(f.cwe.length > 0 || f.owasp) && (
          <section>
            <h3 className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-ink-faint">Standards</h3>
            <div className="flex flex-wrap gap-1.5 text-xs">
              {f.cwe.map((c) => <a key={c} href={`https://cwe.mitre.org/data/definitions/${c.replace(/\D/g, "")}.html`} target="_blank" rel="noopener noreferrer" className="rounded-full border border-line px-2 py-0.5 font-mono text-ink-dim hover:text-ink">{c}</a>)}
              {f.owasp && <span className="rounded-full border border-line px-2 py-0.5 text-ink-dim">OWASP {f.owasp}</span>}
            </div>
          </section>
        )}
      </div>
    </aside>
  );
}
