"use client";

import { useCallback, useEffect, useState } from "react";
import { Check, Copy, Link2, Trash2 } from "lucide-react";

interface Row { id: string; label?: string; createdBy: string; createdAt: number; revokedAt?: number }
interface Created { url: string; badge: string }

/** Read-only links (and a badge) that work without signing in. Only for people with push access. The link is shown once. */
export function SharePanel({ repo }: { repo: string }) {
  const [open, setOpen] = useState(false);
  const [rows, setRows] = useState<Row[]>([]);
  const [made, setMade] = useState<Created | null>(null);
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const q = `/api/shares?repo=${encodeURIComponent(repo)}`;

  const load = useCallback(async () => {
    const r = await fetch(q, { cache: "no-store" });
    if (r.ok) setRows(((await r.json()) as { shares: Row[] }).shares.filter((s) => !s.revokedAt));
  }, [q]);
  useEffect(() => { if (open) void load(); }, [open, load]); // eslint-disable-line react-hooks/set-state-in-effect

  const create = async () => {
    setBusy(true); setError(null);
    try {
      const r = await fetch(q, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ label: label.trim() || undefined }) });
      const d = (await r.json()) as Created & { error?: string };
      if (!r.ok) throw new Error(d.error ?? "Could not create the link.");
      setMade({ url: d.url, badge: d.badge }); setLabel(""); await load();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not create the link."); } finally { setBusy(false); }
  };
  const revoke = async (id: string) => {
    const r = await fetch(`${q}&id=${id}`, { method: "DELETE" });
    if (r.ok) { setMade(null); await load(); } else setError("Could not revoke that link.");
  };
  const copy = async (text: string, what: string) => {
    try { await navigator.clipboard.writeText(text); setCopied(what); setTimeout(() => setCopied(null), 1500); } catch { setError("Copy failed. Select the text and copy it."); }
  };
  const [now] = useState(() => Date.now()); // fixed at mount: relative ages need no live clock
  const ago = (t: number) => { const d = Math.round((now - t) / 86_400_000); return d < 1 ? "today" : `${d}d ago`; };

  return (
    <div className="relative">
      <button onClick={() => setOpen((o) => !o)} aria-expanded={open} className="flex items-center gap-1.5 rounded-lg border border-line bg-surface/80 px-2.5 py-1.5 text-xs text-ink-dim hover:text-ink"><Link2 size={13} aria-hidden /> Share</button>
      {open && (
        <div role="dialog" aria-label="Share this map" className="absolute right-0 top-full z-40 mt-2 w-80 space-y-3 rounded-xl border border-line bg-surface p-3 text-xs shadow-2xl">
          <p className="text-ink-dim">Anyone with a link sees this map and its live health, read-only, without signing in. Revoke a link and it stops working at once.</p>
          {made && (
            <div className="space-y-1.5 rounded-lg border border-accent/40 bg-accent/10 p-2">
              <p className="font-medium text-ink">Copy it now. It won&apos;t be shown again.</p>
              <button onClick={() => copy(made.url, "link")} className="flex w-full items-center gap-1.5 truncate rounded bg-raised px-2 py-1 text-left font-mono text-[11px]">{copied === "link" ? <Check size={12} /> : <Copy size={12} />}<span className="truncate">{made.url}</span></button>
              <button onClick={() => copy(`![launch status](${made.badge})`, "badge")} className="flex w-full items-center gap-1.5 rounded bg-raised px-2 py-1 text-left">{copied === "badge" ? <Check size={12} /> : <Copy size={12} />} Copy README badge (Markdown)</button>
            </div>
          )}
          <form onSubmit={(e) => { e.preventDefault(); void create(); }} className="flex gap-1.5">
            <input value={label} onChange={(e) => setLabel(e.target.value)} maxLength={60} placeholder="Who is it for? (optional)" aria-label="Link label" className="min-w-0 flex-1 rounded-lg border border-line bg-raised px-2.5 py-1.5 outline-none focus:border-accent" />
            <button disabled={busy} className="rounded-lg bg-accent px-3 py-1.5 font-medium text-void disabled:opacity-50">New link</button>
          </form>
          {rows.length > 0 && (
            <ul className="space-y-1">
              {rows.map((r) => (
                <li key={r.id} className="flex items-center gap-2 rounded-lg bg-raised px-2.5 py-1.5">
                  <span className="min-w-0 flex-1 truncate">{r.label || "Untitled link"} <span className="text-ink-faint">· {r.createdBy} · {ago(r.createdAt)}</span></span>
                  <button onClick={() => revoke(r.id)} aria-label={`Revoke ${r.label || "link"}`} className="text-ink-dim hover:text-failing"><Trash2 size={13} /></button>
                </li>
              ))}
            </ul>
          )}
          {error && <p role="alert" className="text-failing">{error}</p>}
        </div>
      )}
    </div>
  );
}
