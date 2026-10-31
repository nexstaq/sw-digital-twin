"use client";

import { useCallback, useEffect, useState } from "react";
import { Check, Copy, Globe, Loader2, ShieldCheck, Trash2 } from "lucide-react";
import type { DomainEntry } from "@/lib/security/types";

type Entry = DomainEntry & { instructions: { dns: { type: string; name: string; value: string }; file: { url: string; contents: string } } };
type Msg = { ok: boolean; text: string; reasons?: string[] } | null;

function Copyable({ label, value }: { label: string; value: string }) {
  const [done, setDone] = useState(false);
  return (
    <button onClick={async () => { try { await navigator.clipboard.writeText(value); setDone(true); setTimeout(() => setDone(false), 1500); } catch { /* the value is on screen to select */ } }}
      aria-label={`Copy ${label}`} className="flex w-full items-center gap-1.5 rounded bg-void px-2 py-1 text-left font-mono text-[10.5px] text-ink-dim hover:text-ink">
      {done ? <Check size={11} className="shrink-0" aria-hidden /> : <Copy size={11} className="shrink-0" aria-hidden />}<span className="break-all">{value}</span>
    </button>
  );
}

/**
 * Passive checks of a live site: TLS, security headers, cookies, a handful of well-known files, email DNS. Nothing is sent to a domain
 * until the person has proved they own it, and that proof is repeated on every run.
 */
export function PassiveChecks({ repo, onChanged }: { repo: string; onChanged: () => void }) {
  const [list, setList] = useState<Entry[] | null>(null);
  const [domain, setDomain] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<Msg>(null);
  const q = encodeURIComponent(repo);

  const load = useCallback(async () => {
    const r = await fetch(`/api/security/domains?repo=${q}`, { cache: "no-store" });
    if (r.ok) setList(((await r.json()) as { domains: Entry[] }).domains);
  }, [q]);
  useEffect(() => { void load(); }, [load]); // eslint-disable-line react-hooks/set-state-in-effect

  const call = async (action: "add" | "verify" | "check", d: string) => {
    setBusy(`${action}:${d}`); setMsg(null);
    try {
      const r = await fetch("/api/security/domains", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ repo, action, domain: d }) });
      const data = (await r.json().catch(() => null)) as { error?: string; reasons?: string[]; verified?: boolean; via?: string; checked?: boolean; findings?: number; requests?: number; notes?: string[] } | null;
      if (action === "verify" && r.ok) {
        setMsg(data?.verified ? { ok: true, text: `Ownership confirmed (${data.via === "dns" ? "DNS record" : "file"}). You can run the checks now.` } : { ok: false, text: "We could not find the proof yet.", reasons: data?.reasons });
      } else if (!r.ok) setMsg({ ok: false, text: data?.error ?? `That failed (${r.status}).`, reasons: data?.reasons });
      else if (action === "check") setMsg({ ok: true, text: `Checked ${d}: ${data?.findings ?? 0} finding${data?.findings === 1 ? "" : "s"} from ${data?.requests ?? 0} ordinary requests.${data?.notes?.length ? ` ${data.notes.join(" ")}` : ""}` });
      await load();
      if (action === "check" && r.ok) onChanged();
      if (action === "add" && r.ok) setDomain("");
    } catch { setMsg({ ok: false, text: "Could not reach the service." }); } finally { setBusy(null); }
  };
  const remove = async (d: string) => {
    setBusy(`remove:${d}`); setMsg(null);
    const r = await fetch(`/api/security/domains?repo=${q}&domain=${encodeURIComponent(d)}`, { method: "DELETE" });
    setMsg(r.ok ? { ok: true, text: `Stopped testing ${d} and removed its findings.` } : { ok: false, text: "Could not remove it." });
    setBusy(null); await load(); onChanged();
  };

  return (
    <div className="mt-3 border-t border-line pt-3 text-[11px] leading-snug text-ink-dim" aria-label="Check your live site">
      <h4 className="flex items-center gap-1.5 font-medium text-ink"><Globe size={12} aria-hidden /> Check your live site</h4>
      <p className="mt-1">A short list of ordinary requests (about 25): the home page, the certificate, security headers, cookies, a few well-known file paths, and email DNS records. <span className="text-ink">No attacks, no logins, no guessing passwords.</span> We only test a domain after you prove you own it, and we prove it again each time.</p>

      <form onSubmit={(e) => { e.preventDefault(); if (domain.trim()) void call("add", domain.trim()); }} className="mt-2 flex gap-1.5">
        <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="staging.example.com" aria-label="Domain to check" spellCheck={false} maxLength={253}
          className="min-w-0 flex-1 rounded-md border border-line bg-void px-2 py-1 font-mono text-[11px] outline-none placeholder:text-ink-faint focus:border-accent" />
        <button disabled={!domain.trim() || !!busy} className="rounded-md bg-accent/15 px-2.5 py-1 font-medium text-accent disabled:opacity-50">Add</button>
      </form>

      {msg && (
        <div role={msg.ok ? "status" : "alert"} className={`mt-2 ${msg.ok ? "text-nominal" : "text-failing"}`}>
          <p>{msg.text}</p>
          {msg.reasons && <ul className="mt-0.5 list-disc space-y-0.5 pl-4 text-ink-faint">{msg.reasons.map((r) => <li key={r}>{r}</li>)}</ul>}
        </div>
      )}

      <ul className="mt-2 space-y-2">
        {(list ?? []).map((d) => (
          <li key={d.domain} data-domain={d.domain} className="rounded-md border border-line bg-surface p-2">
            <div className="flex items-center gap-2">
              <span className="min-w-0 flex-1 truncate font-mono text-ink">{d.domain}</span>
              {d.verifiedAt ? <span className="flex items-center gap-1 text-nominal"><ShieldCheck size={12} aria-hidden /> Ownership proven</span> : <span className="text-degraded">Not verified</span>}
              <button onClick={() => void remove(d.domain)} disabled={!!busy} aria-label={`Stop testing ${d.domain}`} className="text-ink-faint hover:text-failing"><Trash2 size={12} aria-hidden /></button>
            </div>
            {d.verifiedAt ? (
              <div className="mt-1.5 flex flex-wrap items-center gap-2">
                <button onClick={() => void call("check", d.domain)} disabled={!!busy} className="flex items-center gap-1.5 rounded-md bg-accent/15 px-2.5 py-1 font-medium text-accent hover:bg-accent/25 disabled:opacity-50">
                  {busy === `check:${d.domain}` ? <Loader2 size={11} className="animate-spin" aria-hidden /> : null} Run checks
                </button>
                {d.lastCheckAt && <span className="text-ink-faint">last run {new Date(d.lastCheckAt).toLocaleString()} · {d.lastCheckCount} finding{d.lastCheckCount === 1 ? "" : "s"}</span>}
              </div>
            ) : (
              <div className="mt-1.5 space-y-1.5" aria-label={`Prove you own ${d.domain}`}>
                <p>Prove you control <span className="font-mono text-ink">{d.domain}</span> with <span className="text-ink">one</span> of these:</p>
                <div><span className="text-ink">A.</span> Add a DNS <span className="font-mono">TXT</span> record named
                  <Copyable label="DNS record name" value={d.instructions.dns.name} /> with the value <Copyable label="DNS record value" value={d.instructions.dns.value} /></div>
                <div><span className="text-ink">B.</span> Or serve a file at <Copyable label="file address" value={d.instructions.file.url} /> containing exactly <Copyable label="file contents" value={d.instructions.file.contents} /></div>
                <button onClick={() => void call("verify", d.domain)} disabled={!!busy} className="flex items-center gap-1.5 rounded-md border border-line px-2.5 py-1 text-ink-dim hover:text-ink disabled:opacity-50">
                  {busy === `verify:${d.domain}` ? <Loader2 size={11} className="animate-spin" aria-hidden /> : null} Check ownership
                </button>
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
