"use client";

import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { ArrowLeft, Check, Loader2, Lock } from "lucide-react";

interface Model { id: string; label: string; short: string; description: string }
interface View { id: string; label: string; covers: string; default: string; allowed: string[]; fixedBecause?: string; model: string }
interface Payload { models: Model[]; views: View[] }

const subscribe = () => () => {};
const repoFromUrl = () => new URLSearchParams(window.location.search).get("repo");

function Shell({ children }: { children: React.ReactNode }) {
  return <main className="mx-auto w-full max-w-3xl px-6 py-10">{children}</main>;
}

/** One row per view: who may open it. Only maintainers reach this page, and every change is checked again on the server. */
export function AccessSettings() {
  const repo = useSyncExternalStore(subscribe, repoFromUrl, () => null);
  const [data, setData] = useState<Payload | null>(null);
  const [error, setError] = useState<{ status: number; text: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  const load = useCallback(async (r: string) => {
    const res = await fetch(`/api/settings/access?repo=${encodeURIComponent(r)}`, { cache: "no-store" });
    const d = (await res.json().catch(() => null)) as (Payload & { error?: string }) | null;
    if (!res.ok || !d) { setError({ status: res.status, text: d?.error ?? `That failed (${res.status}).` }); return; }
    setError(null); setData(d);
  }, []);
  useEffect(() => { if (repo) void load(repo); }, [repo, load]); // eslint-disable-line react-hooks/set-state-in-effect

  const choose = async (view: string, model: string) => {
    if (!repo) return;
    setBusy(view); setSaved(null);
    try {
      const res = await fetch("/api/settings/access", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ repo, view, model }) });
      const d = (await res.json().catch(() => null)) as (Payload & { error?: string }) | null;
      if (!res.ok || !d) setError({ status: res.status, text: d?.error ?? `That failed (${res.status}).` });
      else { setError(null); setData(d); setSaved(view); }
    } catch { setError({ status: 0, text: "Could not reach the service." }); } finally { setBusy(null); }
  };

  const back = repo ? `/scan?repo=${encodeURIComponent(repo)}` : "/repos";
  if (!repo) return <Shell><h1 className="text-xl font-semibold">Access settings</h1><p className="mt-2 text-ink-dim">Open this page from a repository&apos;s map, so it knows which repository you mean.</p></Shell>;
  if (error && !data) {
    return (
      <Shell>
        <h1 className="text-xl font-semibold">Access settings are for maintainers</h1>
        <p role="alert" className="mt-2 text-ink-dim">{error.text}</p>
        {error.status === 401 && <p className="mt-4"><a className="rounded-xl bg-accent px-4 py-2 text-sm font-medium text-void" href={`/signin?returnTo=${encodeURIComponent(`/settings?repo=${repo}`)}`}>Sign in with GitHub</a></p>}
      </Shell>
    );
  }
  if (!data) return <Shell><Loader2 className="animate-spin text-ink-dim" aria-label="Loading" /></Shell>;

  return (
    <Shell>
      <a href={back} className="inline-flex items-center gap-1.5 text-sm text-ink-dim hover:text-ink"><ArrowLeft size={14} aria-hidden /> Back to the map</a>
      <h1 className="mt-4 text-2xl font-semibold">Who can see what</h1>
      <p className="mt-1 font-mono text-sm text-ink-dim">{repo}</p>
      <p className="mt-3 max-w-xl text-sm leading-relaxed text-ink-dim">Choose, for each view, who may open it. This only ever narrows access: GitHub still decides who can read the repository at all, and a share link you create on purpose keeps working.</p>
      {error && <p role="alert" className="mt-3 text-sm text-failing">{error.text}</p>}

      <ul className="mt-6 space-y-3">
        {data.views.map((v) => {
          const fixed = v.allowed.length < 2;
          return (
            <li key={v.id} data-view={v.id} className="rounded-2xl border border-line bg-surface p-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <h2 className="font-medium">{v.label}</h2>
                  <p className="mt-0.5 text-sm text-ink-dim">{v.covers}</p>
                </div>
                {fixed ? (
                  <span className="flex items-center gap-1.5 rounded-lg border border-line px-2.5 py-1.5 text-sm text-ink-dim"><Lock size={13} aria-hidden /> {data.models.find((m) => m.id === v.model)?.short}</span>
                ) : (
                  <label className="flex items-center gap-2 text-sm">
                    <span className="sr-only">Who can open {v.label}</span>
                    <select value={v.model} disabled={busy === v.id} onChange={(e) => void choose(v.id, e.target.value)} aria-label={`Who can open ${v.label}`}
                      className="rounded-lg border border-line bg-void px-2.5 py-1.5 text-sm text-ink outline-none focus:border-accent">
                      {data.models.filter((m) => v.allowed.includes(m.id)).map((m) => <option key={m.id} value={m.id}>{m.label}{m.id === v.default ? " (default)" : ""}</option>)}
                    </select>
                  </label>
                )}
              </div>
              {fixed && v.fixedBecause && <p className="mt-2 text-xs leading-relaxed text-ink-faint">Fixed: {v.fixedBecause}</p>}
              {saved === v.id && <p role="status" className="mt-2 flex items-center gap-1.5 text-xs text-nominal"><Check size={12} aria-hidden /> Saved.</p>}
            </li>
          );
        })}
      </ul>
      <dl className="mt-8 space-y-2 text-xs leading-relaxed text-ink-faint">
        {data.models.map((m) => <div key={m.id}><dt className="inline font-medium text-ink-dim">{m.short}: </dt><dd className="inline">{m.description}</dd></div>)}
      </dl>
    </Shell>
  );
}
