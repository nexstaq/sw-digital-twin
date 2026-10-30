"use client";

import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { ArrowRight, GitBranch, Loader2, Lock, Plus, Search, TriangleAlert } from "lucide-react";
import type { RepoCard } from "@/lib/auth/github";
import { SessionButton } from "./SessionButton";
import { useSession } from "./useSession";

const ERRORS: Record<string, string> = {
  not_configured: "Sign-in isn't configured on this server yet.", denied: "GitHub sign-in was cancelled.", bad_state: "That sign-in link expired. Try again.",
  no_user: "GitHub didn't return your account.", exchange_failed: "GitHub sign-in failed. Try again.",
};
const ago = (iso?: string) => {
  if (!iso) return "";
  const d = Math.max(0, Date.now() - Date.parse(iso)) / 86_400_000;
  return d < 1 ? "today" : d < 30 ? `${Math.round(d)}d ago` : d < 365 ? `${Math.round(d / 30)}mo ago` : `${Math.round(d / 365)}y ago`;
};

/** Your repositories as cards (private ones locked), plus the "paste any public repo" path. */
export function RepoPicker() {
  const session = useSession();
  const [repos, setRepos] = useState<RepoCard[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [paste, setPaste] = useState("");
  const router = useRouter();
  // the callback puts ?auth_error=... on the URL; read it without a hydration mismatch (null on the server)
  const authCode = useSyncExternalStore(() => () => {}, () => new URLSearchParams(window.location.search).get("auth_error"), () => null);
  const authErr = authCode ? (ERRORS[authCode] ?? "Sign-in failed.") : null;

  const signedIn = !!session?.user;
  useEffect(() => {
    if (!signedIn) return;
    let live = true;
    fetch("/api/repos", { cache: "no-store" }).then(async (r) => { const d = await r.json(); if (!live) return; if (!r.ok) setErr(d.error ?? "Could not load your repositories."); else setRepos(d.repos); }).catch(() => live && setErr("Could not load your repositories."));
    return () => { live = false; };
  }, [signedIn]);

  const shown = useMemo(() => (repos ?? []).filter((r) => r.fullName.toLowerCase().includes(q.toLowerCase())), [repos, q]);
  const go = (repo: string) => router.push(`/scan?repo=${encodeURIComponent(repo)}`);

  return (
    <main className="mx-auto min-h-dvh max-w-5xl px-6 py-10">
      <header className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Your repositories</h1>
          <p className="mt-1 text-sm text-ink-dim">Pick one to see how it is built and run, and whether it is healthy.</p>
        </div>
        <SessionButton />
      </header>

      {authErr && <p role="alert" className="mt-6 flex gap-2 rounded-xl border border-degraded/50 bg-degraded/10 p-3 text-sm text-degraded"><TriangleAlert size={16} className="mt-0.5 shrink-0" />{authErr}</p>}

      <form onSubmit={(e) => { e.preventDefault(); if (paste.trim()) go(paste.trim()); }} className="mt-8 flex gap-2">
        <input value={paste} onChange={(e) => setPaste(e.target.value)} spellCheck={false} placeholder="Paste any public repo: owner/repo or a GitHub URL" aria-label="GitHub repository"
          className="min-w-0 flex-1 rounded-xl border border-line bg-surface px-4 py-3 font-mono text-sm outline-none placeholder:text-ink-faint focus:border-accent" />
        <button disabled={!paste.trim()} className="flex items-center gap-2 rounded-xl bg-accent px-4 py-3 text-sm font-medium text-void disabled:opacity-50"><ArrowRight size={16} />Map it</button>
      </form>

      {session && !session.user && session.configured && (
        <section className="mt-10 rounded-2xl border border-line bg-surface p-8 text-center">
          <Lock className="mx-auto text-ink-faint" size={28} aria-hidden />
          <h2 className="mt-3 text-lg font-medium">Private repositories</h2>
          <p className="mx-auto mt-1 max-w-md text-sm text-ink-dim">Sign in with GitHub and install the app on the repositories you want to see. We only read: workflows, deployments, and code structure.</p>
          <p className="mx-auto mt-2 max-w-md text-xs leading-relaxed text-ink-faint">Signing in happens on github.com, where you approve read-only access. This site never sees your GitHub password. <a href="/privacy" className="underline underline-offset-2 hover:text-ink-dim">Privacy notice</a></p>
          <a href="/api/auth/login?returnTo=/repos" className="mt-5 inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-sm font-medium text-void">Sign in with GitHub</a>
        </section>
      )}
      {session && !session.configured && <p className="mt-10 text-sm text-ink-faint">Sign-in isn&apos;t configured on this server, so only public repositories are available.</p>}

      {signedIn && (
        <section className="mt-10">
          <div className="flex items-center gap-3">
            <div className="relative max-w-xs flex-1">
              <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" aria-hidden />
              <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter" aria-label="Filter repositories" className="w-full rounded-lg border border-line bg-surface py-2 pl-8 pr-3 text-sm outline-none focus:border-accent" />
            </div>
            {session?.installUrl && <a href={session.installUrl} className="ml-auto flex items-center gap-1.5 rounded-lg border border-line px-3 py-2 text-sm text-ink-dim hover:text-ink"><Plus size={14} aria-hidden />Add repositories</a>}
          </div>

          {err && <p role="alert" className="mt-4 text-sm text-failing">{err}</p>}
          {!repos && !err && <p className="mt-6 flex items-center gap-2 text-sm text-ink-dim"><Loader2 size={14} className="animate-spin" />Loading your repositories…</p>}
          {repos && repos.length === 0 && (
            <div className="mt-6 rounded-2xl border border-dashed border-line p-8 text-center">
              <p className="text-sm text-ink-dim">The app isn&apos;t installed on any repository yet.</p>
              {session?.installUrl && <a href={session.installUrl} className="mt-4 inline-flex items-center gap-2 rounded-xl bg-accent px-4 py-2 text-sm font-medium text-void"><Plus size={14} aria-hidden />Install the GitHub App</a>}
            </div>
          )}
          <ul className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {shown.map((r) => (
              <li key={r.fullName}>
                <button onClick={() => go(r.fullName)} className="group flex h-full w-full flex-col gap-2 rounded-xl border border-line bg-surface p-4 text-left transition-colors hover:border-accent/60">
                  <div className="flex items-center gap-2">
                    <GitBranch size={15} className="shrink-0 text-ink-faint" aria-hidden />
                    <span className="min-w-0 flex-1 truncate font-mono text-sm text-ink">{r.fullName}</span>
                    {r.private && <span className="flex items-center gap-1 rounded-full bg-raised px-2 py-0.5 text-[10px] text-ink-dim"><Lock size={10} aria-hidden />Private</span>}
                  </div>
                  <p className="line-clamp-2 min-h-8 text-xs text-ink-dim">{r.description ?? "No description."}</p>
                  <div className="mt-auto flex items-center gap-2 text-[11px] text-ink-faint">
                    {r.language && <span>{r.language}</span>}
                    {r.pushedAt && <span>· pushed {ago(r.pushedAt)}</span>}
                    <span className="ml-auto flex items-center gap-1 text-accent opacity-0 transition-opacity group-hover:opacity-100">Map it <ArrowRight size={12} aria-hidden /></span>
                  </div>
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}
    </main>
  );
}
