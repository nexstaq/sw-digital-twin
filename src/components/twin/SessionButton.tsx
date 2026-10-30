"use client";

import { useEffect, useRef, useState } from "react";
import { FolderGit2, LogIn, LogOut } from "lucide-react";
import { useSession } from "./useSession";

/** Sign in with GitHub / who you are. Renders nothing when sign-in is not configured on this server. */
export function SessionButton() {
  const session = useSession();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const away = (e: PointerEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") { e.stopPropagation(); setOpen(false); } };
    document.addEventListener("pointerdown", away);
    document.addEventListener("keydown", esc, true);
    return () => { document.removeEventListener("pointerdown", away); document.removeEventListener("keydown", esc, true); };
  }, [open]);

  if (!session?.configured) return null;
  if (!session.user) {
    const here = typeof window === "undefined" ? "/repos" : `${window.location.pathname}${window.location.search}`;
    return (
      <a href={`/api/auth/login?returnTo=${encodeURIComponent(here)}`} className="flex items-center gap-2 rounded-lg border border-line bg-surface px-2.5 py-1.5 text-[13px] text-ink-dim hover:text-ink">
        <LogIn size={14} aria-hidden /><span className="hidden lg:inline">Sign in with GitHub</span><span className="lg:hidden">Sign in</span>
      </a>
    );
  }
  return (
    <div ref={ref} className="relative">
      <button onClick={() => setOpen((o) => !o)} aria-expanded={open} aria-haspopup="menu" aria-label={`Signed in as ${session.user.login}`} className="flex items-center gap-2 rounded-lg border border-line bg-surface py-1 pl-1 pr-2.5 text-[13px] text-ink-dim hover:text-ink">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        {session.user.avatar ? <img src={session.user.avatar} alt="" width={22} height={22} className="rounded-full" /> : <span className="grid h-[22px] w-[22px] place-items-center rounded-full bg-raised text-[11px]">{session.user.login[0]?.toUpperCase()}</span>}
        <span className="hidden max-w-28 truncate lg:inline">{session.user.login}</span>
      </button>
      {open && (
        <div role="menu" className="absolute right-0 top-full z-40 mt-2 w-48 rounded-xl border border-line bg-surface p-1.5 shadow-2xl">
          <a role="menuitem" href="/repos" className="flex items-center gap-2 rounded-lg px-2.5 py-2 text-sm text-ink-dim hover:bg-raised hover:text-ink"><FolderGit2 size={14} aria-hidden />My repositories</a>
          <button role="menuitem" onClick={async () => { await fetch("/api/auth/logout", { method: "POST" }); window.location.reload(); }} className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-sm text-ink-dim hover:bg-raised hover:text-ink"><LogOut size={14} aria-hidden />Sign out</button>
        </div>
      )}
    </div>
  );
}
