"use client";

import { useEffect, useState } from "react";

export interface SessionInfo { configured: boolean; user: { login: string; avatar?: string } | null; installUrl: string | null }

/** Who is signed in (never the token: that stays in an httpOnly cookie). `null` while loading. */
export function useSession(): SessionInfo | null {
  const [s, setS] = useState<SessionInfo | null>(null);
  useEffect(() => {
    let live = true;
    fetch("/api/auth/me", { cache: "no-store" }).then((r) => r.json()).then((d: SessionInfo) => { if (live) setS(d); }).catch(() => { if (live) setS({ configured: false, user: null, installUrl: null }); });
    return () => { live = false; };
  }, []);
  return s;
}
