"use client";

import { useCallback, useEffect, useState } from "react";
import type { TwinGraph } from "@/lib/graph/types";
import type { FindingSet } from "@/lib/security/types";

export type SecurityState =
  | { kind: "loading" }
  | { kind: "forbidden"; message: string }
  | { kind: "nomap" }
  | { kind: "error"; message: string }
  | { kind: "ready"; graph: TwinGraph; set: FindingSet | null };

const err = async (r: Response) => ((await r.json().catch(() => null)) as { error?: string } | null)?.error ?? `Request failed (${r.status}).`;

/** The saved map plus the latest security scan of one repo. Needs push access: the server refuses everyone else. */
export function useSecurity(repo: string) {
  const [state, setState] = useState<SecurityState>({ kind: "loading" });
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const q = encodeURIComponent(repo);

  useEffect(() => {
    let live = true;
    (async () => {
      try {
        const f = await fetch(`/api/security/findings?repo=${q}`, { cache: "no-store" });
        if (f.status === 401 || f.status === 403) { if (live) setState({ kind: "forbidden", message: await err(f) }); return; }
        if (!f.ok) throw new Error(await err(f));
        const { set } = (await f.json()) as { set: FindingSet | null };
        const list = await fetch(`/api/snapshots?repo=${q}`, { cache: "no-store" });
        const snaps = list.ok ? ((await list.json()) as { snapshots: { sha: string }[] }).snapshots : [];
        const latest = snaps.at(-1);
        const snap = latest && (await fetch(`/api/snapshots?repo=${q}&sha=${latest.sha}`, { cache: "no-store" }));
        if (!snap || !snap.ok) { if (live) setState({ kind: "nomap" }); return; }
        const { graph } = (await snap.json()) as { graph: TwinGraph };
        if (live) setState({ kind: "ready", graph, set });
      } catch (e) { if (live) setState({ kind: "error", message: e instanceof Error ? e.message : "Could not load." }); }
    })();
    return () => { live = false; };
  }, [q]);

  const scan = useCallback(async () => {
    setScanning(true); setScanError(null);
    try {
      const r = await fetch(`/api/security/scan?repo=${q}`, { method: "POST" });
      if (!r.ok) throw new Error(await err(r));
      const set = (await r.json()) as FindingSet;
      setState((s) => (s.kind === "ready" ? { ...s, set } : s));
    } catch (e) { setScanError(e instanceof Error ? e.message : "The scan failed."); } finally { setScanning(false); }
  }, [q]);

  return { state, scan, scanning, scanError };
}
