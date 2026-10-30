"use client";

import { useEffect, useState } from "react";
import { Eye, Loader2, TriangleAlert } from "lucide-react";
import type { TwinGraph } from "@/lib/graph/types";
import type { SignalSet } from "@/lib/health/signals";
import { Canvas } from "./Canvas";
import { useHealthView } from "./useHealthView";

interface Payload { repo: string; graph: TwinGraph; signals: SignalSet | null; warning?: string }
const POLL_MS = 30_000;

function SharedMap({ data }: { data: Payload }) {
  const { graph, incident, anchor } = useHealthView(data.graph, data.signals);
  return (
    <div className="relative">
      <Canvas graph={graph} incident={incident} anchor={anchor} headerExtra={<span className="flex items-center gap-1.5 rounded-lg border border-line bg-surface/80 px-2.5 py-1.5 text-xs text-ink-dim"><Eye size={13} aria-hidden /> Read-only · {data.repo}</span>} />
      {data.warning && <div role="status" className="absolute left-4 top-[7.2rem] z-10 flex w-72 gap-1.5 rounded-xl border border-line bg-surface/90 p-3 text-xs text-degraded backdrop-blur"><TriangleAlert size={12} className="mt-0.5 shrink-0" />{data.warning}</div>}
    </div>
  );
}

/** What a share link opens: the saved map with live health, no sign-in, no editing. Refreshes itself; stops the moment the link is revoked. */
export function SharedView({ owner, repo, secret }: { owner: string; repo: string; secret: string }) {
  const [data, setData] = useState<Payload | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    const load = async () => {
      try {
        const r = await fetch(`/api/shared/${owner}/${repo}/${secret}`, { cache: "no-store" });
        const d = (await r.json()) as Payload & { error?: string };
        if (!live) return;
        if (!r.ok) { setData(null); setError(d.error ?? "This link doesn't work."); return; } // revoked mid-session: drop the map
        setData(d); setError(null);
      } catch { /* offline blip: keep what is on screen */ }
    };
    void load();
    const t = setInterval(load, POLL_MS);
    return () => { live = false; clearInterval(t); };
  }, [owner, repo, secret]);

  if (error) return <main className="mx-auto grid min-h-dvh max-w-md place-content-center gap-2 px-6 text-center"><h1 className="text-xl font-semibold">Can&apos;t open this map</h1><p role="alert" className="text-ink-dim">{error}</p></main>;
  if (!data) return <main className="grid min-h-dvh place-items-center text-ink-dim"><Loader2 className="animate-spin" aria-label="Loading" /></main>;
  return <SharedMap data={data} />;
}
