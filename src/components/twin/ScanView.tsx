"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowRight, Loader2, ScanSearch, ShieldCheck, TriangleAlert } from "lucide-react";
import { streamSse } from "@/lib/sse";
import { applyOverrides } from "@/lib/graph/overrides";
import type { TwinGraph } from "@/lib/graph/types";
import type { IngestEvent, Stats } from "@/lib/ingest/types";
import { useTwin } from "@/lib/store";
import { Canvas } from "./Canvas";
import { HiddenPanel } from "./HiddenPanel";
import { NodeEditor } from "./NodeEditor";
import { SessionButton } from "./SessionButton";
import { SharePanel } from "./SharePanel";
import { SourcesPanel } from "./SourcesPanel";
import { useConnectors, useMappings } from "./useConnectors";
import { useHealthView } from "./useHealthView";
import { useLiveHealth, type LiveState } from "./useLiveHealth";
import { useOverrides } from "./useOverrides";

const EXAMPLES = ["fastapi/full-stack-fastapi-template", "t3-oss/create-t3-turbo", "vercel/nextjs-subscription-payments"];

function LiveDot({ live }: { live: LiveState }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 5000); return () => clearInterval(t); }, []);
  if (live.kind === "live") {
    const s = Math.max(0, Math.round((now - live.at) / 1000));
    return <div className="flex items-center gap-1.5 text-nominal"><span className="h-1.5 w-1.5 rounded-full bg-nominal" aria-hidden />Live from GitHub · updated {s < 60 ? `${s}s` : `${Math.round(s / 60)}m`} ago</div>;
  }
  if (live.kind === "connecting") return <div className="text-ink-faint">Connecting to GitHub for live health…</div>;
  return <div className="flex gap-1.5 text-degraded"><TriangleAlert size={12} className="mt-0.5 shrink-0" />{live.message}</div>;
}

function LiveCanvas({ graph: scanned, repo, running, progress, warnings }: { graph: TwinGraph; repo: string; running: boolean; progress: Progress | null; warnings: string[] }) {
  const { overrides, canEdit, edit, error: editError } = useOverrides(repo);
  const graph = useMemo(() => applyOverrides(scanned, overrides), [scanned, overrides]);
  const { signals, live } = useLiveHealth(!running, repo);
  const { mappings, confirm, forget, shared } = useMappings(repo);
  const { status, proposals } = useConnectors(repo, graph, mappings, !running);
  const { graph: g, incident, anchor } = useHealthView(graph, signals, mappings);
  return (
    <div className="relative">
      <Canvas graph={g} incident={incident} anchor={anchor}
        nodeEditor={canEdit ? (node) => <NodeEditor key={node.id} node={node} current={overrides[node.id]} onSave={(o) => void edit(node.id, o)} error={editError} /> : undefined}
        headerExtra={<>{canEdit && <a href={`/security?repo=${encodeURIComponent(repo)}`} className="flex items-center gap-1.5 rounded-lg border border-line bg-surface/80 px-2.5 py-1.5 text-xs text-ink-dim hover:text-ink"><ShieldCheck size={13} aria-hidden /> Security</a>}{canEdit && <HiddenPanel scanned={scanned} overrides={overrides} onEdit={(id, o) => void edit(id, o)} />}{canEdit && <SharePanel repo={repo} />}<SourcesPanel status={status} proposals={proposals} graph={graph} onConfirm={confirm} onForget={forget} shared={shared} /><SessionButton /></>} />
      <div className="pointer-events-none absolute left-4 top-[7.2rem] z-10 w-72 rounded-xl border border-line bg-surface/90 p-3 text-xs backdrop-blur">
        <div className="flex items-center gap-2 text-ink">
          {running ? <Loader2 size={13} className="animate-spin text-accent" /> : <ScanSearch size={13} className="text-nominal" />}
          <span className="font-medium">{progress?.message}</span>
        </div>
        <div className="mt-2 h-1 overflow-hidden rounded bg-raised"><div className="h-full bg-accent transition-all duration-500" style={{ width: `${progress?.pct ?? 0}%` }} /></div>
        {progress?.stats && <div className="mt-2 font-mono text-ink-dim">{progress.stats.nodes} nodes · {progress.stats.edges} links · {progress.stats.files} files</div>}
        {!running && warnings.map((w) => <div key={w} className="mt-1.5 flex gap-1.5 text-degraded"><TriangleAlert size={12} className="mt-0.5 shrink-0" />{w}</div>)}
        {!running && <div className="mt-2"><LiveDot live={live} /></div>}
        {!running && g.story && <div className="mt-1 text-ink-faint">{g.story.source === "ai" ? `Descriptions written by AI (${g.story.model}) and checked against the code.` : "Descriptions are auto-generated from the analysis."}</div>}
      </div>
    </div>
  );
}

interface Progress { stage: string; message: string; pct: number; stats?: Stats }

export function ScanView() {
  const [input, setInput] = useState("");
  const [graph, setGraph] = useState<TwinGraph | null>(null);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [repoName, setRepoName] = useState("");
  const abortRef = useRef<AbortController | null>(null);

  const start = useCallback((repo: string) => {
    abortRef.current?.abort();
    setError(null); setWarnings([]); setGraph(null); setRunning(true); setRepoName(repo);
    setProgress({ stage: "clone", message: "Starting…", pct: 2 });
    useTwin.getState().setPath([]);
    window.history.replaceState(null, "", `/scan?repo=${encodeURIComponent(repo)}`);

    const ctl = new AbortController();
    abortRef.current = ctl;
    let finished = false;
    const onData = (data: string) => {
      const ev = JSON.parse(data) as IngestEvent;
      if (ev.type === "stage") setProgress((p) => ({ ...p, stage: ev.stage, message: ev.message, pct: ev.pct }));
      else if (ev.type === "graph") { setGraph(ev.graph); setProgress((p) => (p ? { ...p, stats: ev.stats } : p)); }
      else if (ev.type === "done") {
        finished = true;
        setGraph(ev.graph); setWarnings(ev.warnings); setRunning(false);
        setProgress({ stage: "done", message: `Mapped in ${(ev.ms / 1000).toFixed(1)}s`, pct: 100, stats: ev.stats });
      } else if (ev.type === "error") { finished = true; setError(ev.message); setRunning(false); }
    };
    streamSse(`/api/scan?repo=${encodeURIComponent(repo)}`, onData, ctl.signal)
      .then(() => { if (!finished && !ctl.signal.aborted) { setError("The scanner stopped unexpectedly. Try again."); setRunning(false); } })
      .catch(() => { if (!ctl.signal.aborted) { setError("Lost connection to the scanner."); setRunning(false); } });
  }, []);

  // /scan?repo=owner/name auto-starts, so scans are linkable
  useEffect(() => {
    const repo = new URLSearchParams(window.location.search).get("repo");
    if (repo) { setInput(repo); start(repo); } // eslint-disable-line react-hooks/set-state-in-effect
    return () => abortRef.current?.abort();
  }, [start]);

  if (graph && graph.nodes.length > 0) {
    return <LiveCanvas graph={graph} repo={repoName} running={running} progress={progress} warnings={warnings} />;
  }

  return (
    <main className="mx-auto flex min-h-dvh max-w-xl flex-col justify-center gap-6 px-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Map any GitHub repo</h1>
        <p className="mt-2 text-ink-dim">Paste a public repository. We read its workflows, infrastructure and code, and draw how it is built and run.</p>
      </div>
      <form onSubmit={(e) => { e.preventDefault(); if (input.trim()) start(input.trim()); }} className="flex gap-2">
        <input
          value={input} onChange={(e) => setInput(e.target.value)} disabled={running} autoFocus spellCheck={false}
          placeholder="owner/repo or https://github.com/owner/repo" aria-label="GitHub repository"
          className="min-w-0 flex-1 rounded-xl border border-line bg-surface px-4 py-3 font-mono text-sm outline-none placeholder:text-ink-faint focus:border-accent"
        />
        <button disabled={running || !input.trim()} className="flex items-center gap-2 rounded-xl bg-accent px-4 py-3 text-sm font-medium text-void disabled:opacity-50">
          {running ? <Loader2 size={16} className="animate-spin" /> : <ArrowRight size={16} />} Map it
        </button>
      </form>
      {running && progress && (
        <div role="status" className="space-y-2">
          <div className="h-1 overflow-hidden rounded bg-raised"><div className="h-full bg-accent transition-all duration-500" style={{ width: `${progress.pct}%` }} /></div>
          <p className="text-sm text-ink-dim">{progress.message}</p>
        </div>
      )}
      {error && (
        <div role="alert" className="flex gap-2 rounded-xl border border-failing/50 bg-failing/10 p-3 text-sm text-failing">
          <TriangleAlert size={16} className="mt-0.5 shrink-0" />
          <div>{error}{/sign in/i.test(error) && <a href={`/signin?returnTo=${encodeURIComponent(`/scan?repo=${input.trim()}`)}`} className="mt-2 block font-medium underline">Sign in with GitHub</a>}</div>
        </div>
      )}
      {graph && graph.nodes.length === 0 && !running && !error && (
        <p className="rounded-xl border border-degraded/50 bg-degraded/10 p-3 text-sm text-degraded">{warnings[0] ?? "Nothing recognisable was found in this repository."}</p>
      )}
      <div className="flex flex-wrap gap-2 text-xs text-ink-dim">
        Try: {EXAMPLES.map((ex) => (
          <button key={ex} onClick={() => { setInput(ex); start(ex); }} disabled={running} className="rounded-full border border-line px-2.5 py-1 font-mono hover:text-ink disabled:opacity-50">{ex}</button>
        ))}
      </div>
    </main>
  );
}
