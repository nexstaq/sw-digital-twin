"use client";

import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { ArrowLeft, Loader2, LockKeyhole, ShieldCheck } from "lucide-react";
import { ancestry } from "@/lib/graph/nav";
import type { TwinGraph } from "@/lib/graph/types";
import { findingsUnder, mapFindings, posture, securityGraph } from "@/lib/security/map";
import type { Category, Finding, FindingSet } from "@/lib/security/types";
import { useTwin } from "@/lib/store";
import { Canvas } from "./Canvas";
import { FindingPanel } from "./FindingPanel";
import { PosturePanel } from "./PosturePanel";
import { FindingRow, GradeRing } from "./securityUi";
import { useSecurity } from "./useSecurity";

const subscribe = () => () => {};
const repoFromUrl = () => new URLSearchParams(window.location.search).get("repo");

function Message({ icon, title, children }: { icon: React.ReactNode; title: string; children?: React.ReactNode }) {
  return (
    <main className="mx-auto grid min-h-dvh max-w-md place-content-center gap-3 px-6 text-center">
      <div className="mx-auto text-ink-faint">{icon}</div>
      <h1 className="text-xl font-semibold">{title}</h1>
      <div className="space-y-2 text-sm text-ink-dim">{children}</div>
    </main>
  );
}

/** Drawer section: what is wrong inside the selected part, worst first. Clicking one opens its deep dive. */
function NodeFindings({ list, onOpen }: { list: Finding[]; onOpen: (f: Finding) => void }) {
  const [all, setAll] = useState(false);
  const shown = all ? list : list.slice(0, 6);
  return (
    <section aria-label="Security findings">
      <h3 className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-ink-faint">Security findings{list.length ? ` · ${list.length}` : ""}</h3>
      {list.length === 0 ? <p className="text-xs text-ink-dim">Nothing found in this part.</p> : (
        <div className="space-y-1.5">
          {shown.map((f) => <FindingRow key={f.id} f={f} onOpen={onOpen} />)}
          {list.length > shown.length && <button onClick={() => setAll(true)} className="text-xs text-accent hover:underline">Show {list.length - shown.length} more</button>}
        </div>
      )}
    </section>
  );
}

function Ready({ graph, set, repo, scan, scanning, scanError }: { graph: TwinGraph; set: FindingSet | null; repo: string; scan: () => void; scanning: boolean; scanError: string | null }) {
  const [filter, setFilter] = useState<Category | null>(null);
  const [open, setOpen] = useState<Finding | null>(null);
  const all = useMemo(() => set?.findings ?? [], [set]);
  const visible = useMemo(() => (filter ? all.filter((f) => f.category === filter) : all), [all, filter]);
  const home = useMemo(() => mapFindings(graph, all), [graph, all]);
  const view = useMemo(() => securityGraph(graph, visible, !!set), [graph, visible, set]);
  const p = useMemo(() => posture(all, !!set), [all, set]);

  // "ops" is the lens that steps quiet parts back and shows each tile's top reason, which is what a risk view wants
  useEffect(() => { useTwin.getState().setLens("ops"); return () => useTwin.getState().setLens("overview"); }, []);

  const locate = (f: Finding) => {
    const id = home.get(f.id);
    if (!id) return;
    const s = useTwin.getState();
    s.setPath(ancestry(graph, id));
    s.select(id);
  };

  return (
    <div className="relative">
      <Canvas
        graph={view} mode="security"
        banner={(
          <div className="flex items-center gap-3" aria-live="polite">
            {set ? <GradeRing posture={p} size={40} /> : <div className="grid h-10 w-10 place-items-center rounded-full border-2 border-dashed border-line text-ink-faint">?</div>}
            <div className="leading-tight"><div className="text-sm font-semibold">Security</div><div className="text-xs text-ink-dim">{p.headline}</div></div>
          </div>
        )}
        headerExtra={<a href={`/scan?repo=${encodeURIComponent(repo)}`} className="flex items-center gap-1.5 rounded-lg border border-line bg-surface/80 px-2.5 py-1.5 text-xs text-ink-dim hover:text-ink"><ArrowLeft size={13} aria-hidden /> Health map</a>}
        nodeEditor={(node) => <NodeFindings key={node.id} list={findingsUnder(graph, visible, home, node.id)} onOpen={setOpen} />}
      />
      <PosturePanel set={set} filter={filter} onFilter={setFilter} visible={visible} onOpen={(f) => { setOpen(f); locate(f); }} onScan={scan} scanning={scanning} scanError={scanError} />
      {open && set && <FindingPanel finding={open} repo={repo} sha={set.sha} onClose={() => setOpen(null)} onLocate={() => locate(open)} />}
    </div>
  );
}

export function SecurityView() {
  const repo = useSyncExternalStore(subscribe, repoFromUrl, () => null);
  if (!repo) return <Message icon={<ShieldCheck size={32} />} title="Security analysis">Open a repository from <a className="text-accent underline" href="/repos">your repositories</a> and choose Security.</Message>;
  return <Loaded repo={repo} />;
}

function Loaded({ repo }: { repo: string }) {
  const { state, scan, scanning, scanError } = useSecurity(repo);
  const back = `/scan?repo=${encodeURIComponent(repo)}`;
  switch (state.kind) {
    case "loading": return <main className="grid min-h-dvh place-items-center text-ink-dim"><Loader2 className="animate-spin" aria-label="Loading" /></main>;
    case "forbidden": return (
      <Message icon={<LockKeyhole size={32} />} title="Security findings are for maintainers">
        <p role="alert">{state.message}</p>
        <p>A list of a project&apos;s vulnerabilities is more sensitive than its architecture, so it needs write access to the repository.</p>
        <a className="text-accent underline" href={`/api/auth/login?returnTo=${encodeURIComponent(`/security?repo=${repo}`)}`}>Sign in with GitHub</a>
      </Message>
    );
    case "nomap": return <Message icon={<ShieldCheck size={32} />} title="Map the repository first"><p>The security view colours the map, so it needs one.</p><a className="text-accent underline" href={back}>Map {repo}</a></Message>;
    case "error": return <Message icon={<ShieldCheck size={32} />} title="Couldn't load"><p role="alert">{state.message}</p></Message>;
    default: return <Ready graph={state.graph} set={state.set} repo={repo} scan={scan} scanning={scanning} scanError={scanError} />;
  }
}
