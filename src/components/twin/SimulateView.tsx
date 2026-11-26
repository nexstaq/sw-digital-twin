"use client";

import { useEffect, useState, useSyncExternalStore } from "react";
import { ArrowLeft, ArrowRight, FlaskConical, Loader2, LockKeyhole, Search, ShieldAlert, ShieldCheck, Waypoints } from "lucide-react";
import type { TwinGraph } from "@/lib/graph/types";
import { securityGraph } from "@/lib/security/map";
import type { FindingSet } from "@/lib/security/types";
import { useTwin } from "@/lib/store";
import { Canvas } from "./Canvas";
import { ReachabilityReplay } from "./ReachabilityReplay";
import { useSecurity } from "./useSecurity";
import { SimulationSection } from "./SimulationSection";

const subscribe = () => () => {};
const repoFromUrl = () => new URLSearchParams(window.location.search).get("repo");
const TABS = ["explain", "test", "reachability"] as const;
type Tab = (typeof TABS)[number];
const TAB_LABEL: Record<Tab, string> = { explain: "Explain a block", test: "Run a test", reachability: "Check reachability" };
const TAB_ICON = { explain: Search, test: FlaskConical, reachability: Waypoints } as const;

function Message({ icon, title, children }: { icon: React.ReactNode; title: string; children?: React.ReactNode }) {
  return (
    <main className="mx-auto grid min-h-dvh max-w-md place-content-center gap-3 px-6 text-center">
      <div className="mx-auto text-ink-faint">{icon}</div>
      <h1 className="text-xl font-semibold">{title}</h1>
      <div className="space-y-2 text-sm text-ink-dim">{children}</div>
    </main>
  );
}

function TabSwitcher({ tab, onTab }: { tab: Tab; onTab: (t: Tab) => void }) {
  return (
    <div role="tablist" aria-label="Simulation entry points" className="flex flex-wrap gap-1.5">
      {TABS.map((t) => {
        const Icon = TAB_ICON[t];
        return (
          <button
            key={t} role="tab" aria-selected={tab === t} onClick={() => onTab(t)}
            className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium ${tab === t ? "border-accent/60 bg-accent/10 text-accent" : "border-line text-ink-dim hover:text-ink"}`}
          >
            <Icon size={13} aria-hidden /> {TAB_LABEL[t]}
          </button>
        );
      })}
    </div>
  );
}

function ExplainTab({ repo }: { repo: string }) {
  return (
    <div role="tabpanel" aria-label="Explain a block" className="space-y-2 rounded-lg border border-line bg-raised/60 p-3 text-xs leading-relaxed text-ink-dim">
      <p>Pick any block on the map and watch a request move through it, step by step, in plain language: what it calls, what could go wrong, and what a fault would look like. Nothing real is touched.</p>
      <a href={`/scan?repo=${encodeURIComponent(repo)}`} className="inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 font-medium text-accent hover:bg-accent/20">
        Open the map <ArrowRight size={13} aria-hidden />
      </a>
      <p>Once it is open, switch to the <b className="text-ink">Simulate</b> lens (the flask icon in the lens switcher) and click a block.</p>
    </div>
  );
}

function TestTab({ set, repo, sim }: { set: FindingSet | null; repo: string; sim: { simulating: boolean; error: string | null; onSimulate: (source: boolean) => void; onStop: () => void } }) {
  if (!set) return <p role="tabpanel" aria-label="Run a test" className="rounded-lg border border-line bg-raised/60 p-3 text-xs text-ink-dim">Run a security scan first, on the <a className="text-accent underline" href={`/security?repo=${encodeURIComponent(repo)}`}>Security</a> page, then come back here.</p>;
  return <div role="tabpanel" aria-label="Run a test"><SimulationSection set={set} simulating={sim.simulating} error={sim.error} onSimulate={sim.onSimulate} onStop={sim.onStop} /></div>;
}

/** The rules of engagement for this run, in plain language, with an explicit approval before anything runs. Range-only,
 * so nothing here is technically gated server-side yet (X5-X7's design note) — this screen is deliberately shown anyway,
 * as the same habit X9's real-target runs will actually require. */
function PreFlight({ onApprove }: { onApprove: () => void }) {
  const [checked, setChecked] = useState(false);
  return (
    <div className="space-y-3 rounded-lg border border-line bg-raised/60 p-3 text-xs text-ink-dim">
      <h3 className="text-[11px] font-medium uppercase tracking-wider text-ink-faint">Before this runs</h3>
      <ul className="list-disc space-y-1 pl-4">
        <li><b className="text-ink">Target:</b> this repository&apos;s own simulated range only. No real network request is ever made.</li>
        <li><b className="text-ink">What it tries:</b> every weakness already found reachable, probed from the public surface with no credentials (the red-team agent), then checked against the real, unmodified health engine (the blue observer).</li>
        <li><b className="text-ink">Techniques its log will name:</b> <code>T1190</code> (exploiting a public-facing application), <code>T1195</code> (a pipeline triggered by an outsider).</li>
        <li><b className="text-ink">Bounded:</b> a step budget and a time window, the same as every simulation on this map; every call is checked and logged before it runs.</li>
      </ul>
      <label className="flex cursor-pointer items-start gap-2">
        <input type="checkbox" checked={checked} onChange={(e) => setChecked(e.target.checked)} className="mt-0.5 accent-[var(--color-accent)]" />
        <span>I understand this is bounded to the simulated range, and I want to run it.</span>
      </label>
      <button onClick={onApprove} disabled={!checked} className="rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 font-medium text-accent hover:bg-accent/20 disabled:opacity-40">
        Approve and run
      </button>
    </div>
  );
}

function ReachabilityTab({ graph, set, repo, sim }: { graph: TwinGraph; set: FindingSet | null; repo: string; sim: { simulating: boolean; error: string | null; onSimulate: (source: boolean) => void; onStop: () => void } }) {
  // "approved" is the only state kept here; everything else (running, failed, empty, has-results) is read straight off
  // props each render, so there is nothing to keep in sync with an effect.
  const [approved, setApproved] = useState(!!set?.simulated);
  const approve = () => { setApproved(true); sim.onSimulate(false); };

  if (!approved) return <div role="tabpanel" aria-label="Check reachability"><PreFlight onApprove={approve} /></div>;
  if (sim.simulating) return <p role="status" aria-label="Check reachability" className="flex items-center gap-2 rounded-lg border border-line bg-raised/60 p-3 text-xs text-ink-dim"><Loader2 className="animate-spin" size={14} aria-hidden /> Running against the simulated range…</p>;

  if (sim.error) {
    return (
      <div role="tabpanel" aria-label="Check reachability" className="space-y-2 rounded-lg border border-failing/40 bg-failing/5 p-3 text-xs">
        <p role="alert" className="flex items-center gap-1.5 text-failing"><ShieldAlert size={14} aria-hidden /> {sim.error}</p>
        <button onClick={() => setApproved(false)} className="text-accent hover:underline">Try again</button>
      </div>
    );
  }
  if (!set?.simulated) return <div role="tabpanel" aria-label="Check reachability"><PreFlight onApprove={approve} /></div>;

  const interrupted = set.simulated.notes.find((n) => /ended early/.test(n));
  return (
    <div role="tabpanel" aria-label="Check reachability" className="space-y-3">
      {interrupted && <p role="alert" className="rounded-lg border border-degraded/50 bg-degraded/10 p-2 text-xs text-degraded">This run was interrupted before it finished: {interrupted}</p>}
      <ReachabilityReplay graph={graph} findings={set.findings} blue={set.simulated.blue} />
      <div className="flex flex-wrap items-center gap-3 text-xs">
        <a href={`/api/security/report?repo=${encodeURIComponent(repo)}&format=html`} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">Open report</a>
        <a href={`/api/security/report?repo=${encodeURIComponent(repo)}&format=sarif&download=1`} className="text-ink-dim hover:text-ink" title="For GitHub code scanning and other tools; carries the ATT&amp;CK technique each confirmed finding was exercised with">Download SARIF</a>
        <button onClick={() => setApproved(false)} className="text-ink-dim hover:text-ink">Run again</button>
      </div>
    </div>
  );
}

function Ready({ graph, set, repo, sim }: { graph: TwinGraph; set: FindingSet | null; repo: string; sim: { simulating: boolean; error: string | null; onSimulate: (source: boolean) => void; onStop: () => void } }) {
  const [tab, setTab] = useState<Tab>("explain");
  const view = securityGraph(graph, set?.findings ?? [], !!set);
  useEffect(() => { useTwin.getState().setLens("ops"); return () => useTwin.getState().setLens("overview"); }, []);

  return (
    <div className="relative">
      <Canvas
        graph={tab === "reachability" ? view : graph} mode="security"
        banner={<div className="leading-tight"><div className="text-sm font-semibold">Simulation</div><div className="text-xs text-ink-dim">{repo}</div></div>}
        headerExtra={<a href={`/security?repo=${encodeURIComponent(repo)}`} className="flex items-center gap-1.5 rounded-lg border border-line bg-surface/80 px-2.5 py-1.5 text-xs text-ink-dim hover:text-ink"><ArrowLeft size={13} aria-hidden /> Security</a>}
      />
      <div className="absolute left-4 top-[7.2rem] z-10 max-h-[calc(100%-9rem)] w-[min(26rem,calc(100%-2rem))] space-y-2 overflow-y-auto">
        <TabSwitcher tab={tab} onTab={setTab} />
        {tab === "explain" && <ExplainTab repo={repo} />}
        {tab === "test" && <TestTab set={set} repo={repo} sim={sim} />}
        {tab === "reachability" && <ReachabilityTab graph={graph} set={set} repo={repo} sim={sim} />}
      </div>
    </div>
  );
}

export function SimulateView() {
  const repo = useSyncExternalStore(subscribe, repoFromUrl, () => null);
  if (!repo) return <Message icon={<Waypoints size={32} />} title="Simulation">Open a repository from <a className="text-accent underline" href="/repos">your repositories</a> and choose Simulate.</Message>;
  return <Loaded repo={repo} />;
}

function Loaded({ repo }: { repo: string }) {
  const { state, simulate, simulating, simError, stopSimulation } = useSecurity(repo);
  const back = `/scan?repo=${encodeURIComponent(repo)}`;
  switch (state.kind) {
    case "loading": return <main className="grid min-h-dvh place-items-center text-ink-dim"><Loader2 className="animate-spin" aria-label="Loading" /></main>;
    case "forbidden": return (
      <Message icon={<LockKeyhole size={32} />} title="Simulation is for maintainers">
        <p role="alert">{state.message}</p>
        <a className="text-accent underline" href={`/signin?returnTo=${encodeURIComponent(`/simulate?repo=${repo}`)}`}>Sign in with GitHub</a>
      </Message>
    );
    case "nomap": return <Message icon={<ShieldCheck size={32} />} title="Map the repository first"><p>A simulation runs against the map.</p><a className="text-accent underline" href={back}>Map {repo}</a></Message>;
    case "error": return <Message icon={<ShieldCheck size={32} />} title="Couldn't load"><p role="alert">{state.message}</p></Message>;
    default: return <Ready graph={state.graph} set={state.set} repo={repo} sim={{ simulating, error: simError, onSimulate: (src) => void simulate(src), onStop: () => void stopSimulation() }} />;
  }
}
