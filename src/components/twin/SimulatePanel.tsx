"use client";

import { useEffect, useMemo, useState } from "react";
import { Check, ChevronLeft, ChevronRight, FlaskConical, Pause, Play, RotateCcw, X, Zap } from "lucide-react";
import type { TwinGraph } from "@/lib/graph/types";
import { useTwin } from "@/lib/store";
import { buildRange } from "@/lib/sim/range/generate";
import type { Fault } from "@/lib/sim/range/types";
import { PERSONAS, PERSONA_LABEL, runScenario, type Persona, type SimRun } from "@/lib/sim/simulate/play";
import { scenarioFor, suggest } from "@/lib/sim/simulate/scenario";
import { simulateHealth } from "@/lib/sim/simulate/fault";
import { useReducedMotion } from "./AnimatedEdge";
import { StatusRing } from "./status";

const STEP_MS = 1700;
const FAULTS = {
  outage: { label: "Stops working", fault: { kind: "outage" } as Fault },
  slow: { label: "Gets very slow", fault: { kind: "latency", ms: 900 } as Fault },
  errors: { label: "Fails half the time", fault: { kind: "error", rate: 0.5 } as Fault },
} as const;
type FaultKey = keyof typeof FAULTS;
interface Broken { nodeId: string; kind: FaultKey }

/** The chain of ancestors (root first) down to the block that holds every touched block; the canvas opens there so the whole run is on screen. */
function viewPath(graph: TwinGraph, ids: string[]): string[] {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const chain = (id: string) => { const c: string[] = []; for (let p: string | undefined = id; p && !c.includes(p); p = byId.get(p)?.parentId) c.unshift(p); return c; };
  const chains = ids.filter((i) => byId.has(i)).map(chain);
  if (!chains.length) return [];
  let prefix = chains[0];
  for (const c of chains.slice(1)) { let i = 0; while (i < prefix.length && i < c.length && prefix[i] === c[i]) i++; prefix = prefix.slice(0, i); }
  const last = prefix.at(-1);
  // the container itself is among the touched blocks (a pipeline and its jobs): open it. A lone block: show it among its siblings.
  if (last && ids.length > 1 && ids.includes(last)) return prefix;
  if (last && ids.length === 1 && ids[0] === last) return prefix.slice(0, -1);
  return prefix;
}

export function SimulatePanel({ graph }: { graph: TwinGraph }) {
  const focus = useTwin((s) => s.simFocusId);
  const select = useTwin((s) => s.select);
  const setLens = useTwin((s) => s.setLens);
  const setOverlay = useTwin((s) => s.setSimOverlay);
  const [persona, setPersona] = useState<Persona>("exec");
  const [broken, setBroken] = useState<Broken | null>(null);
  const [baseTs] = useState(() => Date.now());

  // Live health replaces the map object every few seconds. The simulation depends only on structure, so keep the first copy of each
  // structure and rebuild the range only when the structure itself changes.
  const structure = `${graph.repo}|${graph.nodes.length}|${graph.edges.length}|${graph.nodes.map((n) => n.id).join(",").length}`;
  const [stable, setStable] = useState({ structure, graph });
  if (stable.structure !== structure) setStable({ structure, graph });
  const map = stable.graph;
  const spec = useMemo(() => buildRange({ sha: "simulation", graph: map }, null), [map]);
  const tips = useMemo(() => suggest(spec, map), [spec, map]);

  const sc = useMemo(() => (focus ? scenarioFor(spec, map, focus) : null), [spec, map, focus]);
  const fault = useMemo(() => (broken && sc?.ok ? { nodeId: broken.nodeId, fault: FAULTS[broken.kind].fault } : undefined), [broken, sc]);
  const run = useMemo(() => (sc?.ok ? runScenario(spec, map, sc.scenario, { fault }) : null), [spec, map, sc, fault]);
  const health = useMemo(() => (sc?.ok ? simulateHealth(spec, map, sc.scenario, { baseTs, fault }) : null), [spec, map, sc, fault, baseTs]);

  // the map shows the simulation's colours while this lens is open, and the real ones again when it closes
  useEffect(() => { setOverlay(health?.graph ?? null); return () => setOverlay(null); }, [health, setOverlay]);
  useEffect(() => () => { useTwin.getState().setHighlight(null); }, []);

  const choose = (id: string) => { setBroken(null); select(id); };
  const label = (id: string) => map.nodes.find((n) => n.id === id)?.label ?? id;
  // parts that can be broken: everything the run touched except the route it started from and the pipeline as a whole (breaking those changes nothing)
  const breakable = run && sc?.ok ? run.nodes.filter((id) => !spec.endpoints.some((e) => e.nodeId === id) && !(sc.scenario.kind === "workflow" && id === sc.scenario.entryId)) : [];

  return (
    <section role="region" aria-label="Simulation"
      className="absolute inset-x-3 bottom-3 z-10 flex max-h-[46dvh] flex-col gap-3 overflow-y-auto rounded-2xl border border-line bg-surface/95 p-4 shadow-2xl backdrop-blur md:inset-x-auto md:bottom-3 md:right-3 md:top-3 md:max-h-none md:w-[26rem]">
      <div className="flex items-start gap-2">
        <FlaskConical size={16} className="mt-0.5 shrink-0 text-accent" aria-hidden />
        <div className="min-w-0 flex-1">
          <div className="text-[11px] uppercase tracking-wider text-ink-faint">Simulation</div>
          <p className="text-xs text-ink-dim">
            {health ? "The colours and steps now come from a simulated copy of your system, not the real one." : "Pick a block and the map will show a simulated copy of your system, not the real one."} Nothing is sent anywhere.
          </p>
        </div>
        <button onClick={() => setLens("overview")} aria-label="Close simulation" className="shrink-0 rounded p-1 text-ink-dim hover:bg-raised hover:text-ink"><X size={16} /></button>
      </div>

      {!focus && (
        <div>
          <h2 className="text-base font-semibold">Pick a part of the map to see how it works</h2>
          <p className="mt-1 text-sm text-ink-dim">Click any block. You will watch a request, or a change going through the pipeline, pass through it step by step, and can then break something to see what else changes.</p>
          {tips.length > 0 && (
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <span className="text-xs text-ink-faint">Try:</span>
              {tips.map((id) => <button key={id} onClick={() => choose(id)} className="rounded-full border border-line bg-raised px-3 py-1 text-xs text-ink-dim hover:text-ink">{label(id)}</button>)}
            </div>
          )}
        </div>
      )}

      {focus && sc && !sc.ok && (
        <div>
          <h2 className="text-base font-semibold">{label(focus)}</h2>
          <p className="mt-1 text-sm text-ink-dim">{sc.reason}</p>
          <p className="mt-2 text-xs text-ink-faint">Pick another block on the map{tips.length ? ", or try:" : "."}</p>
          {tips.length > 0 && <div className="mt-2 flex flex-wrap gap-2">{tips.map((id) => <button key={id} onClick={() => choose(id)} className="rounded-full border border-line bg-raised px-3 py-1 text-xs text-ink-dim hover:text-ink">{label(id)}</button>)}</div>}
        </div>
      )}

      {run && sc?.ok && health && (
        <Player key={`${sc.scenario.focusId}|${broken ? `${broken.nodeId}:${broken.kind}` : "ok"}`} run={run} graph={map} persona={persona}>
          <div className="flex flex-wrap items-center gap-2" role="radiogroup" aria-label="Who is this written for">
            {PERSONAS.map((p) => (
              <button key={p} role="radio" aria-checked={persona === p} onClick={() => setPersona(p)}
                className={`rounded-full border px-3 py-1 text-xs ${persona === p ? "border-accent/60 bg-accent/10 text-ink" : "border-line text-ink-dim hover:text-ink"}`}>{PERSONA_LABEL[p]}</button>
            ))}
          </div>

          <div className="rounded-xl border border-line bg-raised/50 p-3">
            <div className="flex items-center gap-2 text-sm font-medium"><Zap size={14} className="text-degraded" aria-hidden />What if something breaks?</div>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <label className="sr-only" htmlFor="sim-break-node">Part to break</label>
              <select id="sim-break-node" onChange={(e) => e.target.value && setBroken({ nodeId: e.target.value, kind: broken?.kind ?? "outage" })} value={broken?.nodeId ?? ""}
                className="max-w-[12rem] rounded-lg border border-line bg-surface px-2 py-1 text-xs text-ink">
                <option value="" disabled>Choose a part…</option>
                {breakable.map((id) => <option key={id} value={id}>{label(id)}</option>)}
              </select>
              <label className="sr-only" htmlFor="sim-break-kind">How it breaks</label>
              <select id="sim-break-kind" value={broken?.kind ?? "outage"} onChange={(e) => broken && setBroken({ ...broken, kind: e.target.value as FaultKey })} disabled={!broken}
                className="rounded-lg border border-line bg-surface px-2 py-1 text-xs text-ink disabled:opacity-50">
                {(Object.keys(FAULTS) as FaultKey[]).map((k) => <option key={k} value={k}>{FAULTS[k].label}</option>)}
              </select>
              {broken && <button onClick={() => setBroken(null)} className="rounded-lg border border-line px-2.5 py-1 text-xs text-ink-dim hover:text-ink">Fix it</button>}
            </div>
            {broken ? (
              <div className="mt-2 text-xs" role="status">
                <p className="text-ink-dim"><span className="text-ink">{label(broken.nodeId)}</span> {FAULTS[broken.kind].label.toLowerCase()}.{" "}
                  {health.changed.length ? <>The health engine now judges {health.changed.length} {health.changed.length === 1 ? "part" : "parts"} differently:</> : "No other part changes colour."}</p>
                {health.changed.length > 0 && (
                  <ul className="mt-1.5 space-y-1">
                    {health.changed.slice(0, 6).map((c) => (
                      <li key={c.nodeId} className="flex items-start gap-2">
                        <StatusRing status={c.after} size={14} />
                        <span><span className="text-ink">{c.label}</span> <span className="text-ink-faint">{c.before} → {c.after}</span>{c.reasons[0] ? <span className="text-ink-dim"> · {c.reasons[0]}</span> : null}</span>
                      </li>
                    ))}
                    {health.changed.length > 6 && <li className="text-ink-faint">and {health.changed.length - 6} more</li>}
                  </ul>
                )}
              </div>
            ) : <p className="mt-2 text-xs text-ink-faint">Pick a part and how it breaks. The map recolours the way the real health rules would.</p>}
          </div>
        </Player>
      )}
    </section>
  );
}

/** Playback. Keyed by what is being simulated, so choosing something else starts again from the first step. */
function Player({ run, graph, persona, children }: { run: SimRun; graph: TwinGraph; persona: Persona; children: React.ReactNode }) {
  const reduced = useReducedMotion();
  const setHighlight = useTwin((s) => s.setHighlight);
  // when something is broken, open on the first step that fails: that is what the person came to see
  const firstFail = run.steps.findIndex((x) => !x.ok);
  const [step, setStep] = useState(Math.max(0, firstFail));
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState<1 | 2 | 4>(1);
  const last = run.steps.length - 1;
  const cur = run.steps[Math.min(step, last)];
  const running = playing && !reduced && step < last;

  useEffect(() => {
    if (!running) return;
    const id = setInterval(() => setStep((s) => Math.min(s + 1, last)), STEP_MS / speed);
    return () => clearInterval(id);
  }, [running, speed, last]);

  // light up what has happened so far, with the current block in focus
  useEffect(() => {
    const done = run.steps.slice(0, step + 1);
    const ids = [...new Set(done.map((s) => s.nodeId))];
    setHighlight({
      title: run.scenario.title, mode: "set", ids, focusId: done.at(-1)?.nodeId,
      edgeIds: [...new Set(done.map((s) => s.via).filter((x): x is string => !!x))],
      path: viewPath(graph, [...new Set(run.steps.map((s) => s.nodeId))]), source: "rules",
    });
  }, [step, run, graph, setHighlight]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (t && (t.tagName === "SELECT" || t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) return;
      if (e.key === "ArrowRight") { setPlaying(false); setStep((s) => Math.min(s + 1, last)); }
      if (e.key === "ArrowLeft") { setPlaying(false); setStep((s) => Math.max(s - 1, 0)); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [last]);

  if (!cur) return <p className="text-sm text-ink-dim">Nothing happened in this run.</p>;
  const label = (id: string) => graph.nodes.find((n) => n.id === id)?.label ?? id;
  const node = graph.nodes.find((n) => n.id === cur.nodeId);

  return (
    <>
      <div>
        <h2 className="text-base font-semibold">{run.scenario.title}</h2>
        <p className="mt-0.5 text-sm text-ink-dim">{run.scenario.blurb}</p>
      </div>

      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Playback">
        <button onClick={() => { setPlaying(false); setStep(0); }} aria-label="Back to the first step" className="rounded-lg border border-line p-1.5 text-ink-dim hover:text-ink"><RotateCcw size={14} /></button>
        <button onClick={() => { setPlaying(false); setStep((s) => Math.max(0, s - 1)); }} disabled={step === 0} aria-label="Previous step" className="rounded-lg border border-line p-1.5 text-ink-dim hover:text-ink disabled:opacity-40"><ChevronLeft size={14} /></button>
        <button onClick={() => { if (step >= last) setStep(0); setPlaying((p) => !(p && step < last)); }} disabled={reduced}
          title={reduced ? "Reduced motion is on: use the step buttons" : undefined} aria-label={running ? "Pause" : "Play"}
          className="flex items-center gap-1.5 rounded-lg border border-accent/50 bg-accent/10 px-3 py-1.5 text-xs font-medium text-ink disabled:opacity-40">
          {running ? <Pause size={14} aria-hidden /> : <Play size={14} aria-hidden />}{running ? "Pause" : "Play"}
        </button>
        <button onClick={() => { setPlaying(false); setStep((s) => Math.min(last, s + 1)); }} disabled={step >= last} aria-label="Next step" className="rounded-lg border border-line p-1.5 text-ink-dim hover:text-ink disabled:opacity-40"><ChevronRight size={14} /></button>
        <div role="radiogroup" aria-label="Speed" className="flex rounded-lg border border-line p-0.5">
          {([1, 2, 4] as const).map((v) => (
            <button key={v} role="radio" aria-checked={speed === v} onClick={() => setSpeed(v)} className={`rounded-md px-2 py-0.5 text-xs ${speed === v ? "bg-raised text-ink" : "text-ink-dim"}`}>{v}×</button>
          ))}
        </div>
        <span className="ml-auto text-xs text-ink-faint" aria-hidden>Step {step + 1} of {run.steps.length}</span>
      </div>
      {reduced && <p className="text-xs text-ink-faint">Reduced motion is on, so nothing plays by itself. Use the arrow buttons or the arrow keys.</p>}

      <div aria-live="polite" className={`rounded-xl border p-3 ${cur.ok ? "border-line bg-raised/50" : "border-failing/50 bg-failing/10"}`}>
        <div className="flex items-start gap-2.5">
          <span className={`mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full ${cur.ok ? "bg-nominal/20 text-nominal" : "bg-failing/20 text-failing"}`}>
            {cur.ok ? <Check size={12} aria-label="worked" /> : <X size={12} aria-label="failed" />}
          </span>
          <div className="min-w-0">
            <div className="text-xs text-ink-faint"><span className="sr-only">Step {step + 1} of {run.steps.length}. </span>{node?.label ?? label(cur.nodeId)}</div>
            <p className="mt-0.5 text-sm text-ink">{cur.text[persona]}</p>
            {cur.evidence.length > 0 && (
              <p className="mt-1.5 flex flex-wrap gap-1.5" aria-label="Where this is in the code">
                {cur.evidence.map((e) => <code key={e} className="rounded bg-surface px-1.5 py-0.5 font-mono text-[11px] text-ink-dim">{e}</code>)}
              </p>
            )}
          </div>
        </div>
      </div>

      <details className="text-xs text-ink-dim">
        <summary className="cursor-pointer select-none text-ink-faint">All {run.steps.length} steps</summary>
        <ol className="mt-2 space-y-1">
          {run.steps.map((s) => (
            <li key={s.index}>
              <button onClick={() => { setPlaying(false); setStep(s.index); }} aria-current={s.index === step ? "step" : undefined}
                className={`flex w-full items-center gap-2 rounded px-2 py-1 text-left hover:bg-raised ${s.index === step ? "bg-raised text-ink" : ""}`}>
                {s.ok ? <Check size={12} className="text-nominal" aria-label="worked" /> : <X size={12} className="text-failing" aria-label="failed" />}
                <span className="truncate">{s.index + 1}. {label(s.nodeId)}</span>
              </button>
            </li>
          ))}
        </ol>
      </details>

      {children}
    </>
  );
}
