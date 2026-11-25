import { applyHealth } from "@/lib/health/engine";
import type { Status, TwinGraph } from "@/lib/graph/types";
import { rangeSignals } from "../range/health";
import { startRange } from "../range/runtime";
import type { Fault, RangeSpec, WorkflowResult } from "../range/types";
import { execute, type SimRun } from "./play";
import type { Scenario } from "./scenario";

/**
 * "What happens to the health of the map if this part breaks?" Answered by the real health engine, not by a rule written here:
 * the scenario is run as steady traffic (healthy, then with the fault), the range's events become the same signals the real
 * connectors produce, and `applyHealth` judges them. A fault changes a block's colour exactly when the engine would change it.
 *
 * What the colours mean: only blocks the simulation touched have a colour. Everything else is "unknown", never a guessed green,
 * and the colours describe the simulation, not the real system.
 */

const BUCKET = 5 * 60_000;
/** The engine needs 6 readings to know what "normal" is before it will call anything slow (see anomaly.ts), plus 2 to be sure. */
const HEALTHY_ROUNDS = 8;
const FAULT_ROUNDS = 3;
const PER_ROUND = 20;

export interface Change { nodeId: string; label: string; before: Status; after: Status; reasons: string[] }
export interface SimHealth { graph: TwinGraph; changed: Change[] }

/** steady traffic for a while, then the same again with the fault (if any) switched on; returns the map as the engine sees it at the end */
function health(spec: RangeSpec, graph: TwinGraph, sc: Scenario, baseTs: number, fault?: { nodeId: string; fault: Fault }): TwinGraph {
  const r = startRange(spec, { maxEvents: 60_000 });
  const workflows: WorkflowResult[] = [];
  const round = () => {
    for (let i = 0; i < (sc.kind === "workflow" ? 2 : PER_ROUND); i++) { const x = execute(r, sc); if (x.workflow) workflows.push(x.workflow); }
    r.advance(BUCKET);
  };
  for (let i = 0; i < HEALTHY_ROUNDS; i++) round();
  if (fault) r.inject(fault.nodeId, fault.fault);
  for (let i = 0; i < FAULT_ROUNDS; i++) round(); // the same length with or without a fault, so the only difference is the fault
  const now = baseTs + r.now();
  const out = applyHealth(graph, rangeSignals(spec, { events: r.events(), workflows }, { baseTs, now }), now);
  r.finish();
  // an edge into something that is failing shows as an error edge
  const failing = new Set(out.nodes.filter((n) => n.state === "failing").map((n) => n.id));
  return { ...out, edges: out.edges.map((e) => ({ ...e, errorRate: failing.has(e.to) ? 0.5 : 0 })) };
}

export function simulateHealth(spec: RangeSpec, graph: TwinGraph, sc: Scenario, o: { baseTs: number; fault?: { nodeId: string; fault: Fault } }): SimHealth {
  const before = health(spec, graph, sc, o.baseTs);
  if (!o.fault) return { graph: before, changed: [] };
  const after = health(spec, graph, sc, o.baseTs, o.fault);
  const was = new Map(before.nodes.map((n) => [n.id, n.state]));
  const changed = after.nodes
    .filter((n) => n.state !== was.get(n.id))
    .map((n): Change => ({ nodeId: n.id, label: n.label, before: was.get(n.id)!, after: n.state, reasons: n.reasons }))
    .sort((a, b) => a.label.localeCompare(b.label));
  return { graph: after, changed };
}

export type { SimRun };
