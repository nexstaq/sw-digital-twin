import { ancestry, culprits } from "./nav";
import type { TwinGraph } from "./types";

export type Tone = "nominal" | "degraded" | "failing" | "unknown";

export interface Blocker {
  id: string;
  label: string;
  state: "failing" | "degraded";
  reason: string;
  /** zoom path that reveals it */
  path: string[];
}

export interface Verdict {
  word: "GO" | "HOLD" | "NO-GO" | "NO DATA";
  tone: Tone;
  /** one line for the banner */
  why: string;
  /** the rule that produced the word, in plain English, so the verdict can be audited */
  rule: string;
  blockers: Blocker[];
  /** share of top-level blocks that report any signal */
  coverage: { known: number; total: number };
}

const RULES = {
  "NO-GO": "NO-GO: at least one top-level block is failing. A failing important part fails its block.",
  HOLD: "HOLD: nothing is failing, but at least one block is degraded (flaky, or passing less than 80% recently).",
  GO: "GO: every block that reports a signal is healthy and nothing is failing or degraded.",
  "NO DATA": "NO DATA: no live signal is connected yet, so we cannot say anything is healthy.",
} as const;

/** Explainable, rule-based launch verdict. Pure: same graph in, same verdict out. */
export function explainVerdict(graph: TwinGraph): Verdict {
  const top = graph.nodes.filter((n) => !n.parentId);
  const known = top.filter((n) => n.state !== "unknown").length;
  const coverage = { known, total: top.length };
  const blockers: Blocker[] = culprits(graph).map((n) => ({
    id: n.id, label: n.label, state: n.state as "failing" | "degraded",
    reason: n.reasons[0] ?? `${n.label} is ${n.state}`, path: ancestry(graph, n.id),
  }));

  if (top.length && known === 0) return { word: "NO DATA", tone: "unknown", why: "Connect a live source to see health", rule: RULES["NO DATA"], blockers, coverage };
  const failing = top.filter((n) => n.state === "failing");
  if (failing.length) return { word: "NO-GO", tone: "failing", why: `${failing.map((n) => n.label).join(", ")} failing`, rule: RULES["NO-GO"], blockers, coverage };
  const degraded = top.filter((n) => n.state === "degraded");
  if (degraded.length) return { word: "HOLD", tone: "degraded", why: `${degraded.length} area${degraded.length > 1 ? "s" : ""} degraded`, rule: RULES.HOLD, blockers, coverage };
  return { word: "GO", tone: "nominal", why: known < top.length ? `All ${known} monitored areas nominal (${top.length - known} not monitored)` : "All monitored systems nominal", rule: RULES.GO, blockers, coverage };
}
