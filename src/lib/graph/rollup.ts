import type { Status, TwinNode } from "./types";

/**
 * Health rolls up bottom-up (L2 -> L1 -> L0).
 *
 *  - "unknown" children carry no signal and are ignored, unless every child is unknown.
 *  - A failing child fails its parent if it is important (criticality >= 2), otherwise it only degrades it.
 *  - A parent also fails when failing children hold >= half of the weighted vote.
 *  - Score is a weighted mean pulled toward the worst child, so one bad part is never hidden by many good ones.
 */
export function rollupState(kids: Pick<TwinNode, "state" | "criticality">[]): Status {
  const known = kids.filter((k) => k.state !== "unknown");
  if (!known.length) return "unknown";

  const total = known.reduce((a, k) => a + k.criticality, 0);
  const failingWeight = known.filter((k) => k.state === "failing").reduce((a, k) => a + k.criticality, 0);

  if (known.some((k) => k.state === "failing" && k.criticality >= 2)) return "failing";
  if (failingWeight / total >= 0.5) return "failing";
  if (known.some((k) => k.state === "failing" || k.state === "degraded")) return "degraded";
  return "nominal";
}

export function rollupScore(kids: Pick<TwinNode, "score" | "criticality" | "state">[]): number {
  const known = kids.filter((k) => k.state !== "unknown");
  if (!known.length) return 0.5;
  const total = known.reduce((a, k) => a + k.criticality, 0);
  const mean = known.reduce((a, k) => a + k.score * k.criticality, 0) / total;
  const worst = Math.min(...known.map((k) => k.score));
  return 0.5 * mean + 0.5 * worst;
}

/** Pure: feed it raw (un-rolled) nodes. Returns a new node array with every parent's state/score/reasons derived from its children. */
export function rollup(nodes: TwinNode[]): TwinNode[] {
  const out = nodes.map((n) => ({ ...n }));
  for (const level of [1, 0] as const) {
    for (const parent of out.filter((p) => p.level === level)) {
      const kids = out.filter((k) => k.parentId === parent.id);
      if (!kids.length) continue;
      parent.state = rollupState(kids);
      parent.score = rollupScore(kids);
      // a node's own evidence-backed reasons win; only synthesise one from children when it has none
      if (parent.reasons.length === 0) parent.reasons = kids
        .filter((k) => k.state === "failing" || k.state === "degraded")
        .sort((a, b) => Number(b.state === "failing") - Number(a.state === "failing"))
        .map((k) => `${k.label} is ${k.state}`);
    }
  }
  return out;
}
