"use client";

import { useMemo } from "react";
import type { TwinGraph } from "@/lib/graph/types";
import { signalsAt } from "@/lib/health/at";
import { applyHealth } from "@/lib/health/engine";
import { findIncident, sampleFrames, type Incident } from "@/lib/health/incident";
import type { SignalSet } from "@/lib/health/signals";
import { useTwin } from "@/lib/store";

export const HOUR = 3_600_000;

/**
 * The graph with health applied for the moment the time scrubber points at (live when it is at 0), plus the most
 * serious incident found in the last 48 hours. Everything is a pure function of (graph, signals, scrubber).
 */
export function useHealthView(base: TwinGraph, signals: SignalSet | null, mappings: Record<string, string> = {}) {
  const scrub = useTwin((s) => s.scrub);
  const anchor = signals?.fetchedAt ?? 0;

  const merged = useMemo(() => (signals ? { ...signals, mappings: { ...signals.mappings, ...mappings } } : null), [signals, mappings]);

  const graph = useMemo(() => {
    if (!merged) return base;
    const t = anchor - scrub * HOUR;
    return applyHealth(base, scrub === 0 ? merged : signalsAt(merged, t), t);
  }, [base, merged, anchor, scrub]);

  const incident = useMemo<Incident | null>(() => {
    if (!merged || !((merged.runtime?.length ?? 0) > 0 || merged.runs.length >= 3)) return null;
    return findIncident(base, sampleFrames(base, merged, { to: anchor }));
  }, [base, merged, anchor]);

  return { graph, incident, anchor };
}
