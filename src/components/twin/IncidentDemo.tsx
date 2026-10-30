"use client";

import { useMemo, useState } from "react";
import { scenarioGraph, scenarioMappings, scenarioSignals } from "@/lib/demo/incident";
import { Canvas } from "./Canvas";
import { useHealthView } from "./useHealthView";

/** A seeded incident running through the real health engine, anomaly detector and incident finder. Synthetic data. */
export function IncidentDemo() {
  const [anchor] = useState(() => Date.now());
  const base = useMemo(() => scenarioGraph(), []);
  const signals = useMemo(() => scenarioSignals(anchor), [anchor]);
  const { graph, incident } = useHealthView(base, signals, scenarioMappings);
  return <Canvas graph={graph} incident={incident} anchor={anchor} />;
}
