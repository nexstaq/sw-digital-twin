"use client";

import { useSyncExternalStore } from "react";
import { BaseEdge, getBezierPath, type Edge, type EdgeProps } from "@xyflow/react";

const query = "(prefers-reduced-motion: reduce)";
function subscribe(cb: () => void) {
  const m = window.matchMedia(query);
  m.addEventListener("change", cb);
  return () => m.removeEventListener("change", cb);
}
export function useReducedMotion() {
  return useSyncExternalStore(subscribe, () => window.matchMedia(query).matches, () => false);
}

/** The line plus flowing particles. Particle count/speed track throughput; red + flicker on errors. */
export function EdgeGlyph({ path, throughput, errorRate, id, faded = false }: { path: string; throughput: number; errorRate: number; id: string; faded?: boolean }) {
  const reduced = useReducedMotion();
  const bad = errorRate > 0.05;
  const color = bad ? "var(--color-failing)" : "var(--color-accent)";
  const count = 1 + Math.round(throughput * 3);
  const dur = 4.2 - throughput * 2.6;
  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        className={bad && !reduced ? "edge-flicker" : undefined}
        style={{ stroke: color, opacity: faded ? 0.12 : 1, transition: "opacity .2s", strokeOpacity: bad ? 0.7 : 0.3, strokeWidth: 1.5 + throughput * 1.5, strokeDasharray: bad ? "6 4" : undefined }}
      />
      {!reduced && !faded &&
        Array.from({ length: count }, (_, i) => (
          <circle key={i} r={bad ? 3 : 2.5} fill={color}>
            <animateMotion dur={`${dur}s`} begin={`${-(dur / count) * i}s`} repeatCount="indefinite" path={path} />
          </circle>
        ))}
    </>
  );
}

export type FlowEdge = Edge<{ throughput: number; errorRate: number; faded?: boolean }, "flow">;

export function AnimatedEdge(p: EdgeProps<FlowEdge>) {
  const [path] = getBezierPath(p);
  return <EdgeGlyph id={p.id} path={path} throughput={p.data?.throughput ?? 0.5} errorRate={p.data?.errorRate ?? 0} faded={p.data?.faded} />;
}
