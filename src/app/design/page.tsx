"use client";

import { fixtureGraph } from "@/lib/graph/fixture";
import type { Status } from "@/lib/graph/types";
import { EdgeGlyph } from "@/components/twin/AnimatedEdge";
import { GoNoGoBanner } from "@/components/twin/GoNoGoBanner";
import { LensSwitcher } from "@/components/twin/LensSwitcher";
import { NodeTileView } from "@/components/twin/NodeTile";
import { StatusRing, Sparkline } from "@/components/twin/status";
import { TimelineScrubber } from "@/components/twin/TimelineScrubber";

const STATES: Status[] = ["nominal", "degraded", "failing", "unknown"];
const sample = (s: Status) => fixtureGraph.nodes.find((n) => n.state === s && n.level === 1)!;

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-4">
      <h2 className="text-xs font-medium uppercase tracking-widest text-ink-faint">{title}</h2>
      {children}
    </section>
  );
}

export default function DesignPage() {
  const byState = (s: Status) => fixtureGraph.nodes.filter((n) => n.level === 0 && n.state === s);
  return (
    <main className="mx-auto max-w-5xl space-y-12 px-6 py-10">
      <h1 className="text-2xl font-semibold">Design system</h1>

      <Section title="Status ring (colour + distinct shape)">
        <div className="flex gap-8">{STATES.map((s) => <div key={s} className="flex items-center gap-3"><StatusRing status={s} size={36} /><span className="text-sm capitalize">{s}</span></div>)}</div>
      </Section>

      <Section title="Node tile">
        <div className="flex flex-wrap gap-5">{STATES.map((s) => <NodeTileView key={s} node={sample(s)} />)}</div>
        <div className="flex flex-wrap gap-5">
          <NodeTileView node={sample("failing")} selected />
          <NodeTileView node={fixtureGraph.nodes.find((n) => n.id === "pay")!} childCount={4} />
          <NodeTileView node={sample("nominal")} dim />
        </div>
      </Section>

      <Section title="Sparkline">
        <div className="flex gap-8">{STATES.map((s) => <Sparkline key={s} values={sample(s).spark} status={s} w={140} h={36} />)}</div>
      </Section>

      <Section title="Animated edge (throughput 0.2 / 0.9 / error)">
        <svg width="100%" height="150" className="rounded-xl border border-line bg-surface">
          <EdgeGlyph id="d1" path="M 30 30 C 300 30, 300 30, 780 30" throughput={0.2} errorRate={0} />
          <EdgeGlyph id="d2" path="M 30 75 C 300 75, 300 75, 780 75" throughput={0.9} errorRate={0} />
          <EdgeGlyph id="d3" path="M 30 120 C 300 120, 300 120, 780 120" throughput={0.6} errorRate={0.3} />
        </svg>
      </Section>

      <Section title="Go / No-Go banner">
        <div className="flex flex-wrap gap-8">
          <GoNoGoBanner graph={{ ...fixtureGraph, nodes: byState("nominal") }} />
          <GoNoGoBanner graph={{ ...fixtureGraph, nodes: byState("degraded") }} />
          <GoNoGoBanner graph={{ ...fixtureGraph, nodes: byState("failing") }} />
        </div>
      </Section>

      <Section title="Lens switcher"><LensSwitcher /></Section>
      <Section title="Timeline scrubber"><div className="overflow-hidden rounded-xl border border-line"><TimelineScrubber deploys={fixtureGraph.deploys} /></div></Section>
    </main>
  );
}
