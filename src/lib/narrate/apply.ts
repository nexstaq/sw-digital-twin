import type { Story, TwinGraph } from "@/lib/graph/types";
import { ruleStory } from "./rules";
import type { Validated } from "./validate";

export function applyNarrative(graph: TwinGraph, v: Validated, model: string): TwinGraph {
  const nodes = graph.nodes.map((n) => (v.narratives.has(n.id) ? { ...n, narrative: v.narratives.get(n.id) } : n));
  const withNames: TwinGraph = { ...graph, nodes };
  const fallback = ruleStory(withNames);
  const story: Story = {
    headline: v.headline || fallback.headline,
    source: "ai",
    model,
    tour: v.tour.length >= 3 ? v.tour : fallback.tour,
  };
  return { ...withNames, story };
}
