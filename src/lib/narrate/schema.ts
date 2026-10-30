import { z } from "zod";

/** What we ask the model to return. Lengths are enforced afterwards (truncate) so one long string never voids a response. */
export const LlmNarrativeSchema = z.object({
  headline: z.string().describe("One plain sentence describing what this software is and does."),
  nodes: z.array(z.object({
    id: z.string().describe("Exactly one of the node ids provided."),
    name: z.string().describe("Human-friendly name, at most 4 words."),
    purpose: z.string().describe("One short line on what it is for."),
    exec: z.string().describe("1-2 sentences for a non-technical leader: what it does and why it matters. No jargon."),
    engineer: z.string().describe("1-2 sentences for an engineer: stack, entry points, notable dependencies."),
    security: z.string().describe("1-2 sentences on exposure: public endpoints, data stores, third parties. Say so if nothing notable."),
    citations: z.array(z.string()).describe("Evidence ref ids (like e12) that support these statements."),
    confidence: z.enum(["high", "medium", "low"]),
  })),
  flow: z.array(z.string()).describe("Top-level (level 0) node ids ordered left-to-right: delivery first, then services, then data, then external."),
  tour: z.array(z.object({
    nodeId: z.string(),
    title: z.string(),
    caption: z.string().describe("At most 2 sentences, spoken style."),
  })).describe("5 to 10 steps walking through the level 0 nodes in a sensible order."),
});

export type LlmNarrative = z.infer<typeof LlmNarrativeSchema>;
