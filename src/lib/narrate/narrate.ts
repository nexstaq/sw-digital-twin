import { generateText, Output } from "ai";
import type { TwinGraph } from "@/lib/graph/types";
import { applyNarrative } from "./apply";
import { cacheKey, type NarrativeCache } from "./cache";
import { NO_MODEL_HINT, resolveModel, type ResolvedModel } from "./model";
import { buildInput, PROMPT_VERSION, SYSTEM_PROMPT, userPrompt } from "./prompt";
import { ruleStory } from "./rules";
import { LlmNarrativeSchema, type LlmNarrative } from "./schema";
import { validate } from "./validate";

export interface NarrateOptions {
  model?: ResolvedModel | null;
  cache?: NarrativeCache;
  /** opt-in free text from the README; default is metadata only */
  readme?: string;
  signal?: AbortSignal;
  /** private repo: only a gateway model may be used, never the free dev key */
  private?: boolean;
  /** test seam: replaces the model call */
  generate?: (system: string, prompt: string) => Promise<LlmNarrative>;
}

export interface NarrateResult {
  graph: TwinGraph;
  source: "ai" | "cached" | "rules";
  /** shown to the user when we could not use the model */
  warning?: string;
}

async function callModel(m: ResolvedModel, system: string, prompt: string, signal?: AbortSignal): Promise<LlmNarrative> {
  const { output } = await generateText({
    model: m.model, system, prompt, temperature: 0.2, maxRetries: 1,
    output: Output.object({ schema: LlmNarrativeSchema }),
    abortSignal: signal ? AbortSignal.any([signal, AbortSignal.timeout(90_000)]) : AbortSignal.timeout(90_000),
  });
  return output;
}

/** Deterministic graph in, graph with validated plain-English layer out. Never throws: falls back to rules. */
export async function narrate(graph: TwinGraph, opts: NarrateOptions = {}): Promise<NarrateResult> {
  const fallback = (warning?: string): NarrateResult => ({ graph: { ...graph, story: ruleStory(graph) }, source: "rules", warning });
  if (graph.nodes.length === 0) return { graph, source: "rules" };

  const model = opts.model === undefined ? resolveModel(process.env, { allowDevKey: !opts.private }) : opts.model;
  if (!model && !opts.generate) return fallback(NO_MODEL_HINT);
  const modelId = model?.id ?? "test";

  const { input, refs } = buildInput(graph, { readme: opts.readme });
  const key = cacheKey({ v: PROMPT_VERSION, model: modelId, input });

  try {
    let raw = await opts.cache?.get(key);
    let source: NarrateResult["source"] = "cached";
    if (!raw) {
      source = "ai";
      const system = SYSTEM_PROMPT;
      const prompt = userPrompt(input);
      raw = opts.generate ? await opts.generate(system, prompt) : await callModel(model!, system, prompt, opts.signal);
    }
    const v = validate(raw, graph, refs);
    if (v.narratives.size === 0) return fallback("The AI descriptions could not be verified against the code, so rule-based ones are shown.");
    if (source === "ai") await opts.cache?.set(key, raw); // only cache what produced something usable
    const warning = v.stats.dropped + v.stats.downgraded > 0
      ? `${v.stats.dropped} AI description(s) dropped and ${v.stats.downgraded} marked lower confidence because they cited evidence that does not exist.`
      : undefined;
    return { graph: applyNarrative(graph, v, modelId), source, warning };
  } catch (e) {
    const msg = e instanceof Error ? e.message : "unknown error";
    return fallback(describeAiFailure(msg));
  }
}

/** Provider errors are written for developers; say what to do about the common ones, and keep the rest short. */
export function describeAiFailure(msg: string): string {
  if (/credit card|payment method|billing|insufficient (funds|credit)|quota/i.test(msg)) {
    return "AI descriptions are off: the AI provider needs a payment method or credit on its account. Rule-based descriptions are shown.";
  }
  if (/api key|unauthori[sz]ed|forbidden|permission|\b40[13]\b/i.test(msg)) {
    return "AI descriptions are off: the AI provider rejected the key. Rule-based descriptions are shown.";
  }
  return `AI descriptions failed (${msg.slice(0, 120)}); rule-based ones are shown.`;
}
