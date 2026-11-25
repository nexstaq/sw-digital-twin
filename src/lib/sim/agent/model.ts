import { resolveModel, type ResolvedModel } from "@/lib/narrate/model";

/**
 * Which model an agent may use. The rule, in one place: a private repository NEVER goes to a free-tier model, because free-tier
 * prompts may be used by the provider to improve its products. `resolveModel` already withholds the free dev key when told the repo
 * is private; this adds a second check on the model that comes back, so a change in one place cannot quietly break the rule.
 */

export type ModelChoice = { ok: true; model: ResolvedModel } | { ok: false; reason: string };

/** The model id is `google/...` only when the free dev key is in use (the gateway uses `provider/model` for everyone else, and is not free-tier). */
export const isFreeTier = (id: string) => /^google\//i.test(id);

export function modelPolicyError(modelId: string, isPrivate: boolean): string | null {
  if (isPrivate && isFreeTier(modelId)) return "A private repository cannot use a free-tier model. Configure the AI Gateway for private repositories.";
  return null;
}

export function resolveAgentModel(o: { private: boolean; env?: NodeJS.ProcessEnv }): ModelChoice {
  const m = resolveModel(o.env ?? process.env, { allowDevKey: !o.private });
  if (!m) return { ok: false, reason: o.private ? "No model is available for private repositories. Configure the AI Gateway (AI_GATEWAY_API_KEY)." : "No model is configured. Set AI_GATEWAY_API_KEY or GOOGLE_GENERATIVE_AI_API_KEY." };
  const bad = modelPolicyError(m.id, o.private);
  return bad ? { ok: false, reason: bad } : { ok: true, model: m };
}

/** Dollars per million tokens. An unknown model is priced HIGH, so the cost cap trips early rather than late. */
const PRICES: [RegExp, { in: number; out: number }][] = [
  [/opus/i, { in: 15, out: 75 }],
  [/sonnet/i, { in: 3, out: 15 }],
  [/haiku/i, { in: 1, out: 5 }],
  [/gemini.*flash/i, { in: 0.3, out: 2.5 }],
];
const UNKNOWN = { in: 15, out: 75 };

export function costUsd(modelId: string, inputTokens: number, outputTokens: number): number {
  const p = PRICES.find(([re]) => re.test(modelId))?.[1] ?? UNKNOWN;
  return (Math.max(0, inputTokens) * p.in + Math.max(0, outputTokens) * p.out) / 1_000_000;
}
