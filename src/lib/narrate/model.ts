import { google } from "@ai-sdk/google";
import type { LanguageModel } from "ai";

export interface ResolvedModel {
  /** what we call it in the cache key and UI */
  id: string;
  model: LanguageModel;
}

/**
 * Picks the model from the environment. The app never hard-codes a provider.
 *  1. AI Gateway (AI_GATEWAY_API_KEY, or a Vercel OIDC token when deployed): "provider/model" string, any provider.
 *  2. Google Gemini direct (GOOGLE_GENERATIVE_AI_API_KEY): handy for dev with a free key. Public repos only:
 *     free-tier prompts may be used by Google to improve its products.
 *  3. Nothing configured: null, and the app falls back to rule-based descriptions.
 */
export function resolveModel(env: NodeJS.ProcessEnv = process.env, o: { allowDevKey?: boolean } = {}): ResolvedModel | null {
  if (env.AI_GATEWAY_API_KEY || env.VERCEL_OIDC_TOKEN) {
    const id = env.NARRATE_MODEL || "anthropic/claude-sonnet-5-5";
    return { id, model: id };
  }
  // a free-tier key may train on prompts: fine for public repos in dev, never for private ones
  if (env.GOOGLE_GENERATIVE_AI_API_KEY && o.allowDevKey !== false) {
    const id = env.NARRATE_GOOGLE_MODEL || "gemini-2.5-flash";
    return { id: `google/${id}`, model: google(id) };
  }
  return null;
}

export const NO_MODEL_HINT =
  "Plain-English descriptions are off. Set AI_GATEWAY_API_KEY (any provider) or GOOGLE_GENERATIVE_AI_API_KEY (dev) to enable them.";
