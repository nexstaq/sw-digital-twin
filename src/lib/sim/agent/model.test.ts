import { describe, expect, it } from "vitest";
import { costUsd, isFreeTier, modelPolicyError, resolveAgentModel } from "./model";

const env = (o: Record<string, string>) => o as unknown as NodeJS.ProcessEnv;

describe("a private repository never uses a free-tier model", () => {
  it("the free dev key is withheld, and so nothing is available if it is the only key", () => {
    const r = resolveAgentModel({ private: true, env: env({ GOOGLE_GENERATIVE_AI_API_KEY: "k" }) });
    expect(r).toMatchObject({ ok: false, reason: expect.stringMatching(/private/i) });
  });
  it("the gateway is available for a private repository", () => {
    const r = resolveAgentModel({ private: true, env: env({ AI_GATEWAY_API_KEY: "k" }) });
    expect(r).toMatchObject({ ok: true, model: { id: expect.stringMatching(/^[a-z]+\//) } });
    expect(r.ok && isFreeTier(r.model.id)).toBe(false);
  });
  it("a public repository may use the dev key, and prefers the gateway when both exist", () => {
    expect(resolveAgentModel({ private: false, env: env({ GOOGLE_GENERATIVE_AI_API_KEY: "k" }) })).toMatchObject({ ok: true, model: { id: expect.stringMatching(/^google\//) } });
    const both = resolveAgentModel({ private: false, env: env({ GOOGLE_GENERATIVE_AI_API_KEY: "k", AI_GATEWAY_API_KEY: "g" }) });
    expect(both.ok && isFreeTier(both.model.id)).toBe(false);
  });
  it("nothing configured says so", () => { expect(resolveAgentModel({ private: false, env: env({}) })).toMatchObject({ ok: false }); });
  it("the second check catches a free-tier model even if the first were bypassed", () => {
    expect(modelPolicyError("google/gemini-2.5-flash", true)).toMatch(/free-tier/);
    expect(modelPolicyError("google/gemini-2.5-flash", false)).toBeNull();
    expect(modelPolicyError("anthropic/claude-sonnet-5-5", true)).toBeNull();
  });
});

describe("cost", () => {
  it("is priced per million tokens by model family", () => {
    expect(costUsd("anthropic/claude-sonnet-5-5", 1_000_000, 1_000_000)).toBeCloseTo(18);
    expect(costUsd("anthropic/claude-haiku-5-5", 1_000_000, 0)).toBeCloseTo(1);
    expect(costUsd("anthropic/claude-opus-5-5", 1_000_000, 1_000_000)).toBeCloseTo(90);
    expect(costUsd("google/gemini-2.5-flash", 1_000_000, 1_000_000)).toBeCloseTo(2.8);
  });
  it("an unknown model is priced at the top rate, so the cap trips early", () => {
    expect(costUsd("someone/new-model", 1_000_000, 1_000_000)).toBeCloseTo(90);
    expect(costUsd("someone/new-model", 1000, 1000)).toBeGreaterThan(costUsd("anthropic/claude-haiku-5-5", 1000, 1000));
  });
  it("never goes negative", () => { expect(costUsd("x/y", -5, -5)).toBe(0); });
});
