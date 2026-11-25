import { generateText, isStepCount, Output, tool } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { describe, expect, it } from "vitest";
import { z } from "zod";

/**
 * Contract test for the AI SDK behaviours the agent runtime depends on. If an SDK upgrade changes one of these, this fails first
 * and says which assumption broke, instead of the runtime misbehaving quietly. (File name kept from the first spike.)
 */

const usage = (i: number, o: number) => ({ inputTokens: { total: i, noCache: i, cacheRead: undefined, cacheWrite: undefined }, outputTokens: { total: o, text: o, reasoning: undefined } });
const callTool = (toolName: string, input: unknown, id = "c1") => ({ content: [{ type: "tool-call" as const, toolCallId: id, toolName, input: typeof input === "string" ? input : JSON.stringify(input) }], finishReason: { unified: "tool-calls" as const, raw: undefined }, usage: usage(10, 5), warnings: [] });
const say = (text: string) => ({ content: [{ type: "text" as const, text }], finishReason: { unified: "stop" as const, raw: undefined }, usage: usage(20, 7), warnings: [] });
const scripted = (...turns: unknown[]) => { let n = 0; return new MockLanguageModelV4({ doGenerate: async () => turns[Math.min(n++, turns.length - 1)] as never }); };
const ping = (calls: unknown[]) => tool({ description: "ping", inputSchema: z.object({ x: z.number() }), execute: async (i) => { calls.push(i); return { ok: true }; } });

describe("the SDK behaves the way the runtime assumes", () => {
  it("runs a tool, reports token usage per step in inputTokens and outputTokens, and returns structured output", async () => {
    const calls: unknown[] = [];
    const used: { inputTokens?: number; outputTokens?: number }[] = [];
    const r = await generateText({
      model: scripted(callTool("ping", { x: 1 }), say(JSON.stringify({ done: true }))), prompt: "go", stopWhen: isStepCount(5),
      output: Output.object({ schema: z.object({ done: z.boolean() }) }), tools: { ping: ping(calls) }, onStepFinish: (s) => { used.push(s.usage); },
    });
    expect(r.output).toEqual({ done: true });
    expect(calls).toEqual([{ x: 1 }]);
    expect(used.map((u) => [u.inputTokens, u.outputTokens])).toEqual([[10, 5], [20, 7]]);
  });

  it("a custom stop condition ends the loop even though the model keeps calling tools", async () => {
    const calls: unknown[] = [];
    const model = scripted(callTool("ping", { x: 1 }));
    const r = await generateText({ model, prompt: "go", tools: { ping: ping(calls) }, stopWhen: [isStepCount(50), () => calls.length >= 3] });
    expect(calls).toHaveLength(3);
    expect(r.steps).toHaveLength(3);
  });

  it("with no explicit limit the loop is still bounded by the step count we set", async () => {
    const calls: unknown[] = [];
    await generateText({ model: scripted(callTool("ping", { x: 1 })), prompt: "go", tools: { ping: ping(calls) }, stopWhen: isStepCount(4) });
    expect(calls).toHaveLength(4);
  });

  it("an abort signal ends the call afterwards, but does NOT stop the tool call already in the model's reply", async () => {
    // So the kill switch cannot rely on aborting: the runtime's guard must refuse the call itself (runtime.test.ts proves it does).
    const ac = new AbortController();
    const calls: unknown[] = [];
    const model = new MockLanguageModelV4({ doGenerate: async () => { ac.abort(); return callTool("ping", { x: 1 }) as never; } });
    await generateText({ model, prompt: "go", tools: { ping: ping(calls) }, stopWhen: isStepCount(5), abortSignal: ac.signal }).catch(() => undefined);
    expect(calls).toHaveLength(1);
  });

  it("arguments that do not match the schema never reach execute", async () => {
    const calls: unknown[] = [];
    const model = scripted(callTool("ping", { x: "not a number" }), say("done"));
    await generateText({ model, prompt: "go", tools: { ping: ping(calls) }, stopWhen: isStepCount(3) }).catch(() => undefined);
    expect(calls).toHaveLength(0);
  });

  it("a tool the model invents never runs anything", async () => {
    const calls: unknown[] = [];
    const model = scripted(callTool("format_disk", { x: 1 }), say("done"));
    await generateText({ model, prompt: "go", tools: { ping: ping(calls) }, stopWhen: isStepCount(3) }).catch(() => undefined);
    expect(calls).toHaveLength(0);
  });

  it("a tool that throws does not crash the loop: the model is told, and can carry on", async () => {
    const boom = tool({ description: "boom", inputSchema: z.object({}), execute: async (): Promise<string> => { throw new Error("kaboom"); } });
    const r = await generateText({ model: scripted(callTool("boom", {}), say("recovered")), prompt: "go", tools: { boom }, stopWhen: isStepCount(3) });
    expect(r.text).toBe("recovered");
  });
});
