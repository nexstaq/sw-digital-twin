// Test helpers for the agent runtime. Not imported by production code.
import { MockLanguageModelV4 } from "ai/test";
import { z } from "zod";
import { buildRange } from "../range/generate";
import { shopFindings, shopGraph } from "../range/fixtures";
import { startRange, type RangeInstance } from "../range/runtime";
import type { RangeSpec } from "../range/types";
import { defineTool, type AnyTool } from "./tools";
import type { AgentRunInput } from "./runtime";
import { inspectTool, requestTool } from "./tools/range";
import { probeTool, type ProbeTransport } from "./tools/probe";
import type { ResolvedModel } from "@/lib/narrate/model";

export const T0 = Date.UTC(2026, 10, 25, 12, 0, 0);

export interface Clock { now: () => number; advance: (ms: number) => void }
export const makeClock = (start = T0): Clock => { let t = start; return { now: () => t, advance: (ms) => { t += ms; } }; };

export interface Rig { spec: RangeSpec; range: RangeInstance; roe: Record<string, unknown> }

/** a range for the shop fixture, and a ROE that names it and nothing else */
export function makeRig(over: Record<string, unknown> = {}): Rig {
  const spec = buildRange({ sha: "b".repeat(40), graph: shopGraph() }, shopFindings());
  const range = startRange(spec);
  const roe = {
    version: 1, runId: "run_t1", repo: "acme/shop",
    targets: [{ kind: "range", rangeId: spec.id }],
    agents: ["whitebox", "graybox", "redteam", "blue", "narrator"],
    allowedClasses: ["observe", "probe", "exploit-range"],
    allowedTechniques: ["T1190", "T1078"], forbiddenTechniques: ["T1486"],
    window: { notBefore: T0 - 3_600_000, notAfter: T0 + 3_600_000 },
    budgets: { steps: 20, tokens: 100_000, wallMs: 30 * 60_000, costUsd: 5 },
    killSwitchId: "kill_t1",
    ...over,
  };
  return { spec, range, roe };
}

/** a ROE that also allows one real site, with the approval that requires */
export const withDomain = (rig: Rig, domain = "shop.example.com") => ({
  ...rig.roe,
  targets: [...(rig.roe.targets as unknown[]), { kind: "verified-domain", domain }],
  approval: { approvedBy: "alice", approvedAt: T0 - 7_200_000 },
  window: { notBefore: T0 - 3_600_000, notAfter: T0 + 3_600_000 },
});

export const MODEL: ResolvedModel = { id: "anthropic/claude-sonnet-5-5", model: "anthropic/claude-sonnet-5-5" };

const usage = (i: number, o: number) => ({ inputTokens: { total: i, noCache: i, cacheRead: undefined, cacheWrite: undefined }, outputTokens: { total: o, text: o, reasoning: undefined } });

export interface Turn { calls?: { name: string; input: unknown }[]; final?: unknown; usage?: [number, number] }
export interface Seen { prompts: string[]; systems: string[]; modelCalls: number }
type Next = (ctx: { n: number; prompt: string; last: string }) => Turn;

const flatten = (p: unknown) => JSON.stringify(p);

/** A model that plays whatever `next` says, one turn per model call, and records everything it was shown. */
export function modelFrom(next: Next, o: { usage?: [number, number] } = {}): { model: ResolvedModel; seen: Seen } {
  const seen: Seen = { prompts: [], systems: [], modelCalls: 0 };
  const m = new MockLanguageModelV4({
    doGenerate: (async (options: { prompt: { role: string; content: unknown }[] }) => {
      seen.modelCalls++;
      const prompt = flatten(options.prompt);
      seen.prompts.push(prompt);
      seen.systems.push(options.prompt.filter((x) => x.role === "system").map((x) => String(x.content)).join("\n"));
      const lastTool = [...options.prompt].reverse().find((x) => x.role === "tool");
      const turn = next({ n: seen.modelCalls, prompt, last: lastTool ? flatten(lastTool.content) : "" });
      const [i, out] = turn.usage ?? o.usage ?? [10, 5];
      if (turn.calls?.length) {
        return { content: turn.calls.map((c, k) => ({ type: "tool-call" as const, toolCallId: `call_${seen.modelCalls}_${k}`, toolName: c.name, input: typeof c.input === "string" ? c.input : JSON.stringify(c.input) })), finishReason: { unified: "tool-calls" as const, raw: undefined }, usage: usage(i, out), warnings: [] };
      }
      return { content: [{ type: "text" as const, text: JSON.stringify(turn.final ?? { findings: [] }) }], finishReason: { unified: "stop" as const, raw: undefined }, usage: usage(i, out), warnings: [] };
    }) as never,
  });
  return { model: { id: MODEL.id, model: m }, seen };
}

/** plays the given turns in order; after the last, repeats it forever (a runaway) unless `then` is given */
export function script(turns: Turn[], o: { loop?: boolean; usage?: [number, number] } = {}) {
  return modelFrom(({ n }) => (n <= turns.length ? turns[n - 1] : o.loop ? turns.at(-1)! : { final: { findings: [] } }), o);
}

/** spy around a tool: counts and records what actually ran */
export function spy<T extends AnyTool>(t: T): { tool: T; ran: unknown[] } {
  const ran: unknown[] = [];
  const wrapped = { ...t, run: async (i: unknown, ctx: never) => { ran.push(i); return t.run(i, ctx); } } as T;
  return { tool: wrapped, ran };
}

export function standardTools(rig: Rig, o: { roles?: readonly ("anonymous" | "user" | "admin")[]; transport?: ProbeTransport } = {}) {
  const request = spy(requestTool({ range: rig.range, spec: rig.spec, roles: o.roles ?? ["anonymous", "user"] }));
  const inspect = spy(inspectTool({ spec: rig.spec }));
  const sent: string[] = [];
  const transport: ProbeTransport = async (url, signal) => { sent.push(url); return o.transport ? o.transport(url, signal) : { status: 200, headers: { server: "test" }, bodyBytes: 10 }; };
  const probe = spy(probeTool({ transport }));
  /** `tools` is what a red-team or white-box agent may have; `all` adds the real-site probe, which only the gray-box agent may have */
  return { tools: [inspect.tool, request.tool] as AnyTool[], all: [inspect.tool, request.tool, probe.tool] as AnyTool[], request, inspect, probe, sent };
}

/** a tool named like a real one whose output we control, for planting hostile text where a response would be */
export const planted = (rig: Rig, name: "range_request" | "range_inspect", body: unknown) =>
  defineTool({
    name, description: name, inputSchema: z.record(z.string(), z.unknown()) as never,
    classOf: () => "observe", techniqueOf: () => undefined, targetOf: () => ({ kind: "range" as const, rangeId: rig.spec.id }), source: "range-response",
    summarize: () => "planted", run: async () => body,
  });

export const baseInput = (rig: Rig, tools: AnyTool[], model: ResolvedModel, over: Partial<AgentRunInput> = {}, clock?: Clock): AgentRunInput => ({
  roe: rig.roe, agent: "redteam", task: "Test the range and report what you find.", tools, model, private: false,
  now: clock?.now ?? makeClock().now, ...over,
});
