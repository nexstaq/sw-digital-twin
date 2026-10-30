import { describe, expect, it } from "vitest";
import { MockLanguageModelV4 } from "ai/test";
import { fixtureGraph } from "@/lib/graph/fixture";
import { validateGraph } from "@/lib/graph/integrity";
import type { TwinGraph } from "@/lib/graph/types";
import { cacheKey, type NarrativeCache } from "./cache";
import { resolveModel } from "./model";
import { buildInput, PROMPT_VERSION, SYSTEM_PROMPT, userPrompt } from "./prompt";
import { flowOrder, ruleStory } from "./rules";
import type { LlmNarrative } from "./schema";
import { narrate } from "./narrate";
import { validate } from "./validate";

// the fixture ships a hand-written sample narrative for /demo; tests start from the raw analysis
const graph: TwinGraph = structuredClone(fixtureGraph);
graph.story = undefined;
for (const n of graph.nodes) n.narrative = undefined;
const { input, refs } = buildInput(graph);
const refOf = (nodeId: string) => [...refs].find(([, r]) => r.nodeId === nodeId)![0];

const good = (id: string, extra: Partial<LlmNarrative["nodes"][number]> = {}): LlmNarrative["nodes"][number] => ({
  id, name: `Name of ${id}`, purpose: "p", exec: "exec text", engineer: "eng text", security: "sec text",
  citations: [refOf(id)], confidence: "high", ...extra,
});
const l0 = graph.nodes.filter((n) => n.level === 0).map((n) => n.id);
const base = (): LlmNarrative => ({
  headline: "An online shop.",
  nodes: l0.map((id) => good(id)),
  flow: [...l0].reverse(),
  tour: l0.slice(0, 6).map((id) => ({ nodeId: id, title: `T ${id}`, caption: "c" })),
});

describe("prompt input", () => {
  it("contains only analysis metadata: no source text, no README by default", () => {
    expect(input.readme).toBeUndefined();
    const keys = new Set(input.nodes.flatMap((n) => Object.keys(n)));
    expect([...keys].sort()).toEqual(["children", "evidence", "id", "kind", "label", "level", "parent", "summary"].sort());
  });
  it("includes a README excerpt only when explicitly provided, and caps it", () => {
    const { input: i } = buildInput(graph, { readme: "x".repeat(5000) });
    expect(i.readme!.length).toBe(1500);
  });
  it("covers all L0 nodes, caps L1 per parent and drops L2", () => {
    expect(input.nodes.filter((n) => n.level === 0)).toHaveLength(8);
    expect(input.nodes.some((n) => n.level === 2)).toBe(false);
  });
  it("gives every evidence ref a unique id that maps back to its node", () => {
    expect(refs.size).toBe(input.nodes.reduce((a, n) => a + n.evidence.length, 0));
  });
  it("tells the model the data is untrusted", () => expect(SYSTEM_PROMPT).toMatch(/untrusted data/));
  it("wraps the data in tags", () => expect(userPrompt(input)).toContain("<repository_data>"));
});

describe("validate: the model may only describe what the graph backs up", () => {
  it("accepts well-cited nodes", () => {
    const v = validate(base(), graph, refs);
    expect(v.narratives.size).toBe(8);
    expect(v.stats).toEqual({ accepted: 8, downgraded: 0, dropped: 0 });
  });
  it("drops a node whose citations are invented", () => {
    const out = base();
    out.nodes[0] = good(l0[0], { citations: ["e999", "made-up.ts:1"] });
    const v = validate(out, graph, refs);
    expect(v.narratives.has(l0[0])).toBe(false);
    expect(v.stats.dropped).toBe(1);
  });
  it("rejects citations that belong to an unrelated node", () => {
    const out = base();
    out.nodes[0] = good(l0[0], { citations: [refOf(l0[1])] });
    expect(validate(out, graph, refs).narratives.has(l0[0])).toBe(false);
  });
  it("accepts a citation from a child of the node", () => {
    const child = graph.nodes.find((n) => n.parentId === "pay")!;
    const out = base();
    out.nodes = [good("pay", { citations: [refOf(child.id)] })];
    expect(validate(out, graph, refs).narratives.has("pay")).toBe(true);
  });
  it("keeps partly-bad nodes but lowers confidence, keeping only real citations", () => {
    const out = base();
    out.nodes = [good("pay", { citations: [refOf("pay"), "e999"], confidence: "high" })];
    const v = validate(out, graph, refs);
    expect(v.narratives.get("pay")).toMatchObject({ confidence: "medium" });
    expect(v.narratives.get("pay")!.citations).toHaveLength(1);
    expect(v.stats.downgraded).toBe(1);
  });
  it("ignores unknown and duplicate node ids", () => {
    const out = base();
    out.nodes = [good("pay"), good("pay"), { ...good("pay"), id: "ghost" }];
    const v = validate(out, graph, refs);
    expect(v.narratives.size).toBe(1);
    expect(v.stats.dropped).toBe(2);
  });
  it("trims long text instead of failing, and de-duplicates names", () => {
    const out = base();
    out.nodes = [good("pay", { name: "Same", exec: "x".repeat(2000) }), good("web", { name: "same" })];
    const v = validate(out, graph, refs);
    expect(v.narratives.get("pay")!.exec.length).toBeLessThanOrEqual(360);
    expect(v.narratives.get("web")!.name).toBe(graph.nodes.find((n) => n.id === "web")!.label);
  });
  it("completes the flow with any missing L0 nodes and records order", () => {
    const out = base();
    out.flow = ["pay", "ghost", "pay"];
    const v = validate(out, graph, refs);
    expect(v.flow[0]).toBe("pay");
    expect(new Set(v.flow)).toEqual(new Set(l0));
    expect(v.narratives.get("pay")!.order).toBe(0);
  });
  it("keeps only tour steps that point at real level-0 nodes, once each", () => {
    const out = base();
    out.tour = [{ nodeId: "pay", title: "a", caption: "b" }, { nodeId: "pay", title: "dup", caption: "b" }, { nodeId: "ghost", title: "g", caption: "b" }, { nodeId: "f-charge", title: "l2", caption: "b" }];
    expect(validate(out, graph, refs).tour.map((t) => t.nodeId)).toEqual(["pay"]);
  });
});

describe("narrate()", () => {
  it("applies a validated narrative and builds a story", async () => {
    const r = await narrate(graph, { model: null, generate: async () => base() });
    expect(r.source).toBe("ai");
    expect(r.graph.story).toMatchObject({ source: "ai", headline: "An online shop." });
    expect(r.graph.nodes.find((n) => n.id === "pay")!.narrative!.name).toBe("Name of pay");
    expect(validateGraph(r.graph)).toEqual([]);
    expect(graph.nodes.find((n) => n.id === "pay")!.narrative).toBeUndefined(); // input not mutated
  });
  it("falls back to rules when every citation is fake", async () => {
    const out = base();
    out.nodes = out.nodes.map((n) => ({ ...n, citations: ["e999"] }));
    const r = await narrate(graph, { model: null, generate: async () => out });
    expect(r.source).toBe("rules");
    expect(r.warning).toMatch(/could not be verified/);
    expect(r.graph.story!.source).toBe("rules");
  });
  it("falls back to rules (never throws) when the model call fails", async () => {
    const r = await narrate(graph, { model: null, generate: async () => { throw new Error("429 rate limited"); } });
    expect(r.source).toBe("rules");
    expect(r.warning).toMatch(/429/);
    expect(r.graph.story!.tour.length).toBeGreaterThan(0);
  });
  it("without any model configured, uses rules and says how to enable AI", async () => {
    const r = await narrate(graph, { model: null });
    expect(r.source).toBe("rules");
    expect(r.warning).toMatch(/AI_GATEWAY_API_KEY/);
  });
  it("warns when some descriptions were dropped", async () => {
    const out = base();
    out.nodes[0] = good(l0[0], { citations: ["e999"] });
    const r = await narrate(graph, { model: null, generate: async () => out });
    expect(r.warning).toMatch(/1 AI description\(s\) dropped/);
  });
  it("caches by content hash, so a second run makes no model call", async () => {
    const store = new Map<string, LlmNarrative>();
    const cache: NarrativeCache = { get: async (k) => store.get(k) ?? null, set: async (k, v) => void store.set(k, v) };
    let calls = 0;
    const generate = async () => { calls++; return base(); };
    const a = await narrate(graph, { model: null, generate, cache });
    const b = await narrate(graph, { model: null, generate, cache });
    expect([a.source, b.source, calls]).toEqual(["ai", "cached", 1]);
    expect(b.graph.story!.headline).toBe("An online shop.");
  });
  it("cache key changes with the graph, model and prompt version", () => {
    const k = (over: object) => cacheKey({ v: PROMPT_VERSION, model: "m", input, ...over });
    expect(k({})).toBe(k({}));
    expect(k({ model: "other" })).not.toBe(k({}));
    expect(k({ v: "p9" })).not.toBe(k({}));
    expect(k({ input: { ...input, repo: "x/y" } })).not.toBe(k({}));
  });
  it("does not cache a response that produced nothing usable", async () => {
    const store = new Map<string, LlmNarrative>();
    const cache: NarrativeCache = { get: async (k) => store.get(k) ?? null, set: async (k, v) => void store.set(k, v) };
    const out = base(); out.nodes = [];
    await narrate(graph, { model: null, generate: async () => out, cache });
    expect(store.size).toBe(0);
  });
  it("works through the real AI SDK structured-output path (mock model)", async () => {
    const model = new MockLanguageModelV4({
      doGenerate: async () => ({
        content: [{ type: "text", text: JSON.stringify(base()) }],
        finishReason: { unified: "stop", raw: undefined },
        usage: { inputTokens: { total: 1, noCache: 1, cacheRead: undefined, cacheWrite: undefined }, outputTokens: { total: 1, text: 1, reasoning: undefined } },
        warnings: [],
      }),
    });
    const r = await narrate(graph, { model: { id: "mock/x", model } });
    expect(r.source).toBe("ai");
    expect(r.graph.story!.model).toBe("mock/x");
  });
  it("leaves an empty graph alone", async () => {
    const r = await narrate({ ...graph, nodes: [], edges: [] }, { model: null });
    expect(r.graph.nodes).toHaveLength(0);
  });
});

describe("rule-based story", () => {
  it("orders by flow: pipeline before apps before data", () => {
    const order = flowOrder(graph);
    expect(order.indexOf("ci")).toBeLessThan(order.indexOf("release"));
    expect(order.indexOf("release")).toBeLessThan(order.indexOf("pay"));
    expect(order.indexOf("pay")).toBeLessThan(order.indexOf("data"));
    expect(new Set(order)).toEqual(new Set(l0));
  });
  it("survives cycles", () => {
    const cyc: TwinGraph = { ...graph, edges: [...graph.edges, { id: "c", from: "data", to: "ci", kind: "calls", throughput: 0.1, errorRate: 0 }] };
    expect(new Set(flowOrder(cyc))).toEqual(new Set(l0));
  });
  it("makes a tour of at most 10 steps from analysis text", () => {
    const s = ruleStory(graph);
    expect(s.source).toBe("rules");
    expect(s.tour.length).toBeLessThanOrEqual(10);
    expect(s.tour[0].caption.length).toBeGreaterThan(10);
  });
});

describe("resolveModel", () => {
  it("is null without keys", () => expect(resolveModel({} as NodeJS.ProcessEnv)).toBeNull());
  it("prefers the gateway", () => {
    const m = resolveModel({ AI_GATEWAY_API_KEY: "k", GOOGLE_GENERATIVE_AI_API_KEY: "g" } as unknown as NodeJS.ProcessEnv)!;
    expect(m.id).toBe("anthropic/claude-sonnet-5-5");
    expect(typeof m.model).toBe("string");
  });
  it("honours NARRATE_MODEL", () =>
    expect(resolveModel({ AI_GATEWAY_API_KEY: "k", NARRATE_MODEL: "google/gemini-2.5-pro" } as unknown as NodeJS.ProcessEnv)!.id).toBe("google/gemini-2.5-pro"));
  it("uses Gemini directly with only a Google key", () =>
    expect(resolveModel({ GOOGLE_GENERATIVE_AI_API_KEY: "g" } as unknown as NodeJS.ProcessEnv)!.id).toMatch(/^google\//));
});

describe("describeAiFailure", () => {
  it("turns billing and key errors into advice, and keeps unknown errors short", async () => {
    const { describeAiFailure } = await import("./narrate");
    expect(describeAiFailure("AI Gateway requires a valid credit card on file to service requests")).toMatch(/payment method/);
    expect(describeAiFailure("Invalid API key provided")).toMatch(/rejected the key/);
    expect(describeAiFailure("x".repeat(500)).length).toBeLessThan(200);
  });
});
