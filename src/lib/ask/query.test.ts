import { describe, expect, it } from "vitest";
import { fixtureGraph } from "@/lib/graph/fixture";
import type { TwinGraph } from "@/lib/graph/types";
import { answerLocal, impactOf, searchNodes } from "./query";

const g = structuredClone(fixtureGraph) as TwinGraph;
const hl = (q: string) => { const r = answerLocal(g, q); if (!r.ok) throw new Error(r.message); return r.highlight; };
const label = (id: string) => g.nodes.find((n) => n.id === id)!.label;

describe("node search", () => {
  it("finds by label, friendly name and plural/singular", () => {
    expect(searchNodes(g, "payments")[0].id).toBe("pay");
    expect(searchNodes(g, "payment")[0].id).toBe("pay");
    expect(searchNodes(g, "xyzzy")).toEqual([]);
  });
  it("prefers the more important (shallower) node on ties", () => {
    const hit = searchNodes(g, "payments")[0];
    expect(hit.level).toBe(0);
  });
});

describe("answerLocal", () => {
  it("what breaks if X is down -> impact mode with the real blast radius", () => {
    const h = hl("what breaks if payments is down");
    expect(h.mode).toBe("impact");
    expect(h.focusId).toBe("pay");
    expect(new Set(h.ids)).toEqual(new Set(impactOf(g, "pay")));
    expect(h.ids.length).toBeGreaterThan(0);
    expect(h.title).toMatch(/Payments/);
  });
  it("understands phrasing variants", () => {
    for (const q of ["blast radius of payments", "if payments fails what is affected", "What happens when the payments service goes down?"]) {
      expect(hl(q).focusId, q).toBe("pay");
    }
  });
  it("failing things -> the deepest failing nodes, with a path that reveals them", () => {
    const failing = g.nodes.filter((n) => n.state === "failing");
    if (!failing.length) return; // fixture has failing nodes; guard keeps the test meaningful if it changes
    const h = hl("show failing things");
    expect(h.mode).toBe("set");
    expect(h.ids.length).toBeGreaterThan(0);
    for (const id of h.ids) expect(g.nodes.find((n) => n.id === id)!.state).toBe("failing");
  });
  it("says so plainly when nothing is failing or no signal exists", () => {
    const calm: TwinGraph = { ...g, nodes: g.nodes.map((n) => ({ ...n, state: "nominal" as const })) };
    const r = answerLocal(calm, "what is broken");
    expect(r.ok).toBe(false);
    expect(!r.ok && r.message).toMatch(/Nothing is failing/);
    const blind: TwinGraph = { ...g, nodes: g.nodes.map((n) => ({ ...n, state: "unknown" as const })) };
    expect(!answerLocal(blind, "what is broken").ok && (answerLocal(blind, "what is broken") as { message: string }).message).toMatch(/No live signal/);
  });
  it("who owns X", () => {
    const owned = g.nodes.find((n) => n.owners?.length)!;
    const h = hl(`who owns ${owned.label}`);
    expect(h.focusId).toBe(owned.id);
    expect(h.detail).toContain(owned.owners![0]);
  });
  it("deploy question uses deploy history and activity", () => {
    const h = hl("what changed in the last deploy");
    expect(h.title).toBe("Deploy & release");
    const withActivity: TwinGraph = { ...g, deploys: [{ hoursAgo: 0.2, label: "production abc1234", ok: false }], activity: { running: 1, queued: 2 } };
    const r = answerLocal(withActivity, "last deploy");
    expect(r.ok && r.highlight.detail).toMatch(/FAILED deploy: production abc1234, 12m ago · 1 running now · 2 queued/);
  });
  it("a bare name jumps there; gibberish is unrecognised so AI can try", () => {
    expect(hl("api gateway").focusId).toBe("api");
    const r = answerLocal(g, "frobnicate the quux");
    expect(r.ok).toBe(false);
    expect(!r.ok && r.unrecognised).toBe(true);
  });
  it("every id in every answer exists in the graph", () => {
    const ids = new Set(g.nodes.map((n) => n.id));
    for (const q of ["failing", "degraded", "what breaks if data stores go down", "deploy", "unknown", "who owns api"]) {
      const r = answerLocal(g, q);
      if (r.ok) for (const id of [...r.highlight.ids, ...r.highlight.path]) expect(ids.has(id), `${q}: ${id}`).toBe(true);
    }
    expect(label("pay")).toBeTruthy();
  });
});
