import { describe, expect, it } from "vitest";
import { fixtureGraph } from "./fixture";
import { applyOverrides, OverridesSchema, setOverride } from "./overrides";
import { hashSecret, matchShare, newSecret, type Share } from "../share/token";

const parent = fixtureGraph.nodes.find((n) => !n.parentId && fixtureGraph.nodes.some((k) => k.parentId === n.id))!;
const kid = fixtureGraph.nodes.find((n) => n.parentId === parent.id)!;

describe("applyOverrides", () => {
  it("renames and re-describes a node, leaves the input untouched", () => {
    const g = applyOverrides(fixtureGraph, { [kid.id]: { label: "Checkout API", summary: "Takes the money." } });
    const n = g.nodes.find((x) => x.id === kid.id)!;
    expect(n).toMatchObject({ label: "Checkout API", summary: "Takes the money." });
      expect(fixtureGraph.nodes.find((x) => x.id === kid.id)!.label).not.toBe("Checkout API");
  });
  it("hiding a node hides everything nested in it and every edge touching them", () => {
    const g = applyOverrides(fixtureGraph, { [parent.id]: { hidden: true } });
    expect(g.nodes.some((n) => n.id === parent.id || n.id === kid.id)).toBe(false);
    expect(g.edges.every((e) => e.from !== parent.id && e.to !== parent.id && e.from !== kid.id && e.to !== kid.id)).toBe(true);
    expect(g.nodes.length).toBeLessThan(fixtureGraph.nodes.length);
  });
  it("an override for a node that no longer exists does nothing", () => {
    expect(applyOverrides(fixtureGraph, { "gone/for/good": { hidden: true, label: "x" } }).nodes).toHaveLength(fixtureGraph.nodes.length);
  });
  it("no overrides returns the same graph", () => { expect(applyOverrides(fixtureGraph, {})).toBe(fixtureGraph); });
});

describe("setOverride / schema", () => {
  it("removes an entry that says nothing and keeps only what was set", () => {
    const a = setOverride({}, "n1", { label: "A", hidden: false });
    expect(a).toEqual({ n1: { label: "A" } });
    expect(setOverride(a, "n1", {})).toEqual({});
  });
  it("rejects oversized or malformed edits", () => {
    expect(OverridesSchema.safeParse({ n: { label: "x".repeat(81) } }).success).toBe(false);
    expect(OverridesSchema.safeParse({ n: { hidden: "yes" } }).success).toBe(false);
    expect(OverridesSchema.safeParse({ n: { label: "ok" } }).success).toBe(true);
  });
});

describe("share tokens", () => {
  const mk = (secret: string, extra: Partial<Share> = {}): Share => ({ id: "i", hash: hashSecret(secret), createdBy: "u", createdAt: 1, ...extra });
  it("opens with the right secret, not with a wrong or malformed one", () => {
    const s = newSecret();
    expect(s).toHaveLength(32);
    expect(matchShare([mk(s)], s)?.id).toBe("i");
    expect(matchShare([mk(s)], newSecret())).toBeNull();
    expect(matchShare([mk(s)], "short")).toBeNull();
    expect(matchShare([mk(s)], s.slice(0, 31) + "!")).toBeNull();
  });
  it("a revoked link stops working, and the stored value is a hash, not the secret", () => {
    const s = newSecret();
    expect(matchShare([mk(s, { revokedAt: 5 })], s)).toBeNull();
    expect(JSON.stringify(mk(s))).not.toContain(s);
  });
  it("secrets are unique", () => { expect(new Set(Array.from({ length: 200 }, newSecret)).size).toBe(200); });
});
