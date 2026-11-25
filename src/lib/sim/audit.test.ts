import { describe, expect, it } from "vitest";
import { appendEntry, GENESIS, verifyChain, type AuditEntry } from "./audit";

const T = 1_800_000_000_000;
const build = (n = 4): AuditEntry[] => {
  const out: AuditEntry[] = [];
  for (let i = 0; i < n; i++) out.push(appendEntry(out.at(-1), { ts: T + i, runId: "run_0001", agent: i === 0 ? "system" : "redteam", kind: i === 0 ? "roe" : "decision", decision: i === 0 ? undefined : "allow", tool: i === 0 ? undefined : "http.request", summary: `step ${i}` }));
  return out;
};

describe("append", () => {
  it("starts at sequence 0 from the genesis hash", () => { const [e] = build(1); expect(e).toMatchObject({ seq: 0, prevHash: GENESIS }); expect(e.hash).toMatch(/^[0-9a-f]{64}$/); });
  it("links each entry to the one before", () => { const l = build(); expect(l[1].prevHash).toBe(l[0].hash); expect(l.map((e) => e.seq)).toEqual([0, 1, 2, 3]); });
  it("is deterministic", () => { expect(build()).toEqual(build()); });
  it("refuses an entry from a different run", () => { const [a] = build(1); expect(() => appendEntry(a, { ts: T, runId: "run_9999", agent: "system", kind: "end", summary: "x" })).toThrow(/run/); });
  it("refuses time going backwards", () => { const [a] = build(1); expect(() => appendEntry(a, { ts: T - 1, runId: "run_0001", agent: "system", kind: "end", summary: "x" })).toThrow(/time/); });
});

describe("what is written is redacted and short", () => {
  it("redacts key-shaped text in the summary", () => {
    const key = "AKIA" + "IOSFODNN7EXAMPLE"; // assembled at run time so no key-shaped string is committed
    const e = appendEntry(undefined, { ts: T, runId: "run_0001", agent: "redteam", kind: "tool-result", summary: `found ${key} in response` });
    expect(e.summary).not.toContain(key);
    expect(e.summary).toContain("redacted");
  });
  it("strips the query string, fragment and credentials from a target", () => {
    const e = appendEntry(undefined, { ts: T, runId: "run_0001", agent: "graybox", kind: "decision", decision: "allow", target: "https://u:p@shop.example.com/a?token=abc#frag", summary: "probe" });
    expect(e.target).toBe("https://shop.example.com/a");
  });
  it("keeps a target that is not a URL, such as a range id", () => {
    expect(appendEntry(undefined, { ts: T, runId: "run_0001", agent: "redteam", kind: "decision", decision: "allow", target: "range_acme_shop_1", summary: "x" }).target).toBe("range_acme_shop_1");
  });
  it("collapses whitespace and cuts long text", () => {
    const e = appendEntry(undefined, { ts: T, runId: "run_0001", agent: "redteam", kind: "tool-result", summary: `a\n\n  b ${"z".repeat(2000)}` });
    expect(e.summary.length).toBeLessThanOrEqual(300);
    expect(e.summary.startsWith("a b ")).toBe(true);
  });
});

describe("verifyChain", () => {
  it("accepts an untouched chain", () => { expect(verifyChain(build())).toEqual({ ok: true, head: build().at(-1)!.hash }); });
  it("accepts an empty chain", () => { expect(verifyChain([])).toMatchObject({ ok: true }); });
  it("finds an edited field, and says where", () => { const l = build(); l[2] = { ...l[2], summary: "innocent" }; expect(verifyChain(l)).toMatchObject({ ok: false, index: 2 }); });
  it("finds an edited decision", () => { const l = build(); l[1] = { ...l[1], decision: "deny" }; expect(verifyChain(l)).toMatchObject({ ok: false, index: 1 }); });
  it("finds a deleted entry in the middle", () => { const l = build(); l.splice(1, 1); expect(verifyChain(l)).toMatchObject({ ok: false }); });
  it("finds reordered entries", () => { const l = build(); [l[1], l[2]] = [l[2], l[1]]; expect(verifyChain(l)).toMatchObject({ ok: false }); });
  it("finds a fully recomputed entry, because the next one no longer links to it", () => {
    const l = build(); const forged = appendEntry(l[0], { ts: T + 1, runId: "run_0001", agent: "redteam", kind: "decision", decision: "allow", tool: "http.request", summary: "forged" }); l[1] = forged;
    expect(verifyChain(l)).toMatchObject({ ok: false, index: 2 });
  });
  it("finds a chain that does not start at the genesis hash", () => { expect(verifyChain(build().slice(1))).toMatchObject({ ok: false, index: 0 }); });
  it("finds a mixed-run chain", () => {
    const l = build(2); l.push({ ...appendEntry(l[1], { ts: T + 5, runId: "run_0001", agent: "system", kind: "end", summary: "x" }), runId: "run_other" });
    expect(verifyChain(l)).toMatchObject({ ok: false });
  });
  it("cannot see a truncated tail on its own, but catches it when the head was kept elsewhere", () => {
    const l = build(); const head = l.at(-1)!.hash; const cut = l.slice(0, 3);
    expect(verifyChain(cut).ok).toBe(true);
    expect(verifyChain(cut, { expectedHead: head })).toMatchObject({ ok: false });
    expect(verifyChain(l, { expectedHead: head }).ok).toBe(true);
  });
  it("never throws on garbage", () => { for (const g of [null, undefined, 1, "x", [null], [{}], [{ seq: "a" }]]) expect(verifyChain(g as never).ok).toBe(false); });
});
