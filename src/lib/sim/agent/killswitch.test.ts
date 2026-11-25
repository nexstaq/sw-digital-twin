import { describe, expect, it } from "vitest";
import { KillRegistry, type RunHandle } from "./killswitch";

const handle = (over: Partial<RunHandle> & { calls?: string[] } = {}): RunHandle & { calls: string[] } => {
  const calls: string[] = over.calls ?? [];
  return { runId: "r1", repo: "acme/shop", killSwitchId: "k1", calls, kill: async (reason) => { calls.push(reason); }, ...over };
};

describe("the kill registry", () => {
  it("stops every run for a repository, whatever its case, and only that repository", async () => {
    const reg = new KillRegistry();
    const a = handle({ runId: "a" }), b = handle({ runId: "b", repo: "ACME/Shop" }), c = handle({ runId: "c", repo: "other/x" });
    for (const h of [a, b, c]) reg.register(h);
    expect(await reg.killRepo("acme/shop")).toBe(2);
    expect(a.calls).toHaveLength(1); expect(b.calls).toHaveLength(1); expect(c.calls).toHaveLength(0);
  });
  it("by kill-switch id and by run id", async () => {
    const reg = new KillRegistry();
    const a = handle({ runId: "a", killSwitchId: "ks1" }), b = handle({ runId: "b", killSwitchId: "ks2" });
    reg.register(a); reg.register(b);
    expect(await reg.killSwitch("ks2")).toBe(1);
    expect(await reg.killRun("a")).toBe(1);
    expect([a.calls.length, b.calls.length]).toEqual([1, 1]);
  });
  it("passes the reason on", async () => {
    const reg = new KillRegistry(); const a = handle(); reg.register(a);
    await reg.killRepo("acme/shop", "operator pressed stop");
    expect(a.calls).toEqual(["operator pressed stop"]);
  });
  it("one run that cannot be stopped cleanly does not stop the others from being stopped", async () => {
    const reg = new KillRegistry();
    const broken = handle({ runId: "x", kill: async () => { throw new Error("teardown failed"); } });
    const fine = handle({ runId: "y" });
    reg.register(broken); reg.register(fine);
    expect(await reg.killRepo("acme/shop")).toBe(2);
    expect(fine.calls).toHaveLength(1);
  });
  it("a run that unregisters is no longer found", async () => {
    const reg = new KillRegistry(); const a = handle();
    const off = reg.register(a);
    expect(reg.active()).toHaveLength(1);
    off();
    expect(reg.active()).toHaveLength(0);
    expect(await reg.killRepo("acme/shop")).toBe(0);
  });
  it("nothing to stop is zero, not an error", async () => { expect(await new KillRegistry().killRepo("a/b")).toBe(0); });
});
