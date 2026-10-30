import { describe, expect, it } from "vitest";
import { rollup, rollupScore, rollupState } from "./rollup";
import { fixtureGraph } from "./fixture";
import type { Status, TwinNode } from "./types";

const k = (state: Status, criticality: 1 | 2 | 3 = 2, score = 0.5) => ({ state, criticality, score });

describe("rollupState", () => {
  it("is nominal when all children are nominal", () => expect(rollupState([k("nominal"), k("nominal")])).toBe("nominal"));
  it("ignores unknown children", () => expect(rollupState([k("nominal"), k("unknown")])).toBe("nominal"));
  it("is unknown only when every child is unknown", () => {
    expect(rollupState([k("unknown"), k("unknown")])).toBe("unknown");
    expect(rollupState([])).toBe("unknown");
  });
  it("degraded child degrades parent", () => expect(rollupState([k("nominal"), k("degraded")])).toBe("degraded"));
  it("important failing child fails parent", () => expect(rollupState([k("nominal"), k("nominal"), k("failing", 2)])).toBe("failing"));
  it("low-criticality failure only degrades", () => expect(rollupState([k("nominal"), k("nominal"), k("failing", 1)])).toBe("degraded"));
  it("majority of weight failing fails parent even if low criticality", () =>
    expect(rollupState([k("failing", 1), k("failing", 1), k("nominal", 1)])).toBe("failing"));
});

describe("rollupScore", () => {
  it("is pulled toward the worst child", () => {
    const s = rollupScore([k("nominal", 2, 1), k("nominal", 2, 1), k("failing", 2, 0)]);
    expect(s).toBeLessThan(0.5);
  });
  it("ignores unknown children", () => expect(rollupScore([k("nominal", 2, 0.9), k("unknown", 3, 0)])).toBeCloseTo(0.9));
});

describe("rollup on the fixture", () => {
  const byId = (id: string) => fixtureGraph.nodes.find((n) => n.id === id)!;
  it("propagates failure L2 -> L1 -> L0", () => {
    expect(byId("f-charge").state).toBe("failing");
    expect(byId("pay-svc").state).toBe("failing");
    expect(byId("pay").state).toBe("failing");
  });
  it("keeps external services unknown", () => expect(byId("ext").state).toBe("unknown"));
  it("is pure and idempotent", () => {
    const input: TwinNode[] = structuredClone(fixtureGraph.nodes);
    const before = JSON.stringify(input);
    const once = rollup(input);
    expect(JSON.stringify(input)).toBe(before);
    expect(rollup(once)).toEqual(once);
  });
  it("explains the parent state with child reasons", () => expect(byId("pay").reasons[0]).toMatch(/failing/));
});
