import { describe, expect, it } from "vitest";
import { fixtureGraph } from "./fixture";
import { parsePath, pathSearch } from "./path";

describe("zoom path in URL", () => {
  it("parses a valid chain", () => expect(parsePath("?z=pay,pay-svc", fixtureGraph)).toEqual(["pay", "pay-svc"]));
  it("is empty without z", () => expect(parsePath("", fixtureGraph)).toEqual([]));
  it("truncates at the first invalid id", () => expect(parsePath("?z=pay,nope,pay-svc", fixtureGraph)).toEqual(["pay"]));
  it("rejects non-contiguous chains", () => expect(parsePath("?z=pay,f-charge", fixtureGraph)).toEqual(["pay"]));
  it("rejects a chain that does not start at the top", () => expect(parsePath("?z=pay-svc", fixtureGraph)).toEqual([]));
  it("serialises and preserves other params", () => {
    expect(pathSearch(["pay", "pay-svc"])).toBe("?z=pay%2Cpay-svc");
    expect(pathSearch([], "?z=pay&x=1")).toBe("?x=1");
    expect(pathSearch([])).toBe("");
  });
});
