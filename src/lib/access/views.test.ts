import { describe, expect, it } from "vitest";
import { VIEWS, modelFor, needsMaintainer, validChoice } from "./views";

describe("modelFor", () => {
  it("uses each view's default when nothing was chosen", () => {
    expect(modelFor({}, "map")).toBe("github");
    expect(modelFor(undefined, "health")).toBe("github");
    expect(modelFor(null, "security")).toBe("maintainers");
  });
  it("uses the choice when the view allows it", () => {
    expect(modelFor({ health: "maintainers" }, "health")).toBe("maintainers");
    expect(needsMaintainer({ map: "maintainers" }, "map")).toBe(true);
    expect(needsMaintainer({ map: "maintainers" }, "health")).toBe(false);
  });
  it("a stored value the view does not allow is ignored, so a setting can never weaken Security", () => {
    expect(modelFor({ security: "github" }, "security")).toBe("maintainers");
    expect(needsMaintainer({ security: "github" }, "security")).toBe(true);
    expect(modelFor({ map: "nonsense" as never }, "map")).toBe("github");
  });
});

describe("validChoice", () => {
  it("accepts an allowed pair", () => expect(validChoice("health", "maintainers")).toEqual({ ok: true, view: "health", model: "maintainers" }));
  it("refuses opening Security to everyone, and says why", () => {
    const r = validChoice("security", "github");
    expect(r).toMatchObject({ ok: false });
    expect((r as { reason: string }).reason).toMatch(/sensitive/);
  });
  it("refuses unknown views and models", () => {
    expect(validChoice("nope", "github")).toMatchObject({ ok: false });
    expect(validChoice("map", "everyone")).toMatchObject({ ok: false });
    expect(validChoice("map", "__proto__")).toMatchObject({ ok: false });
  });
  it("every view's default is one of its allowed models", () => {
    for (const v of VIEWS) expect(v.allowed).toContain(v.default);
  });
});
