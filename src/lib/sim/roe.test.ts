import { describe, expect, it } from "vitest";
import { LIMITS, parseRoe } from "./roe";
import { ciRoe, domainRoe, HOUR, NOW, rangeRoe } from "./fixtures";

const bad = (input: unknown, fragment?: string) => {
  const r = parseRoe(input);
  expect(r.ok).toBe(false);
  if (!r.ok && fragment) expect(r.errors.join("\n")).toContain(fragment);
};
const withRoe = (over: Record<string, unknown>) => ({ ...rangeRoe(), ...over });

describe("a well-formed rules of engagement", () => {
  it("accepts a range run with no approval", () => { expect(parseRoe(rangeRoe()).ok).toBe(true); });
  it("accepts a verified-domain run that carries an approval", () => { expect(parseRoe(domainRoe()).ok).toBe(true); });
  it("accepts a ci-runner run that carries an approval", () => { expect(parseRoe(ciRoe()).ok).toBe(true); });
  it("lowercases a domain target", () => {
    const r = parseRoe({ ...domainRoe(), targets: [{ kind: "verified-domain", domain: "Shop.Example.COM" }] });
    expect(r.ok && r.roe.targets[0]).toEqual({ kind: "verified-domain", domain: "shop.example.com" });
  });
});

describe("default deny on malformed input", () => {
  it.each([null, undefined, "roe", 42, [], {}])("refuses %j", (v) => bad(v));
  it("refuses unknown keys, so nothing can ride along", () => { bad({ ...rangeRoe(), allowEverything: true }, "allowEverything"); });
  it("refuses unknown keys inside nested objects", () => { bad(withRoe({ budgets: { ...rangeRoe().budgets, extra: 1 } })); });
  it("refuses a wrong version", () => { bad(withRoe({ version: 2 })); });
  it("reports every problem, with the field it is in", () => {
    const r = parseRoe(withRoe({ targets: [], agents: [] }));
    expect(!r.ok && r.errors.length).toBeGreaterThanOrEqual(2);
  });
});

describe("targets", () => {
  it("needs at least one and at most five", () => {
    bad(withRoe({ targets: [] }));
    bad(withRoe({ targets: Array.from({ length: 6 }, (_, i) => ({ kind: "range", rangeId: `range_${i}` })) }));
  });
  it.each([
    ["an IP address", "10.0.0.5"], ["a wildcard", "*.example.com"], ["a scheme", "https://shop.example.com"], ["a path", "shop.example.com/admin"],
    ["a port", "shop.example.com:8443"], ["credentials", "a@shop.example.com"], ["a single label", "intranet"], ["an internal suffix", "db.corp"], ["an IPv6 literal", "[::1]"],
  ])("refuses a domain target that is %s", (_n, domain) => { bad(withRoe({ targets: [{ kind: "verified-domain", domain }], approval: domainRoe().approval })); });
  it("refuses a ci-runner url that is not https", () => { bad({ ...ciRoe(), targets: [{ kind: "ci-runner", repo: "acme/shop", url: "http://staging.shop.example.com" }] }); });
  it("refuses a ci-runner url that carries credentials, a path or a port", () => {
    for (const url of ["https://a:b@staging.example.com", "https://staging.example.com/x", "https://staging.example.com:8443"]) bad({ ...ciRoe(), targets: [{ kind: "ci-runner", repo: "acme/shop", url }] });
  });
  it("refuses a malformed repo", () => { bad({ ...ciRoe(), repo: "acme", targets: [{ kind: "ci-runner", repo: "acme/shop/x", url: "https://staging.example.com" }] }); });
  it("refuses an unknown target kind", () => { bad(withRoe({ targets: [{ kind: "everything" }] })); });
  it("refuses a range id that is not a plain identifier", () => { bad(withRoe({ targets: [{ kind: "range", rangeId: "../prod" }] })); });
});

describe("approval", () => {
  it("is required for any target that is not a range", () => {
    const { approval: _a, ...noApproval } = domainRoe(); // eslint-disable-line @typescript-eslint/no-unused-vars
    bad(noApproval, "approval");
  });
  it("is required when a range is mixed with a real target", () => {
    bad({ ...rangeRoe(), targets: [...rangeRoe().targets, { kind: "verified-domain", domain: "shop.example.com" }] }, "approval");
  });
  it("needs a named approver", () => { bad({ ...domainRoe(), approval: { approvedBy: "", approvedAt: NOW - HOUR } }); });
  it("cannot be dated in the future", () => { bad({ ...domainRoe(), approval: { approvedBy: "alice", approvedAt: NOW + 10 * HOUR } }, "approval"); });
});

describe("window", () => {
  it("must end after it starts", () => { bad(withRoe({ window: { notBefore: NOW, notAfter: NOW } })); bad(withRoe({ window: { notBefore: NOW, notAfter: NOW - 1 } })); });
  it("cannot be longer than 24 hours", () => { bad(withRoe({ window: { notBefore: NOW, notAfter: NOW + LIMITS.maxWindowMs + 1 } }), "window"); });
  it("allows exactly 24 hours", () => { expect(parseRoe(withRoe({ window: { notBefore: NOW, notAfter: NOW + LIMITS.maxWindowMs } })).ok).toBe(true); });
  it.each([1.5, "soon", -1, NaN, Infinity])("refuses %j as a time", (v) => { bad(withRoe({ window: { notBefore: v, notAfter: NOW + HOUR } })); });
});

describe("budgets are bounded", () => {
  it.each(["steps", "tokens", "wallMs", "costUsd"] as const)("%s must be positive, finite and under the hard cap", (k) => {
    const cap = { steps: LIMITS.maxSteps, tokens: LIMITS.maxTokens, wallMs: LIMITS.maxWallMs, costUsd: LIMITS.maxCostUsd }[k];
    for (const v of [0, -1, Infinity, NaN, cap + 1]) bad(withRoe({ budgets: { ...rangeRoe().budgets, [k]: v } }), "budgets");
    expect(parseRoe(withRoe({ budgets: { ...rangeRoe().budgets, [k]: cap } })).ok).toBe(true);
  });
  it("steps and tokens must be whole numbers", () => { bad(withRoe({ budgets: { ...rangeRoe().budgets, steps: 1.5 } })); });
  it("a missing budget is refused, never defaulted to unlimited", () => { bad(withRoe({ budgets: { steps: 10, tokens: 10, wallMs: 10 } })); });
});

describe("classes, techniques and agents", () => {
  it("intrusive actions are not available in this version", () => { bad(withRoe({ allowedClasses: ["observe", "intrusive"] }), "allowedClasses"); });
  it("needs at least one class and one agent", () => { bad(withRoe({ allowedClasses: [] })); bad(withRoe({ agents: [] })); });
  it("refuses an unknown agent or class", () => { bad(withRoe({ agents: ["root"] })); bad(withRoe({ allowedClasses: ["everything"] })); });
  it.each(["T1190", "T1059.004", "T1078.001"])("accepts ATT&CK id %s", (t) => { expect(parseRoe(withRoe({ allowedTechniques: [t] })).ok).toBe(true); });
  it.each(["T1059.4", "t1190", "T119", "*", "T1190; rm -rf /", " T1190", "T1190\n", "ALL", ""])("refuses technique %j", (t) => { bad(withRoe({ allowedTechniques: [t] })); });
  it("a technique cannot be both allowed and forbidden", () => { bad(withRoe({ allowedTechniques: ["T1190"], forbiddenTechniques: ["T1190"] }), "T1190"); });
  it("lists are capped, so a ROE cannot be a megabyte", () => { bad(withRoe({ allowedTechniques: Array.from({ length: 201 }, (_, i) => `T${1000 + i}`) })); });
  it("a run id and kill switch id are plain identifiers", () => { bad(withRoe({ runId: "run 1; drop" })); bad(withRoe({ killSwitchId: "" })); });
});
