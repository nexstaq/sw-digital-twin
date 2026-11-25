import { describe, expect, it } from "vitest";
import { allow, AGENT_CEILING, type DenyReason } from "./scope";
import { ciRoe, domainAction, domainRoe, freshState, HOUR, NOW, rangeAction, rangeRoe } from "./fixtures";

const denied = (r: ReturnType<typeof allow>, reason: DenyReason) => { expect(r).toMatchObject({ ok: false, reason }); };
const okRange = (over: Record<string, unknown> = {}, roe: unknown = rangeRoe(), state = freshState()) => allow(rangeAction(over), roe, NOW, state);
const withDomainProof = (over = {}) => freshState({ ownershipProvedAt: { "shop.example.com": NOW - 30_000 }, ...over });
const okDomain = (url: string, over: Record<string, unknown> = {}, state = withDomainProof()) => allow(domainAction(url, over), domainRoe(), NOW, state);

describe("what is allowed", () => {
  it("a range action inside the ROE", () => { expect(okRange()).toEqual({ ok: true }); });
  it("every agent's own ceiling on the range", () => {
    for (const agent of Object.keys(AGENT_CEILING) as (keyof typeof AGENT_CEILING)[]) {
      expect(okRange({ agent, class: AGENT_CEILING[agent], technique: AGENT_CEILING[agent] === "observe" ? undefined : "T1190" })).toEqual({ ok: true });
    }
  });
  it("an observe action needs no technique", () => { expect(okRange({ class: "observe", technique: undefined, agent: "narrator" })).toEqual({ ok: true }); });
  it("a probe of the exact verified domain once ownership was proved in this run", () => { expect(okDomain("https://shop.example.com/login?next=/")).toEqual({ ok: true }); });
  it("the host is compared case-insensitively", () => { expect(okDomain("https://SHOP.Example.COM/")).toEqual({ ok: true }); });
  it("a probe of the ci-runner staging origin", () => {
    expect(allow(domainAction("https://staging.shop.example.com/health", { target: { kind: "ci-runner", url: "https://staging.shop.example.com/health" } }), ciRoe(), NOW, freshState())).toEqual({ ok: true });
  });
});

describe("one test per deny reason", () => {
  it("roe-invalid: a ROE that does not parse", () => { denied(allow(rangeAction(), { ...rangeRoe(), extra: 1 }, NOW, freshState()), "roe-invalid"); });
  it("killed: the kill switch wins over everything else", () => { denied(okRange({}, rangeRoe(), freshState({ killed: true })), "killed"); });
  it("not-yet-valid: before the window", () => { denied(allow(rangeAction(), rangeRoe(), NOW - 2 * HOUR, freshState({ startedAt: NOW - 3 * HOUR })), "not-yet-valid"); });
  it("state-invalid: a run that claims to have started in the future", () => { denied(allow(rangeAction(), rangeRoe(), NOW - 2 * HOUR, freshState()), "state-invalid"); });
  it("expired: at and after the end of the window", () => {
    denied(allow(rangeAction(), rangeRoe(), NOW + HOUR, freshState()), "expired");
    denied(allow(rangeAction(), rangeRoe(), NOW + 2 * HOUR, freshState()), "expired");
  });
  it("budget-steps", () => { denied(okRange({}, rangeRoe(), freshState({ stepsUsed: 100 })), "budget-steps"); expect(okRange({}, rangeRoe(), freshState({ stepsUsed: 99 })).ok).toBe(true); });
  it("budget-tokens", () => { denied(okRange({}, rangeRoe(), freshState({ tokensUsed: 500_000 })), "budget-tokens"); });
  it("budget-time", () => { denied(okRange({}, rangeRoe(), freshState({ startedAt: NOW - 30 * 60_000 })), "budget-time"); });
  it("budget-cost", () => { denied(okRange({}, rangeRoe(), freshState({ costUsd: 5 })), "budget-cost"); });
  it("action-invalid: malformed or extra keys", () => {
    denied(okRange({ sudo: true }), "action-invalid");
    denied(okRange({ class: "everything" }), "action-invalid");
    denied(okRange({ tool: "" }), "action-invalid");
    denied(okRange({ tool: "x".repeat(200) }), "action-invalid");
    denied(okRange({ technique: "ALL" }), "action-invalid");
  });
  it("agent-not-in-roe", () => { denied(okRange({ agent: "whitebox" }, { ...rangeRoe(), agents: ["redteam"] }), "agent-not-in-roe"); });
  it("class-not-in-roe", () => { denied(okRange({ class: "exploit-range" }, { ...rangeRoe(), allowedClasses: ["observe", "probe"] }), "class-not-in-roe"); });
  it("class-above-agent-ceiling: a narrator or blue observer can only observe", () => {
    denied(okRange({ agent: "narrator", class: "probe" }), "class-above-agent-ceiling");
    denied(okRange({ agent: "blue", class: "exploit-range" }), "class-above-agent-ceiling");
  });
  it("class-above-agent-ceiling: intrusive is above every agent's ceiling", () => { denied(okRange({ class: "intrusive" }), "class-above-agent-ceiling"); });
  it("class-not-allowed-on-target: nothing beyond a probe ever reaches a real target", () => {
    const roe = { ...domainRoe(), allowedClasses: ["observe", "probe", "exploit-range"] };
    denied(allow(domainAction("https://shop.example.com/", { class: "exploit-range" }), roe, NOW, withDomainProof()), "class-not-allowed-on-target");
  });
  it("technique-missing: anything but observe must name its technique", () => { denied(okRange({ technique: undefined }), "technique-missing"); });
  it("technique-not-allowed: not on the allowlist", () => { denied(okRange({ technique: "T1566" }), "technique-not-allowed"); });
  it("technique-forbidden: named in the ROE's forbidden list", () => { denied(okRange({ technique: "T1486" }), "technique-forbidden"); });
  it("target-not-in-roe: another range, or another kind of target", () => {
    denied(okRange({ target: { kind: "range", rangeId: "range_other" } }), "target-not-in-roe");
    denied(okRange({ target: { kind: "verified-domain", url: "https://shop.example.com/" } }), "target-not-in-roe");
  });
  it("ownership-not-reproved: no proof, or a proof from an earlier run", () => {
    denied(okDomain("https://shop.example.com/", {}, freshState()), "ownership-not-reproved");
    denied(okDomain("https://shop.example.com/", {}, withDomainProof({ ownershipProvedAt: { "shop.example.com": NOW - 10 * 60_000 } })), "ownership-not-reproved");
  });
  it("ownership-not-reproved: a proof for a different domain does not count", () => {
    denied(okDomain("https://shop.example.com/", {}, freshState({ ownershipProvedAt: { "other.example.com": NOW - 1000 } })), "ownership-not-reproved");
  });
});

describe("a target that merely looks like the allowed one is refused", () => {
  it.each([
    ["a longer host that starts the same", "https://shop.example.com.evil.com/"],
    ["credentials that name the allowed host", "https://shop.example.com@evil.com/"],
    ["the allowed host only in the query", "https://evil.com/?h=shop.example.com"],
    ["the allowed host only in the path", "https://evil.com/shop.example.com"],
    ["a subdomain", "https://api.shop.example.com/"],
    ["the parent domain", "https://example.com/"],
    ["a trailing dot", "https://shop.example.com./"],
    ["a look-alike Unicode host", "https://shοp.example.com/"],
    ["a backslash trick", "https://evil.com\\@shop.example.com/"],
  ])("%s", (_n, url) => { expect(okDomain(url)).toMatchObject({ ok: false }); });
  it.each([
    ["plain http", "http://shop.example.com/", "url-unsafe"],
    ["a non-standard port", "https://shop.example.com:8443/", "url-unsafe"],
    ["embedded credentials", "https://user:pw@shop.example.com/", "url-unsafe"],
    ["an IPv4 literal", "https://127.0.0.1/", "url-unsafe"],
    ["an IPv6 literal", "https://[::1]/", "url-unsafe"],
    ["the cloud metadata address", "https://169.254.169.254/latest/meta-data/", "url-unsafe"],
    ["a file URL", "file:///etc/passwd", "url-unsafe"],
    ["javascript", "javascript:alert(1)", "url-unsafe"],
    ["not a URL at all", "shop.example.com", "url-unsafe"],
    ["a different host", "https://evil.com/", "host-mismatch"],
  ] as const)("%s", (_n, url, reason) => { denied(okDomain(url), reason); });
  it.each(["https://api.shop.example.com/", "https://evilshop.example.com/", "https://example.com/", "https://shop.example.com.evil.com/"])(
    "%s is refused as the wrong host even if ownership of it had been proved (the host rule stands on its own)",
    (url) => {
      const host = new URL(url).hostname;
      denied(okDomain(url, {}, freshState({ ownershipProvedAt: { [host]: NOW - 1000 } })), "host-mismatch");
    },
  );
  it("an over-long URL", () => { denied(okDomain(`https://shop.example.com/${"a".repeat(3000)}`), "url-unsafe"); });
  it("a ci-runner origin other than the named one", () => {
    const a = domainAction("https://prod.shop.example.com/", { target: { kind: "ci-runner", url: "https://prod.shop.example.com/" } });
    denied(allow(a, ciRoe(), NOW, freshState()), "host-mismatch");
  });
});

describe("default deny and purity", () => {
  it.each([null, undefined, "act", 7, [], {}, { id: "x" }])("a garbage action %j is refused, never thrown on", (a) => { expect(allow(a, rangeRoe(), NOW, freshState())).toMatchObject({ ok: false }); });
  it("garbage ROE or state never throws and never allows", () => {
    for (const roe of [null, undefined, 1, "x", [], {}]) expect(allow(rangeAction(), roe, NOW, freshState()).ok).toBe(false);
    for (const st of [null, undefined, {}, { killed: "no" }, { startedAt: "now" }]) expect(allow(rangeAction(), rangeRoe(), NOW, st as never).ok).toBe(false);
  });
  it("a non-finite clock is refused", () => { for (const n of [NaN, Infinity, -Infinity]) expect(allow(rangeAction(), rangeRoe(), n, freshState()).ok).toBe(false); });
  it("a prototype-pollution attempt in an action does not change the answer", () => {
    const a = JSON.parse('{"id":"a","agent":"redteam","tool":"t","class":"exploit-range","technique":"T1190","target":{"kind":"range","rangeId":"range_acme_shop_1"},"__proto__":{"class":"intrusive"}}');
    expect(allow(a, rangeRoe(), NOW, freshState())).toMatchObject({ ok: false, reason: "action-invalid" });
    expect(({} as Record<string, unknown>).class).toBeUndefined();
  });
  it("does not mutate its inputs, and answers the same twice", () => {
    const roe = Object.freeze(rangeRoe()), action = Object.freeze(rangeAction()), state = Object.freeze(freshState());
    const a = allow(action, roe, NOW, state), b = allow(action, roe, NOW, state);
    expect(a).toEqual(b);
  });
  it("every deny carries a reason code and a human sentence", () => {
    const r = okRange({ technique: "T1566" });
    expect(r).toMatchObject({ ok: false, reason: expect.any(String), detail: expect.stringMatching(/\S{3,}/) });
  });
  it("the order is fixed: kill and window are decided before the action is even read", () => {
    denied(allow({ garbage: true }, rangeRoe(), NOW, freshState({ killed: true })), "killed");
    denied(allow({ garbage: true }, rangeRoe(), NOW + 5 * HOUR, freshState()), "expired");
  });
});
