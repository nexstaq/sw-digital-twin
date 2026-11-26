import { describe, expect, it } from "vitest";
import { verifyChain } from "../audit";
import { KillRegistry } from "../agent/killswitch";
import { accessGraph, shopFindings } from "../range/fixtures";
import { scope } from "../whitebox/test-scope";
import { buildPlan } from "./plan";
import { stagingOrigin } from "../roe";

const SHA = "b".repeat(40);
const URL_ = "https://staging.example.com";
const build = (profile: "access" | "reachability", over: Partial<Parameters<typeof buildPlan>[0]> = {}) =>
  buildPlan({ repo: "acme/shop", url: URL_, profile, sha: SHA, graph: accessGraph(), set: shopFindings(), approvedBy: "ci:acme/shop", now: () => 1_800_000_000_000, ...over });

describe("buildPlan: authorising, never sending", () => {
  it("never actually requests anything: it only decides what the runner may ask for", async () => {
    const r = await build("access");
    expect(r.routes.length).toBeGreaterThan(0);
    // nothing here has network access at all: no fetch, no transport. Proven by construction (no import of one), not by a mock.
  });
  it("'access' authorises only routes the map says are not meant for anonymous callers", async () => {
    const r = await build("access");
    expect(r.routes.map((x) => x.path)).toEqual(["/api/admin/stats"]);
  });
  it("'reachability' authorises every plain GET route, open or not", async () => {
    const r = await build("reachability");
    expect(r.routes.map((x) => x.path).sort()).toEqual(["/api/admin/stats", "/api/orders"]);
  });
  it("never authorises a route that addresses one object by id, or anything but GET", async () => {
    const r = await build("reachability");
    expect(r.routes.some((x) => x.path.includes("["))).toBe(false);
    expect(r.routes.some((x) => x.path.includes("checkout") || x.path.includes("login"))).toBe(false); // POST routes
  });
  it("the control path looks nothing like a real route, and is stable for one run", async () => {
    const r = await build("access");
    expect(r.controlPath).toMatch(/^\/__mc-control-[0-9a-f]{8}$/);
  });
  it("its own run keeps an auditable, hash-chained log, with the right agent and technique, one decision per distinct route", async () => {
    const r = await build("reachability"); // two distinct candidates, so a target that collapsed to the bare origin would be visible here
    expect(verifyChain(r.run.audit, { expectedHead: r.run.head })).toMatchObject({ ok: true });
    const decisions = r.run.audit.filter((e) => e.kind === "decision");
    expect(decisions.length).toBe(2);
    for (const d of decisions) expect(d.technique).toBe("T1190");
    expect(new Set(decisions.map((d) => d.target)).size).toBe(2); // the log names each route, not just the shared origin
  });
  it("every call it actually makes is class \"probe\", never stronger, regardless of what any agent ceiling would otherwise permit", async () => {
    const r = await build("access");
    const decisions = r.run.audit.filter((e) => e.kind === "decision");
    expect(decisions.length).toBeGreaterThan(0);
    for (const d of decisions) expect(d.class).toBe("probe");
  });
});

describe("the guard: only a probe on the named staging origin, never more", () => {
  it("refuses a request whose target does not match the staging origin this run named", () => {
    const now = 1_800_000_000_000;
    const roe = { version: 1 as const, runId: "cp_x", repo: "acme/shop", targets: [{ kind: "ci-runner" as const, repo: "acme/shop", url: URL_ }], agents: ["graybox" as const], allowedClasses: ["observe" as const, "probe" as const], allowedTechniques: ["T1190"], forbiddenTechniques: [], window: { notBefore: now - 60_000, notAfter: now + 30 * 60_000 }, budgets: { steps: 10, tokens: 1000, wallMs: 60_000, costUsd: 1 }, approval: { approvedBy: "ci:acme/shop", approvedAt: now - 60_000 }, killSwitchId: "kill_cp_x" };
    const act = (over: Record<string, unknown>) => scope({ id: "a1", agent: "graybox", tool: "ci_plan_request", class: "probe", technique: "T1190", target: { kind: "ci-runner", url: `${URL_}/x` }, ...over }, roe, now);
    expect(act({})).toEqual({ ok: true });
    expect(act({ target: { kind: "ci-runner", url: "https://evil.example.com/x" } })).toMatchObject({ reason: "host-mismatch" });
    expect(act({ class: "exploit-range" })).toMatchObject({ reason: "class-not-in-roe" }); // refused once already, by this run's own allowed classes
    expect(act({ technique: "T1566" })).toMatchObject({ reason: "technique-not-allowed" });
  });
  it("even a ROE that named exploit-range as allowed could still never reach a real target with it: the target itself caps at probe", () => {
    const now = 1_800_000_000_000;
    const roe = { version: 1 as const, runId: "cp_y", repo: "acme/shop", targets: [{ kind: "ci-runner" as const, repo: "acme/shop", url: URL_ }], agents: ["graybox" as const], allowedClasses: ["observe" as const, "probe" as const, "exploit-range" as const], allowedTechniques: ["T1190"], forbiddenTechniques: [], window: { notBefore: now - 60_000, notAfter: now + 30 * 60_000 }, budgets: { steps: 10, tokens: 1000, wallMs: 60_000, costUsd: 1 }, approval: { approvedBy: "ci:acme/shop", approvedAt: now - 60_000 }, killSwitchId: "kill_cp_y" };
    const d = scope({ id: "a1", agent: "graybox", tool: "ci_plan_request", class: "exploit-range", technique: "T1190", target: { kind: "ci-runner", url: `${URL_}/x` } }, roe, now);
    expect(d).toMatchObject({ reason: "class-not-allowed-on-target" });
  });
  it("a staging URL is validated the same way everywhere this type is used (https, no path, no IP, no credentials)", () => {
    for (const bad of ["http://staging.example.com", "https://staging.example.com/x", "https://1.2.3.4", "https://u:p@staging.example.com"]) {
      expect(stagingOrigin.safeParse(bad).success, bad).toBe(false);
    }
    expect(stagingOrigin.safeParse(URL_).success).toBe(true);
  });
});

describe("a run that is stopped mid-way authorises nothing further, and a clean map authorises nothing", () => {
  it("the kill switch stops authorisation immediately, and says so, and nothing further is authorised once it fires", async () => {
    const reg = new KillRegistry();
    let calls = 0;
    const r = await buildPlan({ repo: "acme/shop", url: URL_, profile: "reachability", sha: SHA, graph: accessGraph(), set: shopFindings(), approvedBy: "ci:acme/shop", killRegistry: reg, now: () => { if (++calls === 5) void reg.killRepo("acme/shop"); return 1_800_000_000_000; } });
    expect(r.run.stopReason).toBe("killed");
    expect(r.notes.join(" ")).toMatch(/ended early/);
    expect(reg.active()).toHaveLength(0);
    expect(r.routes).toEqual([]); // killed before the first candidate (of two) was ever authorised
  });
  it("a map with no plain GET route at all authorises nothing, and says why", async () => {
    const r = await buildPlan({ repo: "acme/shop", url: URL_, profile: "access", sha: SHA, graph: { repo: "acme/shop", deploys: [], nodes: [], edges: [] }, set: shopFindings(), approvedBy: "ci:acme/shop", now: () => 1_800_000_000_000 });
    expect(r.routes).toEqual([]);
    expect(r.notes.join(" ")).toMatch(/has no plain GET route/);
  });
});

describe("determinism", () => {
  it("the same inputs give the same plan", async () => {
    const [a, b] = await Promise.all([build("access"), build("access")]);
    expect(a.routes).toEqual(b.routes);
    expect(a.controlPath).toBe(b.controlPath);
    expect(a.run.head).toBe(b.run.head);
  });
});
