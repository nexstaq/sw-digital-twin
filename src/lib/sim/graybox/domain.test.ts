import { describe, expect, it, vi } from "vitest";
import type { Transport } from "@/lib/security/passive/transport";
import { FindingSchema } from "@/lib/security/types";
import { KillRegistry } from "../agent/killswitch";
import { accessGraph, node, shopFindings } from "../range/fixtures";
import { probeDomain, type DomainProbeInput } from "./domain";

const NOW = 1_800_000_000_000;
const DOMAIN = "shop.example.com";
const APPROVAL = { approvedBy: "alice", approvedAt: NOW - 3_600_000 };

type Reply = { status: number; bytes?: number; headers?: Record<string, string> };
interface Sent { host: string; path: string; opts: Record<string, unknown> | undefined }

/** a pretend internet that records every request it is asked to make */
function internet(answer: (path: string) => Reply, o: { onRequest?: (n: number) => void } = {}) {
  const sent: Sent[] = [];
  const transport: Transport = {
    request: async (host, path, opts) => { sent.push({ host, path, opts: opts as Record<string, unknown> | undefined }); o.onRequest?.(sent.length); const r = answer(path); return { status: r.status, headers: r.headers ?? {}, body: "", bytes: r.bytes ?? 0, truncated: false }; },
    cert: async () => { throw new Error("not used"); }, txt: async () => [], mx: async () => [],
  };
  return { transport, sent };
}

const graph = () => {
  const g = accessGraph();
  g.nodes.push(node("route:api:GET:/api/admin/users", 2, "endpoint", "GET /api/admin/users", "grp:api", "api/src/admin-users.ts"), node("route:api:GET:/api/admin/[section]", 2, "endpoint", "GET /api/admin/[section]", "grp:api", "api/src/admin-section.ts"));
  return g;
};
const run = (net: ReturnType<typeof internet>, over: Partial<DomainProbeInput> = {}) =>
  probeDomain({ repo: "acme/shop", domain: DOMAIN, sha: "b".repeat(40), graph: graph(), set: shopFindings(), transport: net.transport, verifyDomain: async () => true, approval: APPROVAL, now: () => NOW, sleep: async () => undefined, killRegistry: new KillRegistry(), ...over });
const PAGE = (path: string): Reply => (path.startsWith("/__mc-control") ? { status: 404, bytes: 120 } : { status: 401, bytes: 40 });

describe("nothing is sent unless ownership is proved in this run", () => {
  it("not proved: zero requests, and the run says why", async () => {
    const net = internet(PAGE);
    const r = await run(net, { verifyDomain: async () => false });
    expect(net.sent).toHaveLength(0);
    expect(r.requests).toBe(0);
    expect(r.findings).toEqual([]);
    expect(r.notes.join(" ")).toMatch(/Ownership of the domain could not be proved/);
    expect(r.run.denies).toEqual({ "ownership-not-reproved": 1 });
  });
  it("a proof that crashes is the same as no proof", async () => {
    const net = internet(PAGE);
    await run(net, { verifyDomain: async () => { throw new Error("dns down"); } });
    expect(net.sent).toHaveLength(0);
  });
  it("proved: the proof is asked for once, before anything is sent, and the requests then go to that host only", async () => {
    const order: string[] = [];
    const net = internet(PAGE, { onRequest: () => order.push("request") });
    await run(net, { verifyDomain: async (d) => { order.push(`prove ${d}`); return true; } });
    expect(order[0]).toBe(`prove ${DOMAIN}`);
    expect(order.filter((x) => x.startsWith("prove"))).toHaveLength(1);
    expect(net.sent.length).toBeGreaterThan(0);
    expect(new Set(net.sent.map((s) => s.host))).toEqual(new Set([DOMAIN]));
  });
  it("without a named approval the rules of engagement are not valid and nothing is sent", async () => {
    const net = internet(PAGE);
    const r = await run(net, { approval: { approvedBy: "", approvedAt: NOW - 3_600_000 } });
    expect(net.sent).toHaveLength(0);
    expect(r.run).toMatchObject({ stopReason: "refused" });
  });
  it("an approval dated after the run is not an approval: the window has not opened, and nothing is sent", async () => {
    const net = internet(PAGE);
    const r = await run(net, { approval: { approvedBy: "alice", approvedAt: NOW + 3_600_000 } });
    expect(net.sent).toHaveLength(0);
    expect(r.run.stopReason).toBe("refused");
  });
  it("a domain that cannot be a target (an address, a single label) is refused before anything is sent", async () => {
    for (const domain of ["10.0.0.5", "localhost", "https://shop.example.com", "*.example.com"]) {
      const net = internet(PAGE);
      await run(net, { domain });
      expect(net.sent, domain).toHaveLength(0);
    }
  });
});

describe("what it sends, exactly", () => {
  it("one made-up page as a control, then each plain GET route meant for admins: nothing with a parameter, nothing that writes", async () => {
    const net = internet(PAGE);
    const r = await run(net);
    const paths = net.sent.map((s) => s.path);
    expect(paths.filter((p) => /^\/__mc-control-[0-9a-f]{8}$/.test(p))).toHaveLength(1);
    expect(paths.filter((p) => !p.startsWith("/__mc-control")).sort()).toEqual(["/api/admin/stats", "/api/admin/users"]);
    expect(r.requests).toBe(3);
  });
  it("only GET over https, with a size cap, and nothing else: no credentials, no cookie, no body, no query", async () => {
    const net = internet(PAGE);
    await run(net);
    for (const s of net.sent) {
      expect(s.opts).toEqual({ scheme: "https", method: "GET", maxBytes: 4096 });
      expect(s.path).not.toMatch(/[?#]/);
    }
    expect(JSON.stringify(net.sent)).not.toMatch(/authorization|cookie|bearer|password|token/i);
  });
  it("pauses between requests, as the passive checks do, and not before the first", async () => {
    const sleep = vi.fn(async () => undefined);
    const net = internet(PAGE);
    await run(net, { sleep, pauseMs: 250 });
    expect(sleep).toHaveBeenCalledTimes(net.sent.length - 1);
    expect(sleep).toHaveBeenCalledWith(250);
  });
  it("is limited to the number of routes asked for", async () => {
    const net = internet(PAGE);
    await run(net, { maxRoutes: 1 });
    expect(net.sent).toHaveLength(2); // the control and one route
  });
  it("every request is in the audit log as an allowed probe of the one approved host, with no query or credentials in the target", async () => {
    const net = internet(PAGE);
    const r = await run(net);
    const probes = r.run.audit.filter((e) => e.kind === "tool-result");
    expect(probes).toHaveLength(net.sent.length);
    for (const e of probes) expect(e.target).toMatch(new RegExp(`^https://${DOMAIN.replace(/\./g, "\\.")}/`));
    expect(r.run.audit.filter((e) => e.kind === "decision").every((e) => e.decision === "allow" && e.class === "probe")).toBe(true);
  });
  it("sends nothing at all when the map has nothing safe to check", async () => {
    const net = internet(PAGE);
    const g = accessGraph();
    const r = await run(net, { graph: g });
    expect(net.sent.length).toBe(2); // the control and /api/admin/stats: the shop graph has one admin GET
    const none = await run(internet(PAGE), { graph: { ...g, nodes: g.nodes.filter((n) => !/admin/.test(n.label)) } });
    expect(none.requests).toBe(0);
    expect(none.notes.join(" ")).toMatch(/nothing safe to check/);
    expect(r.requests).toBe(2);
  });
});

describe("what it concludes", () => {
  it("a page meant for admins that answers an anonymous visitor with a real page is reported, with evidence and the caveat", async () => {
    const net = internet((p) => (p.startsWith("/__mc-control") ? { status: 404, bytes: 120 } : p === "/api/admin/stats" ? { status: 200, bytes: 4200 } : { status: 401, bytes: 40 }));
    const r = await run(net);
    expect(r.observations.find((o) => o.route === "GET /api/admin/stats")).toMatchObject({ outcome: "reachable", status: 200 });
    expect(r.findings).toHaveLength(1);
    const f = r.findings[0];
    expect(f).toMatchObject({ ruleId: "SIM/anonymous-access", category: "runtime", severity: "high", confidence: "medium", technique: "T1190", path: `https://${DOMAIN}/api/admin/stats`, cwe: ["CWE-862"] });
    expect(f.proof).toMatch(/answered 200 \(4200 bytes\).*made-up path answered 404.*Audit step #\d+/);
    expect(f.reason).toMatch(/assumption about what the page is meant for/);
    expect(FindingSchema.safeParse(f).success).toBe(true);
    const step = Number(/#(\d+)/.exec(f.proof!)![1]);
    expect(r.run.audit.find((e) => e.seq === step)).toMatchObject({ kind: "tool-result" });
  });
  it("a page that refuses or redirects is protected, and is not reported", async () => {
    for (const status of [401, 403, 302]) {
      const r = await run(internet((p) => (p.startsWith("/__mc-control") ? { status: 404, bytes: 100 } : { status, bytes: 10 })));
      expect(r.findings, String(status)).toEqual([]);
      expect(r.observations.filter((o) => o.outcome === "protected").length).toBe(2);
    }
  });
  it("a site that answers a page that cannot exist in the same way proves nothing, and nothing is reported", async () => {
    const r = await run(internet(() => ({ status: 200, bytes: 5000 })));
    expect(r.findings).toEqual([]);
    expect(r.observations.every((o) => o.outcome === "inconclusive" && /does not exist in the same way/.test(o.why))).toBe(true);
  });
  it("but a real page that differs from the catch-all is still reported", async () => {
    const r = await run(internet((p) => (p === "/api/admin/stats" ? { status: 200, bytes: 9000 } : { status: 200, bytes: 5000 })));
    expect(r.findings.map((f) => f.title)).toEqual(["GET /api/admin/stats answers without signing in"]);
  });
  it("an error or a missing page says nothing about access, and is not reported", async () => {
    for (const status of [404, 405, 500, 503]) {
      const r = await run(internet((p) => (p.startsWith("/__mc-control") ? { status: 404, bytes: 100 } : { status, bytes: 10 })));
      expect(r.findings, String(status)).toEqual([]);
    }
  });
  it("the same finding id every time for the same page, so a repeat is the same finding", async () => {
    const answer = (p: string): Reply => (p === "/api/admin/stats" ? { status: 200, bytes: 4200 } : p.startsWith("/__mc-control") ? { status: 404, bytes: 100 } : { status: 401 });
    expect((await run(internet(answer))).findings[0].id).toBe((await run(internet(answer))).findings[0].id);
  });
});

describe("stopping", () => {
  it("the kill switch stops it between requests: what was found is kept, and nothing more is sent", async () => {
    const reg = new KillRegistry();
    const net = internet(PAGE, { onRequest: (n) => { if (n === 2) void reg.killRepo("acme/shop"); } });
    const r = await run(net, { killRegistry: reg });
    expect(r.run.stopReason).toBe("killed");
    expect(net.sent.length).toBeLessThanOrEqual(3);
    expect(reg.active()).toHaveLength(0);
  });
});
