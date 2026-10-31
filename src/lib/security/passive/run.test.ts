import { describe, expect, it } from "vitest";
import { PROBE_PATHS } from "./checks";
import { BlockedError, type CertInfo, type Response } from "./net";
import { runPassiveChecks, verifyOwnership } from "./run";
import type { ReqOpts, Transport } from "./transport";

const TOKEN = "mc-verify-0123456789abcdef0123456789abcdef";
const res = (status: number, headers: Response["headers"] = {}, body = ""): Response => ({ status, headers, body, bytes: body.length, truncated: false });
const GOOD_HEADERS = { "strict-transport-security": "max-age=63072000", "content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff" };

interface Call { host: string; path: string; o?: ReqOpts }
function fake(o: { request?: (c: Call) => Response | Promise<Response>; cert?: CertInfo | Error; txt?: Record<string, string[] | Error>; mx?: string[] | Error } = {}) {
  const calls: Call[] = [];
  const log: string[] = [];
  const t: Transport = {
    async request(host, path, opts) { calls.push({ host, path, o: opts }); log.push(`${opts?.scheme ?? "https"} ${opts?.method ?? "GET"} ${path}`); return (o.request ?? (() => res(404)))({ host, path, o: opts }); },
    async cert() { log.push("cert"); if (o.cert instanceof Error) throw o.cert; return o.cert ?? { authorized: true, protocol: "TLSv1.3", daysLeft: 90, keyBits: 256, ec: true }; },
    async txt(name) { log.push(`txt ${name}`); const v = o.txt?.[name]; if (v instanceof Error) throw v; if (!v) throw Object.assign(new Error("ENODATA"), { code: "ENODATA" }); return v; },
    async mx() { log.push("mx"); if (o.mx instanceof Error) throw o.mx; return o.mx ?? []; },
  };
  return { t, calls, log };
}
const noSleep = async () => {};

describe("verifyOwnership", () => {
  const D = "shop.example.com";
  it("accepts the token in the DNS TXT record, without making any web request", async () => {
    const f = fake({ txt: { [`_mission-control-verify.${D}`]: [TOKEN] } });
    expect(await verifyOwnership(D, TOKEN, f.t)).toEqual({ ok: true, via: "dns" });
    expect(f.calls).toHaveLength(0);
  });
  it("falls back to the file on the exact host over HTTPS", async () => {
    const f = fake({ request: () => res(200, {}, `${TOKEN}\n`) });
    expect(await verifyOwnership(D, TOKEN, f.t)).toEqual({ ok: true, via: "file" });
    expect(f.calls[0]).toMatchObject({ host: D, path: "/.well-known/mission-control-verify.txt", o: { scheme: "https" } });
  });
  it("needs the EXACT token: a different one, a longer string containing it, or an empty answer all fail", async () => {
    for (const body of ["mc-verify-ffffffffffffffffffffffffffffffff", `prefix ${TOKEN}`, `${TOKEN} suffix`, "", "<html>" + TOKEN + "</html>"]) {
      const r = await verifyOwnership(D, TOKEN, fake({ request: () => res(200, {}, body) }).t);
      expect(r.ok, JSON.stringify(body)).toBe(false);
    }
    expect((await verifyOwnership(D, TOKEN, fake({ txt: { [`_mission-control-verify.${D}`]: ["mc-verify-wrong", `${TOKEN}x`] } }).t)).ok).toBe(false);
  });
  it("a redirect is NOT followed, so someone else's file at the redirect target proves nothing", async () => {
    const f = fake({ request: () => res(302, { location: "https://attacker.example/mission-control-verify.txt" }) });
    const r = await verifyOwnership(D, TOKEN, f.t);
    expect(r.ok).toBe(false);
    expect(f.calls.every((c) => c.host === D)).toBe(true);
    expect(f.calls).toHaveLength(1);
  });
  it("a non-200, a fetch failure and a private-network block each give their own plain reason", async () => {
    const r404 = await verifyOwnership(D, TOKEN, fake().t);
    expect(!r404.ok && r404.reasons.join(" ")).toMatch(/answered 404/);
    const fail = await verifyOwnership(D, TOKEN, fake({ request: () => { throw new Error("ECONNREFUSED"); } }).t);
    expect(!fail.ok && fail.reasons.join(" ")).toMatch(/could not be fetched \(ECONNREFUSED\)/);
    const priv = await verifyOwnership(D, TOKEN, fake({ request: () => { throw new BlockedError("x"); } }).t);
    expect(!priv.ok && priv.reasons.join(" ")).toMatch(/private network address/);
  });
  it("explains both ways it looked, so the person knows what to fix", async () => {
    const r = await verifyOwnership(D, TOKEN, fake().t);
    expect(!r.ok && r.reasons).toHaveLength(2);
    expect(!r.ok && r.reasons[0]).toContain("_mission-control-verify.shop.example.com");
  });
});

describe("runPassiveChecks", () => {
  const D = "shop.example.com";
  const site = (c: Call) => (c.o?.scheme === "http" ? res(301, { location: `https://${D}/` }) : c.path === "/.well-known/security.txt" ? res(200, {}, "Contact: x") : res(c.path === "/" ? 200 : 404, c.path === "/" ? GOOD_HEADERS : {}));

  it("a healthy site gives no findings", async () => {
    const r = await runPassiveChecks(D, fake({ request: site }).t, { sleep: noSleep });
    expect(r.findings).toEqual([]);
    expect(r.notes).toEqual([]);
  });
  it("makes ordinary, bounded requests, in a fixed order, and only to the domain it was given", async () => {
    const f = fake({ request: site });
    const r = await runPassiveChecks(D, f.t, { sleep: noSleep });
    expect(f.calls.every((c) => c.host === D)).toBe(true);
    expect(f.log.slice(0, 5)).toEqual(["https GET /", "cert", "http GET /", "https GET /", "https OPTIONS /"]);
    expect(f.log.filter((l) => l.startsWith("https GET /") && l !== "https GET /").map((l) => l.slice(10))).toEqual(PROBE_PATHS);
    expect(r.requests).toBeLessThanOrEqual(30);
    expect(f.calls.every((c) => (c.o?.maxBytes ?? 0) <= 4096)).toBe(true); // never asks for a big body
  });
  it("never uses any method but GET and OPTIONS, and sends nothing but a fixed probe origin", async () => {
    const f = fake({ request: site });
    await runPassiveChecks(D, f.t, { sleep: noSleep });
    expect(new Set(f.calls.map((c) => c.o?.method ?? "GET"))).toEqual(new Set(["GET", "OPTIONS"]));
    const heads = f.calls.flatMap((c) => Object.keys(c.o?.headers ?? {}));
    expect(new Set(heads)).toEqual(new Set(["origin"]));
  });
  it("is gentle: it pauses between requests, so it is never a burst", async () => {
    const waits: number[] = [];
    await runPassiveChecks(D, fake({ request: site }).t, { sleep: async (ms) => { waits.push(ms); } });
    expect(waits.length).toBeGreaterThanOrEqual(20);
    expect(waits.every((w) => w >= 50)).toBe(true);
  });
  it("follows a redirect that stays on the same host, but not one that leaves it", async () => {
    const same = fake({ request: (c) => (c.path === "/" && c.o?.scheme !== "http" ? res(301, { location: `https://${D}/home` }) : c.path === "/home" ? res(200, GOOD_HEADERS) : c.o?.scheme === "http" ? res(301, { location: `https://${D}/` }) : res(404)) });
    await runPassiveChecks(D, same.t, { sleep: noSleep });
    expect(same.log[1]).toBe("https GET /home");

    const off = fake({ request: (c) => (c.path === "/" && c.o?.scheme !== "http" ? res(302, { location: "https://elsewhere.example/" }) : res(404)) });
    const r = await runPassiveChecks(D, off.t, { sleep: noSleep });
    expect(off.calls.every((c) => c.host === D)).toBe(true);
    expect(r.notes.join(" ")).toMatch(/redirects to another address/);
  });
  it("caps redirect hops, so a loop cannot run forever", async () => {
    const loop = fake({ request: (c) => (c.o?.scheme === "http" ? res(301, { location: `https://${D}/` }) : res(302, { location: `https://${D}/again` })) });
    await runPassiveChecks(D, loop.t, { sleep: noSleep });
    expect(loop.log.filter((l) => l === "https GET /" || l === "https GET /again").length).toBeLessThanOrEqual(5);
  });
  it("turns what it saw into findings located at the URL", async () => {
    const r = await runPassiveChecks(D, fake({ request: (c) => (c.o?.scheme === "http" ? res(200) : c.path === "/.env" ? res(200, { "content-type": "text/plain" }, "DB_PASSWORD=hunter2hunter2\n") : res(c.path === "/" ? 200 : 404, c.path === "/" ? { "set-cookie": ["sessionid=abc"] } : {})) }).t, { sleep: noSleep });
    const byRule = Object.fromEntries(r.findings.map((f) => [f.ruleId, f]));
    expect(byRule["WEB/exposed-file"]).toMatchObject({ path: `https://${D}/.env`, severity: "high", category: "runtime" });
    expect(byRule["WEB/http-no-redirect"].path).toBe(`http://${D}/`);
    expect(byRule["WEB/cookie-insecure"].title).toContain("sessionid");
    expect(JSON.stringify(r.findings)).not.toContain("hunter2hunter2"); // the file's contents are not kept
  });
  it("an unreachable site stops header and file checks, and says so", async () => {
    const f = fake({ request: () => { throw new Error("ECONNREFUSED"); }, cert: new Error("ECONNREFUSED") });
    const r = await runPassiveChecks(D, f.t, { sleep: noSleep });
    expect(r.findings.map((x) => x.ruleId)).toEqual(["WEB/https-unavailable"]);
    expect(r.notes.join(" ")).toMatch(/could not be fetched over HTTPS/);
    expect(f.calls.filter((c) => c.path !== "/")).toHaveLength(0);
  });
  it("checks email protections only when the domain receives mail", async () => {
    const none = fake({ request: site });
    await runPassiveChecks(D, none.t, { sleep: noSleep });
    expect(none.log.some((l) => l.startsWith("txt"))).toBe(false);
    const mail = fake({ request: site, mx: ["mx.example.com"], txt: { [D]: ["v=spf1 -all"], [`_dmarc.${D}`]: ["v=DMARC1; p=reject"] } });
    const r = await runPassiveChecks(D, mail.t, { sleep: noSleep });
    expect(mail.log).toContain(`txt _dmarc.${D}`);
    expect(r.findings).toEqual([]);
    const bare = await runPassiveChecks(D, fake({ request: site, mx: ["mx.example.com"] }).t, { sleep: noSleep });
    expect(bare.findings.map((x) => x.ruleId).sort()).toEqual(["WEB/dmarc-missing", "WEB/spf-missing"]);
  });
  it("if the network layer refuses the host as private, everything stops and nothing is reported as a finding", async () => {
    const f = fake({ request: () => { throw new BlockedError("shop.example.com resolves to a non-public address, so it will not be contacted"); } });
    const r = await runPassiveChecks(D, f.t, { sleep: noSleep });
    expect(r).toMatchObject({ blocked: true, findings: [] });
    expect(r.notes[0]).toContain("Refused:");
    expect(f.calls).toHaveLength(1); // it did not carry on probing
  });
});
