import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { BlockedError, guardedLookup, isPublicIp, safeCert, safeRequest, USER_AGENT } from "./net";

describe("isPublicIp: the SSRF guard", () => {
  it("accepts ordinary public addresses, IPv4 and IPv6", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "93.184.216.34", "172.32.0.1", "172.15.255.255", "11.0.0.1", "2606:4700:4700::1111", "2001:4860:4860::8888", "::ffff:8.8.8.8"]) expect(isPublicIp(ip), ip).toBe(true);
  });
  it("refuses loopback, private, link-local, cloud-metadata and carrier-grade ranges", () => {
    for (const ip of ["127.0.0.1", "127.255.255.254", "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.0.1", "192.168.255.255", "169.254.169.254", "169.254.0.1", "100.64.0.1", "100.127.255.255", "0.0.0.0", "0.1.2.3"]) expect(isPublicIp(ip), ip).toBe(false);
  });
  it("refuses multicast, reserved, documentation and benchmarking ranges", () => {
    for (const ip of ["224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255", "192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1", "192.0.0.8"]) expect(isPublicIp(ip), ip).toBe(false);
  });
  it("refuses the IPv6 equivalents", () => {
    for (const ip of ["::1", "::", "fe80::1", "fc00::1", "fd12:3456:789a::1", "ff02::1", "2001:db8::1", "100::1"]) expect(isPublicIp(ip), ip).toBe(false);
  });
  it("sees through IPv4-in-IPv6 and transition tricks, so ::ffff:127.0.0.1 is not a way around the guard", () => {
    for (const ip of ["::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::ffff:7f00:1", "::ffff:a00:1", "::ffff:a9fe:a9fe", "64:ff9b::7f00:1", "2002:7f00:1::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2"]) expect(isPublicIp(ip), ip).toBe(false);
  });
  it("refuses anything that is not an IP address at all", () => {
    for (const x of ["", "localhost", "example.com", "999.1.1.1", "1.2.3", "8.8.8.8/32", "0x7f.0.0.1", "2130706433"]) expect(isPublicIp(x), x).toBe(false);
  });
});

describe("guardedLookup", () => {
  const cb = (resolve: (r: unknown) => void) => (err: Error | null, address?: unknown, family?: number) => resolve({ err, address, family });
  const lookup = (answers: { address: string; family: number }[], o: object = {}, opts: unknown = {}) =>
    new Promise<{ err: Error | null; address?: unknown; family?: number }>((resolve) => guardedLookup({ resolve: async () => answers, ...o })("example.com", opts, cb(resolve as never)));

  it("hands back a validated public address, preferring IPv4", async () => {
    const r = await lookup([{ address: "2606:4700::1", family: 6 }, { address: "93.184.216.34", family: 4 }]);
    expect(r).toMatchObject({ err: null, address: "93.184.216.34", family: 4 });
  });
  it("supports the `all` form too", async () => {
    const r = await lookup([{ address: "8.8.8.8", family: 4 }], {}, { all: true });
    expect(r.address).toEqual([{ address: "8.8.8.8", family: 4 }]);
  });
  it("refuses a host that resolves to a private address", async () => {
    const r = await lookup([{ address: "10.0.0.5", family: 4 }]);
    expect(r.err).toBeInstanceOf(BlockedError);
    expect(r.err!.message).toContain("non-public");
  });
  it("DNS-rebinding style answers: if ANY address is private, the whole host is refused, even when the first is public", async () => {
    expect((await lookup([{ address: "93.184.216.34", family: 4 }, { address: "169.254.169.254", family: 4 }])).err).toBeInstanceOf(BlockedError);
    expect((await lookup([{ address: "93.184.216.34", family: 4 }, { address: "::ffff:127.0.0.1", family: 6 }])).err).toBeInstanceOf(BlockedError);
  });
  it("an empty answer and a resolver failure are errors, not a fallback", async () => {
    expect((await lookup([])).err).toBeInstanceOf(BlockedError);
    const failing = await new Promise<{ err: Error | null }>((resolve) => guardedLookup({ resolve: async () => { throw new Error("ENOTFOUND"); } })("x.com", {}, cb(resolve as never)));
    expect(failing.err?.message).toBe("ENOTFOUND");
  });
});

describe("safeRequest: refusals that happen before any packet is sent", () => {
  it("will not contact localhost, or anything that resolves to loopback", async () => {
    await expect(safeRequest("localhost", "/")).rejects.toBeInstanceOf(BlockedError);
  });
  it("refuses IP literals, host:port, credentials and paths in the host", async () => {
    for (const h of ["127.0.0.1", "8.8.8.8", "::1", "example.com:8080", "user@example.com", "example.com/evil", "exa mple.com", "example.com\r\nX: y"]) await expect(safeRequest(h, "/"), h).rejects.toBeInstanceOf(BlockedError);
  });
  it("refuses a path that could smuggle a header or a second request", async () => {
    for (const p of ["noslash", "/a b", "/a\r\nHost: evil", "/a\nX: y", "http://evil.example/", "/a\u0000b"]) {
      await expect(safeRequest("example.com", p), JSON.stringify(p)).rejects.toBeInstanceOf(BlockedError);
    }
  });
});

describe("safeRequest against a local stand-in server", () => {
  const seen: { headers: http.IncomingHttpHeaders; url?: string; method?: string }[] = [];
  const server = http.createServer((req, res) => {
    seen.push({ headers: req.headers, url: req.url, method: req.method });
    if (req.url === "/ok") { res.writeHead(200, { "content-type": "text/plain", "set-cookie": ["a=1; Secure", "b=2; HttpOnly"], "x-powered-by": "Express" }); return void res.end("hello"); }
    if (req.url === "/redirect") { res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" }); return void res.end(); }
    if (req.url === "/big") { res.writeHead(200); const chunk = Buffer.alloc(64 * 1024, 65); let sent = 0; const pump = () => { while (sent < 5_000_000) { sent += chunk.length; if (!res.write(chunk)) return void res.once("drain", pump); } res.end(); }; return void pump(); }
    if (req.url === "/hang") return; // never answers
    res.writeHead(404); res.end("no");
  });
  const ready = new Promise<number>((r) => server.listen(0, "127.0.0.1", () => r((server.address() as AddressInfo).port)));
  afterAll(() => { server.closeAllConnections(); server.close(); });
  const opts = async (extra: object = {}) => ({ allowPrivate: true, testPort: await ready, scheme: "http" as const, ...extra });

  it("returns status, headers (including every Set-Cookie) and the body", async () => {
    const r = await safeRequest("localhost", "/ok", await opts());
    expect(r.status).toBe(200);
    expect(r.body).toBe("hello");
    expect(r.headers["set-cookie"]).toEqual(["a=1; Secure", "b=2; HttpOnly"]);
    expect(r.headers["x-powered-by"]).toBe("Express");
    expect(r.truncated).toBe(false);
  });
  it("identifies itself, asks for no compression, reuses no connection, and sends no cookies or credentials", async () => {
    seen.length = 0;
    await safeRequest("localhost", "/ok", await opts());
    const h = seen[0].headers;
    expect(h["user-agent"]).toBe(USER_AGENT);
    expect(USER_AGENT).toContain("github.com/nexstaq/sw-digital-twin");
    expect(h["accept-encoding"]).toBe("identity");
    expect(h.connection).toBe("close");
    expect(h.cookie).toBeUndefined();
    expect(h.authorization).toBeUndefined();
    expect(h.host).toContain("localhost");
  });
  it("does NOT follow redirects: a redirect to the metadata service is reported, never visited", async () => {
    seen.length = 0;
    const r = await safeRequest("localhost", "/redirect", await opts());
    expect(r.status).toBe(302);
    expect(r.headers.location).toBe("http://169.254.169.254/latest/meta-data/");
    expect(seen).toHaveLength(1);
  });
  it("never reads more than it asked for: a 5 MB response is cut off at the cap, quickly", async () => {
    const t = Date.now();
    const r = await safeRequest("localhost", "/big", await opts({ maxBytes: 2048 }));
    expect(r.truncated).toBe(true);
    expect(r.body.length).toBeLessThanOrEqual(2048);
    expect(Date.now() - t).toBeLessThan(3000);
  });
  it("gives up on a server that never answers", async () => {
    await expect(safeRequest("localhost", "/hang", await opts({ timeoutMs: 300 }))).rejects.toThrow(/timed out/);
  });
  it("the test-only port and loopback allowance do nothing unless allowPrivate is set", async () => {
    await expect(safeRequest("localhost", "/ok", { testPort: await ready, scheme: "http" })).rejects.toBeInstanceOf(BlockedError);
  });
});

describe("safeCert", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "cert-"));
  let ok = true;
  try {
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", `${dir}/k.pem`, "-out", `${dir}/c.pem`, "-days", "30", "-subj", "/CN=localhost/O=Test Org", "-addext", "subjectAltName=DNS:localhost"], { stdio: "ignore" });
  } catch { ok = false; }

  it.skipIf(!ok)("reads what the server presents without trusting it: self-signed is reported as unauthorised, with expiry and key size", async () => {
    const server = https.createServer({ key: readFileSync(`${dir}/k.pem`), cert: readFileSync(`${dir}/c.pem`) }, (_q, r) => r.end("x"));
    const port = await new Promise<number>((r) => server.listen(0, "127.0.0.1", () => r((server.address() as AddressInfo).port)));
    try {
      const info = await safeCert("localhost", { allowPrivate: true, testPort: port });
      expect(info.authorized).toBe(false);
      expect(info.authorizationError).toMatch(/SELF_SIGNED|self.signed/i);
      expect(info.protocol).toMatch(/^TLSv1\.[23]$/);
      expect(info.keyBits).toBe(2048);
      expect(info.subject).toBe("localhost");
      expect(info.names).toContain("localhost");
      expect(info.daysLeft).toBeGreaterThanOrEqual(29);
      expect((await safeCert("localhost", { allowPrivate: true, testPort: port, now: Date.now() + 400 * 86_400_000 })).daysLeft).toBeLessThan(0); // an expired certificate reads as negative days
    } finally { server.closeAllConnections(); server.close(); }
  });
  it("refuses to connect to private addresses, like everything else", async () => {
    await expect(safeCert("localhost")).rejects.toBeInstanceOf(BlockedError);
    await expect(safeCert("127.0.0.1")).rejects.toBeInstanceOf(BlockedError);
  });
});
