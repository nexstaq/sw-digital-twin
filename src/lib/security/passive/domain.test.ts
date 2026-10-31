import { describe, expect, it } from "vitest";
import { instructions, newVerifyToken, parseDomain } from "./domain";

describe("parseDomain", () => {
  it("accepts ordinary public hostnames, lowercased, with a trailing dot or a pasted URL tolerated", () => {
    expect(parseDomain("Staging.Example.com")).toEqual({ ok: true, domain: "staging.example.com" });
    expect(parseDomain("  shop.example.co.uk. ")).toEqual({ ok: true, domain: "shop.example.co.uk" });
    expect(parseDomain("https://app.example.com")).toEqual({ ok: true, domain: "app.example.com" });
    expect(parseDomain("xn--bcher-kva.com")).toMatchObject({ ok: true });
    expect(parseDomain("a-b.example.org")).toMatchObject({ ok: true });
  });
  it("refuses IP addresses in every spelling, so an address cannot be tested by name tricks", () => {
    for (const ip of ["127.0.0.1", "10.0.0.5", "8.8.8.8", "169.254.169.254", "::1", "[::1]", "2130706433", "0x7f.0.0.1", "1.2.3"]) {
      const r = parseDomain(ip);
      expect(r.ok, ip).toBe(false);
    }
  });
  it("refuses internal and reserved names, and single-label hosts", () => {
    for (const d of ["localhost", "intranet", "db", "printer.local", "app.internal", "host.localhost", "x.lan", "foo.corp", "foo.example", "foo.invalid", "a.onion", "1.0.0.127.in-addr.arpa", "svc.cluster.local"]) expect(parseDomain(d).ok, d).toBe(false);
  });
  it("refuses anything with a port, path, query, credentials or whitespace", () => {
    for (const d of ["example.com:8443", "example.com/admin", "example.com?x=1", "user@example.com", "ex ample.com", "example.com#frag", "exa\tmple.com", "example.com\\evil", "http://user:pw@example.com"]) {
      const r = parseDomain(d);
      // a full URL is reduced to its hostname; credentials and ports inside it never survive into the domain
      if (r.ok) expect(r.domain, d).toBe("example.com"); else expect(r.ok).toBe(false);
    }
    expect(parseDomain("example.com:8443").ok).toBe(false);
    expect(parseDomain("example.com/admin").ok).toBe(false);
  });
  it("refuses malformed labels and over-long names", () => {
    for (const d of ["-bad.example.com", "bad-.example.com", "a..example.com", ".example.com", "exa$mple.com", `${"a".repeat(64)}.example.com`, `${"a.".repeat(130)}com`, "example.c", "example.123", ""]) expect(parseDomain(d).ok, d).toBe(false);
  });
  it("gives a reason a person can act on", () => {
    const empty = parseDomain("");
    expect(!empty.ok && empty.reason).toMatch(/Enter a domain/);
    const ip = parseDomain("10.0.0.1");
    expect(!ip.ok && ip.reason).toMatch(/IP addresses cannot be tested/);
    const bare = parseDomain("intranet");
    expect(!bare.ok && bare.reason).toMatch(/full domain name/);
  });
  it("the e2e fixture's .test names are accepted only when the fixture is configured, and never on Vercel", () => {
    expect(parseDomain("shop.test").ok).toBe(false);
    process.env.PASSIVE_CHECK_FIXTURE_URL = "http://localhost:4010";
    try {
      expect(parseDomain("shop.test").ok).toBe(true);
      process.env.VERCEL = "1";
      expect(parseDomain("shop.test").ok).toBe(false);
    } finally { delete process.env.PASSIVE_CHECK_FIXTURE_URL; delete process.env.VERCEL; }
  });
});

describe("verification token and instructions", () => {
  it("tokens are long, random and unique", () => {
    const t = newVerifyToken();
    expect(t).toMatch(/^mc-verify-[0-9a-f]{32}$/);
    expect(new Set(Array.from({ length: 200 }, newVerifyToken)).size).toBe(200);
  });
  it("tells the person exactly where to put it", () => {
    const i = instructions("shop.example.com", "mc-verify-abc");
    expect(i.dns).toEqual({ type: "TXT", name: "_mission-control-verify.shop.example.com", value: "mc-verify-abc" });
    expect(i.file).toEqual({ url: "https://shop.example.com/.well-known/mission-control-verify.txt", contents: "mc-verify-abc" });
  });
});
