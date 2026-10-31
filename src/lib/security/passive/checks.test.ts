import { describe, expect, it } from "vitest";
import { analyzeProbe, EXPOSED, parseSetCookie, PROBE_PATHS, toFindings, type PathResult, type Probe } from "./checks";

const SECRET_VALUE = "q7Zp4Lm9Xv2Kd8Tn5Rb3Wc6Yh1Jf0Ga";
const GOOD_HEADERS = {
  "strict-transport-security": "max-age=63072000; includeSubDomains", "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-abc'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff", server: "cloudflare",
};
const GOOD: Probe = {
  domain: "shop.example.com",
  https: { status: 200, headers: GOOD_HEADERS },
  http: { status: 301, location: "https://shop.example.com/" },
  cert: { authorized: true, protocol: "TLSv1.3", daysLeft: 80, keyBits: 256, ec: true },
  paths: PROBE_PATHS.map((path): PathResult => ({ path, status: 404, body: "", bytes: 0 })).map((p) => (p.path === "/.well-known/security.txt" ? { ...p, status: 200, body: "Contact: mailto:x@y" } : p)),
  dns: { mx: [] },
};
const probe = (o: Partial<Probe> = {}): Probe => ({ ...GOOD, ...o });
const ids = (p: Probe) => analyzeProbe(p).map((h) => h.ruleId).sort();
const one = (p: Probe, id: string) => analyzeProbe(p).find((h) => h.ruleId === id)!;
const withPath = (path: string, r: Partial<PathResult>) => probe({ paths: GOOD.paths.map((x) => (x.path === path ? { ...x, ...r } : x)) });

describe("a well-configured site", () => {
  it("produces nothing at all", () => { expect(ids(GOOD)).toEqual([]); });
});

describe("TLS and plain HTTP", () => {
  it("an untrusted certificate says why browsers will warn", () => {
    const h = one(probe({ cert: { authorized: false, authorizationError: "DEPTH_ZERO_SELF_SIGNED_CERT", daysLeft: 80 } }), "WEB/cert-untrusted");
    expect(h).toMatchObject({ severity: "high", cwe: ["CWE-295"] });
    expect(h.reason).toContain("DEPTH_ZERO_SELF_SIGNED_CERT");
  });
  it("expired is high; expiring soon scales with how soon", () => {
    expect(one(probe({ cert: { authorized: false, daysLeft: -3 } }), "WEB/cert-expired")).toMatchObject({ severity: "high", reason: expect.stringContaining("3 days ago") });
    expect(one(probe({ cert: { authorized: true, daysLeft: 10 } }), "WEB/cert-expiring").severity).toBe("medium");
    expect(one(probe({ cert: { authorized: true, daysLeft: 25 } }), "WEB/cert-expiring").severity).toBe("low");
    expect(ids(probe({ cert: { authorized: true, daysLeft: 31 } }))).toEqual([]);
  });
  it("key size: a small RSA key is weak, but a 256-bit elliptic-curve key is strong", () => {
    expect(ids(probe({ cert: { authorized: true, daysLeft: 80, keyBits: 1024, ec: false } }))).toEqual(["WEB/cert-weak-key"]);
    expect(ids(probe({ cert: { authorized: true, daysLeft: 80, keyBits: 256, ec: true } }))).toEqual([]);
    expect(ids(probe({ cert: { authorized: true, daysLeft: 80, keyBits: 2048, ec: false } }))).toEqual([]);
  });
  it("only genuinely old protocols are flagged", () => {
    expect(ids(probe({ cert: { authorized: true, daysLeft: 80, protocol: "TLSv1" } }))).toEqual(["WEB/tls-old-protocol"]);
    expect(ids(probe({ cert: { authorized: true, daysLeft: 80, protocol: "TLSv1.2" } }))).toEqual([]);
  });
  it("HTTPS unreachable is reported with the reason", () => {
    expect(one(probe({ https: { error: "ECONNREFUSED" }, cert: { error: "x" } }), "WEB/https-unavailable").reason).toContain("ECONNREFUSED");
  });
  it("plain HTTP that serves content, versus one that redirects properly", () => {
    expect(one(probe({ http: { status: 200 } }), "WEB/http-no-redirect")).toMatchObject({ severity: "medium", url: "http://shop.example.com/" });
    expect(ids(probe({ http: { status: 308, location: "https://shop.example.com/" } }))).toEqual([]);
    expect(ids(probe({ http: { status: 301, location: "http://other.example.com/" } }))).toEqual(["WEB/http-redirect-insecure"]);
    expect(ids(probe({ http: { error: "ECONNREFUSED" } }))).toEqual([]); // port 80 closed is fine
  });
});

describe("response headers", () => {
  const withHeaders = (headers: Record<string, string | string[]>) => probe({ https: { status: 200, headers } });
  it("flags the missing ones, once each, with a fix", () => {
    const hs = analyzeProbe(withHeaders({}));
    expect(hs.map((h) => h.ruleId).sort()).toEqual(["WEB/clickjacking", "WEB/csp-missing", "WEB/hsts-missing", "WEB/nosniff-missing"]);
    expect(hs.every((h) => h.fix.length > 20 && h.cwe.length > 0)).toBe(true);
  });
  it("HSTS: too short is low; a long lifetime is fine", () => {
    expect(ids(withHeaders({ ...GOOD_HEADERS, "strict-transport-security": "max-age=3600" }))).toEqual(["WEB/hsts-weak"]);
    expect(ids(withHeaders({ ...GOOD_HEADERS, "strict-transport-security": "max-age=31536000" }))).toEqual([]);
  });
  it("CSP: weak policies are flagged, but a nonce or hash makes 'unsafe-inline' harmless", () => {
    const csp = (v: string) => ids(withHeaders({ ...GOOD_HEADERS, "content-security-policy": v }));
    expect(csp("default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")).toEqual(["WEB/csp-weak"]);
    expect(csp("script-src 'self' 'unsafe-eval'; frame-ancestors 'none'")).toEqual(["WEB/csp-weak"]);
    expect(csp("script-src *; frame-ancestors 'none'")).toEqual(["WEB/csp-weak"]);
    expect(csp("script-src 'self' 'unsafe-inline' 'nonce-xyz'; frame-ancestors 'none'")).toEqual([]);
    expect(csp("script-src 'self' 'strict-dynamic' 'unsafe-inline'; frame-ancestors 'none'")).toEqual([]);
    expect(csp("default-src 'self'; frame-ancestors 'none'")).toEqual([]);
  });
  it("clickjacking: either X-Frame-Options or frame-ancestors is enough", () => {
    expect(ids(withHeaders({ ...GOOD_HEADERS, "content-security-policy": "default-src 'self'", "x-frame-options": "DENY" }))).toEqual([]);
    expect(ids(withHeaders({ ...GOOD_HEADERS, "content-security-policy": "default-src 'self'" }))).toEqual(["WEB/clickjacking"]);
  });
  it("version disclosure is flagged only when there is a version", () => {
    expect(ids(withHeaders({ ...GOOD_HEADERS, server: "nginx/1.18.0 (Ubuntu)" }))).toEqual(["WEB/server-version"]);
    expect(ids(withHeaders({ ...GOOD_HEADERS, server: "nginx" }))).toEqual([]);
    expect(ids(withHeaders({ ...GOOD_HEADERS, "x-powered-by": "Express" }))).toEqual(["WEB/powered-by"]);
  });
  it("an unreachable site gets no header findings: nothing was observed", () => {
    expect(ids(probe({ https: { error: "timed out" }, cert: { error: "x" } }))).toEqual(["WEB/https-unavailable"]);
  });
});

describe("cookies", () => {
  const withCookies = (...c: string[]) => probe({ https: { status: 200, headers: { ...GOOD_HEADERS, "set-cookie": c } } });
  it("parses the flags", () => {
    expect(parseSetCookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")).toEqual({ name: "sid", secure: true, httpOnly: true, sameSite: "lax" });
    expect(parseSetCookie("theme=dark")).toEqual({ name: "theme", secure: false, httpOnly: false, sameSite: undefined });
    expect(parseSetCookie("")).toBeNull();
  });
  it("a session cookie without Secure and HttpOnly is medium, and the finding says what each flag prevents", () => {
    const h = one(withCookies("sessionid=abc123; Path=/"), "WEB/cookie-insecure");
    expect(h.severity).toBe("medium");
    expect(h.title).toBe("Cookie “sessionid” is missing Secure, HttpOnly, SameSite");
    expect(h.reason).toMatch(/plain HTTP/);
    expect(h.reason).toMatch(/steal it/);
    expect(h.reason).toMatch(/cross-site request forgery/);
  });
  it("a harmless cookie missing flags is only low, and a properly flagged one is silent", () => {
    expect(one(withCookies("theme=dark; Secure; SameSite=Lax"), "WEB/cookie-insecure")?.severity).toBeUndefined(); // fully fine: HttpOnly is not required for a theme
    expect(one(withCookies("theme=dark"), "WEB/cookie-insecure").severity).toBe("low");
    expect(ids(withCookies("sid=a; Secure; HttpOnly; SameSite=Strict"))).toEqual([]);
  });
  it("one finding per cookie name, and the cookie VALUE is never kept", () => {
    const hs = analyzeProbe(withCookies("sessionid=" + SECRET_VALUE, "sessionid=" + SECRET_VALUE + "; Path=/x", "csrftoken=zzz"));
    expect(hs.filter((h) => h.ruleId === "WEB/cookie-insecure")).toHaveLength(2);
    expect(JSON.stringify(hs)).not.toContain(SECRET_VALUE);
  });
});

describe("CORS and methods", () => {
  const cors = (acao: string, acac?: string) => probe({ cors: { acao, acac } });
  it("reflecting an arbitrary origin is medium, and high with credentials", () => {
    expect(one(cors("https://mission-control-probe.invalid"), "WEB/cors-reflects-origin").severity).toBe("medium");
    expect(one(cors("https://mission-control-probe.invalid", "true"), "WEB/cors-reflects-origin").severity).toBe("high");
  });
  it("a wildcard alone is normal for a public API; with credentials it is flagged", () => {
    expect(ids(cors("*"))).toEqual([]);
    expect(ids(cors("*", "true"))).toEqual(["WEB/cors-wildcard-credentials"]);
    expect(ids(cors("https://app.example.com", "true"))).toEqual([]);
  });
  it("TRACE", () => {
    expect(ids(probe({ options: { allow: "GET, HEAD, OPTIONS, TRACE" } }))).toEqual(["WEB/trace-enabled"]);
    expect(ids(probe({ options: { allow: "GET, HEAD, OPTIONS" } }))).toEqual([]);
  });
});

describe("exposed files: a signature must match", () => {
  const ENV_BODY = `NODE_ENV=production\nDB_PASSWORD=${SECRET_VALUE}\n`;
  it("flags a readable .env, .git/HEAD and SQL dump", () => {
    expect(one(withPath("/.env", { status: 200, contentType: "text/plain", body: ENV_BODY }), "WEB/exposed-file")).toMatchObject({ severity: "high", url: "https://shop.example.com/.env", title: ".env file is publicly readable" });
    expect(ids(withPath("/.git/HEAD", { status: 200, contentType: "text/plain", body: "ref: refs/heads/main\n" }))).toEqual(["WEB/exposed-file"]);
    expect(ids(withPath("/backup.sql", { status: 200, contentType: "application/sql", body: "CREATE TABLE users (id int);" }))).toEqual(["WEB/exposed-file"]);
    expect(ids(withPath("/backup.zip", { status: 200, contentType: "application/zip", body: "PK\u0003\u0004rest" }))).toEqual(["WEB/exposed-file"]);
  });
  it("a single-page app that answers 200 with its homepage for EVERY path is not leaking files", () => {
    const spa = probe({ paths: GOOD.paths.map((p) => ({ ...p, status: 200, contentType: "text/html; charset=utf-8", body: "<!doctype html><html><body>app</body></html>" })) });
    expect(ids(spa)).toEqual([]);
  });
  it("a 200 whose body does not match the file's signature is ignored", () => {
    expect(ids(withPath("/.env", { status: 200, contentType: "text/plain", body: "Not found, sorry" }))).toEqual([]);
    expect(ids(withPath("/.git/HEAD", { status: 200, contentType: "text/plain", body: "<html>" }))).toEqual([]);
  });
  it("a 403/404 is exactly what we want to see", () => {
    expect(ids(withPath("/.env", { status: 403, body: ENV_BODY }))).toEqual([]);
  });
  it("some pages are legitimately HTML (phpinfo, server-status)", () => {
    expect(ids(withPath("/phpinfo.php", { status: 200, contentType: "text/html", body: "<title>phpinfo()</title>PHP Version 8.1" }))).toEqual(["WEB/exposed-file"]);
  });
  it("the file's CONTENTS never appear in what we keep", () => {
    const fs = toFindings("shop.example.com", analyzeProbe(withPath("/.env", { status: 200, contentType: "text/plain", body: ENV_BODY })));
    expect(JSON.stringify(fs)).not.toContain(SECRET_VALUE);
    expect(JSON.stringify(fs)).not.toContain("DB_PASSWORD");
  });
  it("every probed path has a signature, so none can fire on a bare 200", () => {
    for (const e of EXPOSED) { expect(e.sig("").valueOf(), e.path).toBe(false); expect(e.sig("hello world"), e.path).toBe(false); }
  });
  it("a missing security.txt is an informational note only", () => {
    const f = one(withPath("/.well-known/security.txt", { status: 404 }), "WEB/no-security-txt");
    expect(f.severity).toBe("info");
  });
});

describe("email protections", () => {
  const mail = (spf?: string[], dmarc?: string[]) => probe({ dns: { mx: ["mx.example.com"], spf, dmarc } });
  it("a domain with no mail is not asked for SPF or DMARC", () => { expect(ids(probe({ dns: { mx: [] } }))).toEqual([]); });
  it("a domain that receives mail needs both", () => { expect(ids(mail([], []))).toEqual(["WEB/dmarc-missing", "WEB/spf-missing"]); });
  it("SPF that authorises everyone is flagged, and +all is high", () => {
    expect(one(mail(["v=spf1 +all"], ["v=DMARC1; p=reject"]), "WEB/spf-permissive").severity).toBe("high");
    expect(one(mail(["v=spf1 ?all"], ["v=DMARC1; p=reject"]), "WEB/spf-permissive").severity).toBe("low");
    expect(ids(mail(["v=spf1 include:_spf.google.com -all"], ["v=DMARC1; p=reject"]))).toEqual([]);
  });
  it("DMARC in monitor-only mode is a low note", () => {
    expect(ids(mail(["v=spf1 -all"], ["v=DMARC1; p=none"]))).toEqual(["WEB/dmarc-none"]);
  });
});

describe("toFindings", () => {
  it("become 'live testing' findings located at the URL, attributed to the domain, with stable ids", () => {
    const hits = analyzeProbe(probe({ https: { status: 200, headers: {} } }));
    const fs = toFindings("shop.example.com", hits);
    expect(fs.length).toBe(hits.length);
    for (const f of fs) expect(f).toMatchObject({ category: "runtime", detail: { source: "passive:shop.example.com", sourceName: "shop.example.com" }, path: expect.stringMatching(/^(https?|dns):/) });
    expect(toFindings("shop.example.com", analyzeProbe(probe({ https: { status: 200, headers: {} } }))).map((f) => f.id)).toEqual(fs.map((f) => f.id));
    expect(new Set(fs.map((f) => f.id)).size).toBe(fs.length);
  });
  it("the same rule on different domains is a different finding", () => {
    const a = toFindings("a.example.com", analyzeProbe(probe({ domain: "a.example.com", https: { status: 200, headers: {} } })));
    const b = toFindings("b.example.com", analyzeProbe(probe({ domain: "b.example.com", https: { status: 200, headers: {} } })));
    expect(a[0].id).not.toBe(b[0].id);
  });
});
