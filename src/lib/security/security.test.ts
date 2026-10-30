import { beforeEach, describe, expect, it } from "vitest";
import { securityHeaders } from "./headers";
import { clientKey, LIMITS, rateLimit, resetRateLimits, tooManySse } from "./ratelimit";

const req = (ip?: string) => new Request("https://x.test/", { headers: ip ? { "x-forwarded-for": ip } : {} });
const get = (prod: boolean, key: string) => securityHeaders(prod).find((h) => h.key === key)?.value ?? "";

describe("securityHeaders", () => {
  it("production CSP forbids eval, plugins, framing and foreign origins", () => {
    const csp = get(true, "Content-Security-Policy");
    expect(csp).not.toContain("unsafe-eval");
    for (const d of ["default-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "base-uri 'self'", "form-action 'self'", "connect-src 'self'", "upgrade-insecure-requests"]) expect(csp).toContain(d);
    expect(csp).not.toMatch(/\*|http:/); // no wildcards, no plain http
  });
  it("dev allows eval (React stack traces) but production never does; HSTS only in production", () => {
    expect(get(false, "Content-Security-Policy")).toContain("'unsafe-eval'");
    expect(get(false, "Strict-Transport-Security")).toBe("");
    expect(get(true, "Strict-Transport-Security")).toContain("max-age=");
  });
  it("sets the standard hardening headers", () => {
    expect(get(true, "X-Content-Type-Options")).toBe("nosniff");
    expect(get(true, "X-Frame-Options")).toBe("DENY");
    expect(get(true, "Referrer-Policy")).toBe("strict-origin-when-cross-origin");
    expect(get(true, "Permissions-Policy")).toContain("camera=()");
  });
});

describe("rateLimit", () => {
  beforeEach(resetRateLimits);
  const lim = { name: "t", max: 3, windowMs: 1000 };

  it("allows up to max, then refuses with a retry hint", () => {
    for (let i = 0; i < 3; i++) expect(rateLimit(req("1.1.1.1"), lim, 0).ok).toBe(true);
    const v = rateLimit(req("1.1.1.1"), lim, 100);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.retryAfterSec).toBe(1);
  });
  it("counts clients and routes separately", () => {
    for (let i = 0; i < 3; i++) rateLimit(req("1.1.1.1"), lim, 0);
    expect(rateLimit(req("2.2.2.2"), lim, 0).ok).toBe(true);
    expect(rateLimit(req("1.1.1.1"), { ...lim, name: "other" }, 0).ok).toBe(true);
  });
  it("starts a fresh window after it elapses", () => {
    for (let i = 0; i < 4; i++) rateLimit(req("1.1.1.1"), lim, 0);
    expect(rateLimit(req("1.1.1.1"), lim, 1001).ok).toBe(true);
  });
  it("uses the first x-forwarded-for hop, falling back to a shared bucket", () => {
    expect(clientKey(req("9.9.9.9, 10.0.0.1"))).toBe("9.9.9.9");
    expect(clientKey(req())).toBe("anon");
  });
  it("the stream refusal is parseable by the client, with status 429", async () => {
    const r = tooManySse({ ok: false, retryAfterSec: 7 });
    expect(r.status).toBe(429);
    expect(r.headers.get("retry-after")).toBe("7");
    expect(JSON.parse((await r.text()).replace(/^data: /, "")).type).toBe("error");
  });
  it("every shipped limit is sane", () => {
    for (const l of Object.values(LIMITS)) expect(l.max).toBeGreaterThan(0);
  });
});
