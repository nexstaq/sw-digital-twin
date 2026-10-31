import { describe, expect, it } from "vitest";
import { renderBadge } from "./badge";
import { securityHeaders } from "../security/headers";

describe("renderBadge", () => {
  it("is a valid labelled SVG whose text names the state, not just a colour", () => {
    const s = renderBadge("launch", "NO-GO", "failing");
    expect(s).toMatch(/^<svg [^>]*role="img"/);
    expect(s).toContain('aria-label="launch: NO-GO"');
    expect(s).toContain(">NO-GO<");
    expect(s).toContain("#cf222e");
  });
  it("uses a different fill per tone", () => {
    const fills = (["nominal", "degraded", "failing", "unknown"] as const).map((t) => /fill="(#[0-9a-f]{6})"\/><\/g>/.exec(renderBadge("a", "b", t))![1]);
    expect(new Set(fills).size).toBe(4);
  });
  it("escapes anything that could break out of the markup", () => {
    const s = renderBadge('"><script>alert(1)</script>', "<b>&'", "unknown");
    expect(s).not.toContain("<script>");
    expect(s).not.toContain("<b>");
    expect(s).toContain("&lt;script&gt;");
  });
  it("grows with the text", () => {
    const w = (v: string) => Number(/width="(\d+)"/.exec(renderBadge("launch", v, "unknown"))![1]);
    expect(w("not mapped")).toBeGreaterThan(w("GO"));
  });
});

describe("embeddable headers", () => {
  const corp = (e: boolean) => securityHeaders(true, { embeddable: e }).find((h) => h.key === "Cross-Origin-Resource-Policy")!.value;
  it("only the badge variant is loadable cross-origin", () => {
    expect(corp(false)).toBe("same-origin");
    expect(corp(true)).toBe("cross-origin");
    expect(securityHeaders(true, { embeddable: true }).find((h) => h.key === "X-Frame-Options")!.value).toBe("DENY");
  });
});

describe("locked headers (the security report)", () => {
  const csp = (locked: boolean) => securityHeaders(true, { locked }).find((h) => h.key === "Content-Security-Policy")!.value;
  it("allow no script, no network and no framing at all", () => {
    const c = csp(true);
    expect(c).toContain("default-src 'none'");
    expect(c).not.toMatch(/script-src/);
    expect(c).toContain("frame-ancestors 'none'");
    expect(c).toContain("form-action 'none'");
    expect(csp(false)).toContain("script-src"); // ordinary pages are unchanged
  });
  it("still carry the rest of the hardening headers", () => {
    const h = securityHeaders(true, { locked: true });
    expect(h.find((x) => x.key === "X-Content-Type-Options")!.value).toBe("nosniff");
    expect(h.find((x) => x.key === "Strict-Transport-Security")).toBeTruthy();
  });
});

describe("form-action (the sign-in form is redirected to GitHub, and Chrome applies form-action to redirects)", () => {
  const formAction = () => securityHeaders(true).find((h) => h.key === "Content-Security-Policy")!.value.split("; ").find((d) => d.startsWith("form-action"))!;
  it("allows this site and github.com, and nothing else", () => {
    const prior = process.env.GITHUB_WEB_URL;
    delete process.env.GITHUB_WEB_URL;
    expect(formAction()).toBe("form-action 'self' https://github.com");
    if (prior === undefined) delete process.env.GITHUB_WEB_URL; else process.env.GITHUB_WEB_URL = prior;
  });
  it("follows GITHUB_WEB_URL for GitHub Enterprise Server, and falls back safely on a bad value", () => {
    const prior = process.env.GITHUB_WEB_URL;
    process.env.GITHUB_WEB_URL = "https://ghe.example.com/";
    expect(formAction()).toBe("form-action 'self' https://ghe.example.com");
    process.env.GITHUB_WEB_URL = "not a url";
    expect(formAction()).toBe("form-action 'self' https://github.com");
    if (prior === undefined) delete process.env.GITHUB_WEB_URL; else process.env.GITHUB_WEB_URL = prior;
  });
  it("the locked report page still allows no form at all", () => {
    expect(securityHeaders(true, { locked: true }).find((h) => h.key === "Content-Security-Policy")!.value).toContain("form-action 'none'");
  });
});
