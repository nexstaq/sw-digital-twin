import { describe, expect, it } from "vitest";
import { depKey, explainUnavailable, fetchGithubAlerts, mapCodeScanning, mapDependabot, mapSecretScanning } from "./github-alerts";
import type { Finding } from "./types";

const AWS = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE";
const SECRET_VALUE = "q7Zp4Lm9Xv2Kd8Tn5Rb3Wc6Yh1Jf0Ga";

const depAlert = (o: Record<string, unknown> = {}) => ({
  number: 1, state: "open", html_url: "https://github.com/acme/shop/security/dependabot/1",
  dependency: { package: { ecosystem: "npm", name: "lodash" }, manifest_path: "package.json", scope: "runtime", relationship: "direct" },
  security_advisory: { ghsa_id: "GHSA-p6mc-m468-83gw", cve_id: "CVE-2020-8203", summary: "Prototype Pollution in lodash", severity: "high", cvss: { score: 7.4 }, cwes: [{ cwe_id: "CWE-1321" }] },
  security_vulnerability: { package: { ecosystem: "npm", name: "lodash" }, severity: "high", first_patched_version: { identifier: "4.17.19" } },
  ...o,
});
const codeAlert = (o: Record<string, unknown> = {}) => ({
  number: 7, state: "open", html_url: "https://github.com/acme/shop/security/code-scanning/7", tool: { name: "CodeQL" },
  rule: { id: "js/sql-injection", description: "Database query built from user-controlled sources", severity: "error", security_severity_level: "high", tags: ["security", "external/cwe/cwe-089"] },
  most_recent_instance: { location: { path: "src/db.ts", start_line: 12, end_line: 14 }, message: { text: "This query depends on a user-provided value." } },
  ...o,
});
const secAlert = (o: Record<string, unknown> = {}) => ({ number: 3, state: "open", secret_type: "aws_access_key_id", secret_type_display_name: "AWS Access Key ID", secret: SECRET_VALUE, html_url: "https://github.com/acme/shop/security/secret-scanning/3", ...o });

/** A fake GitHub keyed by path prefix; unknown paths are 404. */
function gh(routes: Record<string, { status?: number; body?: unknown }>) {
  const calls: string[] = [];
  const f = (async (input: RequestInfo | URL) => {
    const u = new URL(String(input));
    calls.push(u.pathname + u.search);
    const hit = Object.entries(routes).sort((a, b) => b[0].length - a[0].length).find(([k]) => u.pathname === k || u.pathname.startsWith(k));
    const r = hit?.[1] ?? { status: 404, body: { message: "Not Found" } };
    return Response.json(r.body ?? [], { status: r.status ?? 200 });
  }) as unknown as typeof fetch;
  return { f, calls };
}
const R = "/repos/acme/shop";

describe("mapDependabot", () => {
  it("turns an alert into a dependency finding pinned to the manifest, with the fix and advisory", () => {
    const [f] = mapDependabot([depAlert()]);
    expect(f).toMatchObject({ category: "dependency", severity: "high", path: "package.json", ruleId: "dependabot/alert", cwe: ["CWE-1321"], confidence: "high" });
    expect(f.title).toBe("lodash has 1 open Dependabot alert");
    expect(f.fix).toBe("Upgrade lodash to 4.17.19 or later (Dependabot can open this pull request for you).");
    expect(f.detail).toMatchObject({ source: "dependabot", package: "lodash", ecosystem: "npm", direct: true, dev: false, url: "https://github.com/acme/shop/security/dependabot/1" });
    expect(f.detail.vulns![0]).toMatchObject({ id: "GHSA-p6mc-m468-83gw", aliases: ["CVE-2020-8203"], score: 7.4, fixedIn: ["4.17.19"], url: "https://github.com/acme/shop/security/dependabot/1" });
  });
  it("groups several alerts for one package into one finding with the worst severity", () => {
    const [f, ...rest] = mapDependabot([depAlert(), depAlert({ number: 2, security_advisory: { ghsa_id: "GHSA-2", summary: "x", severity: "critical" }, security_vulnerability: { severity: "critical", first_patched_version: { identifier: "4.17.21" } } })]);
    expect(rest).toHaveLength(0);
    expect(f.severity).toBe("critical");
    expect(f.detail.vulns).toHaveLength(2);
    expect(f.fix).toContain("4.17.21");
  });
  it("is honest when a patch is not available, and skips closed alerts and unnamed packages", () => {
    const [f] = mapDependabot([depAlert({ security_vulnerability: { severity: "low", first_patched_version: null } })]);
    expect(f.fix).toContain("No patched version");
    expect(mapDependabot([depAlert({ state: "fixed" }), depAlert({ dependency: {}, security_vulnerability: {} })])).toEqual([]);
  });
  it("only https links, and bounded text, from a source we do not control", () => {
    const [f] = mapDependabot([depAlert({ html_url: "javascript:alert(1)", security_advisory: { ghsa_id: "G", summary: "s".repeat(900), severity: "high" } })]);
    expect(f.detail.vulns![0].url).toBeUndefined();
    expect(f.detail.vulns![0].summary.length).toBeLessThanOrEqual(200);
  });
});

describe("mapCodeScanning", () => {
  it("maps CodeQL-style alerts with location, severity and CWE", () => {
    const [f] = mapCodeScanning([codeAlert()]);
    expect(f).toMatchObject({ category: "code", severity: "high", path: "src/db.ts", line: 12, endLine: 14, ruleId: "codeql/js/sql-injection", cwe: ["CWE-089"], detail: { source: "codeql" } });
    expect(f.reason).toContain("user-provided value");
  });
  it("falls back to the rule's severity when there is no security score, and skips closed or path-less alerts", () => {
    expect(mapCodeScanning([codeAlert({ rule: { id: "r", severity: "warning" } })])[0].severity).toBe("medium");
    expect(mapCodeScanning([codeAlert({ state: "dismissed" }), codeAlert({ most_recent_instance: { location: {} } }), codeAlert({ most_recent_instance: { location: { path: "../../etc/passwd" } } })])).toEqual([]);
  });
});

describe("mapSecretScanning", () => {
  it("NEVER keeps the secret value, anywhere", () => {
    const f = mapSecretScanning([secAlert()], new Map([[3, { path: "src/config.ts", line: 4 }]]));
    expect(f).toHaveLength(1);
    expect(JSON.stringify(f)).not.toContain(SECRET_VALUE);
    expect(f[0]).toMatchObject({ category: "secret", severity: "high", path: "src/config.ts", line: 4, detail: { source: "secret-scanning", secretKind: "AWS Access Key ID", masked: "(value not stored)" } });
  });
  it("an alert GitHub says is still active is critical", () => {
    expect(mapSecretScanning([secAlert({ validity: "active" })], new Map())[0].severity).toBe("critical");
  });
  it("copes with no location", () => {
    expect(mapSecretScanning([secAlert()], new Map())[0].path).toBe("(location not provided by GitHub)");
  });
});

describe("fetchGithubAlerts: all three sources, each with its own status", () => {
  it("pulls everything, fetches secret locations, and drops the secret", async () => {
    const { f } = gh({
      [`${R}/dependabot/alerts`]: { body: [depAlert()] }, [`${R}/code-scanning/alerts`]: { body: [codeAlert()] },
      [`${R}/secret-scanning/alerts/3/locations`]: { body: [{ type: "commit", details: { path: "src/config.ts", start_line: 2, blob_sha: AWS } }] },
      [`${R}/secret-scanning/alerts`]: { body: [secAlert()] },
    });
    const a = await fetchGithubAlerts("acme/shop", "tok", [], f);
    expect(a.sources.dependabot).toMatchObject({ status: "ok", count: 1, via: "github" });
    expect(a.sources["code-scanning"]).toMatchObject({ status: "ok", count: 1 });
    expect(a.sources["secret-scanning"]).toMatchObject({ status: "ok", count: 1 });
    expect(a.findings.map((x) => x.detail.source).sort()).toEqual(["codeql", "dependabot", "secret-scanning"]);
    expect(a.findings.find((x) => x.detail.source === "secret-scanning")).toMatchObject({ path: "src/config.ts", line: 2 });
    expect(JSON.stringify(a)).not.toContain(SECRET_VALUE);
  });

  it("an alert about a package our own scan already flagged is the SAME finding, confirmed, not a duplicate", async () => {
    const mine: Finding = { id: "ours", ruleId: "SCA/known-vulnerability", category: "dependency", severity: "high", title: "lodash@4.17.15", path: "package.json", reason: "r", fix: "f", cwe: [], confidence: "high", detail: { package: "lodash", ecosystem: "npm", version: "4.17.15" } };
    const { f } = gh({ [`${R}/dependabot/alerts`]: { body: [depAlert(), depAlert({ number: 2, dependency: { package: { ecosystem: "npm", name: "left-pad" }, manifest_path: "package.json" }, security_vulnerability: { package: { name: "left-pad" }, severity: "low" } })] }, [`${R}/code-scanning/alerts`]: { status: 404, body: { message: "Not Found" } }, [`${R}/secret-scanning/alerts`]: { status: 404, body: { message: "Not Found" } } });
    const a = await fetchGithubAlerts("acme/shop", "tok", [mine], f);
    expect(a.confirmed.get("ours")).toEqual(["dependabot"]);
    expect(a.findings.map((x) => x.detail.package)).toEqual(["left-pad"]); // lodash merged away, left-pad is new information
  });

  it("each failure says what is actually wrong and what to do", async () => {
    const { f } = gh({
      [`${R}/dependabot/alerts`]: { status: 403, body: { message: "Resource not accessible by integration" } },
      [`${R}/code-scanning/alerts`]: { status: 403, body: { message: "Advanced Security must be enabled for this repository to use code scanning." } },
      [`${R}/secret-scanning/alerts`]: { status: 503, body: { message: "Unavailable" } },
    });
    const a = await fetchGithubAlerts("acme/shop", "tok", [], f);
    expect(a.findings).toEqual([]);
    expect(a.sources.dependabot).toMatchObject({ status: "unavailable", count: 0 });
    expect(a.sources.dependabot.message).toContain('"Dependabot alerts: Read-only"');
    expect(a.sources["code-scanning"].message).toMatch(/not switched on.*Advanced Security/);
    expect(a.sources["secret-scanning"].message).toMatch(/could not be asked.*right now/);
  });

  it("'no analysis found' is a state, not an error: code scanning is on but has not run", async () => {
    const { f } = gh({ [`${R}/code-scanning/alerts`]: { status: 404, body: { message: "no analysis found" } } });
    const a = await fetchGithubAlerts("acme/shop", "tok", [], f);
    expect(a.sources["code-scanning"]).toMatchObject({ status: "ok", count: 0, message: "Code scanning is on, but no analysis has run yet." });
  });

  it("a network failure is reported as unavailable, never as 'no alerts'", async () => {
    const down = (async () => { throw new Error("offline"); }) as unknown as typeof fetch;
    const a = await fetchGithubAlerts("acme/shop", "tok", [], down);
    for (const s of Object.values(a.sources)) expect(s.status).toBe("unavailable");
  });

  it("pages through up to 300 alerts and asks only for open ones", async () => {
    const page = (n: number) => Array.from({ length: 100 }, (_, i) => depAlert({ number: n * 100 + i, dependency: { package: { ecosystem: "npm", name: `p${n}-${i}` }, manifest_path: "package.json" } }));
    let calls = 0;
    const f = (async (input: RequestInfo | URL) => {
      const u = new URL(String(input));
      if (!u.pathname.endsWith("/dependabot/alerts")) return Response.json([], { status: 404 });
      calls++;
      return Response.json(page(Number(u.searchParams.get("page"))));
    }) as unknown as typeof fetch;
    const a = await fetchGithubAlerts("acme/shop", "tok", [], f);
    expect(calls).toBe(3);
    expect(a.sources.dependabot.count).toBe(300);
  });

  it("sends the token as a Bearer header and never in the URL", async () => {
    const seen: { url: string; auth: string | null }[] = [];
    const f = (async (input: RequestInfo | URL, init?: RequestInit) => { seen.push({ url: String(input), auth: new Headers(init?.headers).get("authorization") }); return Response.json([]); }) as unknown as typeof fetch;
    await fetchGithubAlerts("acme/shop", "tok-secret", [], f);
    expect(seen.every((s) => s.auth === "Bearer tok-secret" && !s.url.includes("tok-secret"))).toBe(true);
  });
});

describe("helpers", () => {
  it("depKey lines up Dependabot's ecosystem names with ours", () => {
    expect(depKey("pip", "Django")).toBe("PyPI:django");
    expect(depKey("rust", "regex")).toBe("crates.io:regex");
    expect(depKey("npm", "Lodash")).toBe("npm:lodash");
    expect(depKey("maven", "x")).toBe("maven:x");
  });
  it("explainUnavailable distinguishes a missing permission from a switched-off feature", () => {
    expect(explainUnavailable("secret-scanning", 403, "Resource not accessible by integration")).toContain('"Secret scanning alerts: Read-only"');
    expect(explainUnavailable("dependabot", 403, "Dependabot alerts are disabled for this repository.")).toContain("not switched on");
    expect(explainUnavailable("dependabot", 404, "Not Found")).toContain("may be switched off");
    expect(explainUnavailable("dependabot", 429, "")).toContain("right now");
  });
});
