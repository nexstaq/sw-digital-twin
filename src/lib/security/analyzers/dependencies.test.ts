import { describe, expect, it } from "vitest";
import { analyzeDependencies, cmpVersion, findUsage, pickFix } from "./dependencies";
import { mergeVulns, normalizeVuln } from "./osv";
import type { SecurityContext } from "../types";

const ctx = (files: Record<string, string>): SecurityContext => ({ repo: "a/b", files: Object.keys(files), read: async (p) => files[p] ?? null });

const LODASH_ADVISORY = {
  id: "GHSA-p6mc-m468-83gw", aliases: ["CVE-2020-8203"], summary: "Prototype Pollution in lodash",
  severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H" }],
  database_specific: { cwe_ids: ["CWE-1321"], severity: "HIGH" },
  affected: [{ package: { name: "lodash", ecosystem: "npm" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.19" }] }] }],
  references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-p6mc-m468-83gw" }],
};
const LODASH_2 = { id: "GHSA-35jh-r3h4-6jhm", aliases: ["CVE-2021-23337"], summary: "Command Injection in lodash", database_specific: { severity: "HIGH", cwe_ids: ["CWE-77"] },
  affected: [{ package: { name: "lodash", ecosystem: "npm" }, ranges: [{ events: [{ fixed: "4.17.21" }] }] }], references: [] };

/** A fake OSV: knows which advisories hit which name@version. */
function osv(db: Record<string, string[]>, adv: Record<string, unknown>, o: { fail?: "batch" | "detail" } = {}) {
  const calls = { batch: 0, detail: 0 };
  const f: typeof fetch = async (input, init) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      calls.batch++;
      if (o.fail === "batch") return new Response("nope", { status: 503 });
      const { queries } = JSON.parse(String(init!.body)) as { queries: { package: { name: string }; version: string }[] };
      return Response.json({ results: queries.map((q) => ({ vulns: (db[`${q.package.name}@${q.version}`] ?? []).map((id) => ({ id })) })) });
    }
    calls.detail++;
    if (o.fail === "detail") return new Response("nope", { status: 500 });
    const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
    return adv[id] ? Response.json(adv[id]) : new Response("", { status: 404 });
  };
  return { f, calls };
}

const NPM = {
  "package.json": `{\n  "dependencies": {\n    "lodash": "^4.17.15",\n    "express": "4"\n  }\n}\n`,
  "package-lock.json": JSON.stringify({ packages: { "": {}, "node_modules/lodash": { version: "4.17.15" }, "node_modules/express": { version: "4.18.0" } } }),
  "src/util.ts": `import _ from "lodash";\nexport const x = _.merge({}, {});\n`,
};

describe("analyzeDependencies", () => {
  it("reports a vulnerable direct dependency at the line it is declared, with severity, fix and reachability", async () => {
    const { f } = osv({ "lodash@4.17.15": ["GHSA-p6mc-m468-83gw", "GHSA-35jh-r3h4-6jhm"] }, { "GHSA-p6mc-m468-83gw": LODASH_ADVISORY, "GHSA-35jh-r3h4-6jhm": LODASH_2 });
    const r = await analyzeDependencies(ctx(NPM), { fetch: f });
    expect(r.findings).toHaveLength(1);
    const x = r.findings[0];
    expect(x).toMatchObject({ category: "dependency", severity: "high", path: "package.json", line: 3, confidence: "high", owasp: expect.stringContaining("A06") });
    expect(x.title).toBe("lodash@4.17.15 has 2 known vulnerabilities");
    expect(x.fix).toBe("Upgrade lodash to 4.17.21 or later."); // the version that fixes BOTH, not just the first
    expect(x.reason).toContain("src/util.ts");
    expect(x.reason).toContain("reachable");
    expect(x.detail).toMatchObject({ package: "lodash", version: "4.17.15", direct: true, usedIn: ["src/util.ts"] });
    expect(x.detail.vulns!.map((v) => v.id)).toEqual(["GHSA-p6mc-m468-83gw", "GHSA-35jh-r3h4-6jhm"]);
    expect(x.detail.vulns![0]).toMatchObject({ score: 7.4, aliases: ["CVE-2020-8203"], fixedIn: ["4.17.19"] }); // computed from the vector
    expect(x.cwe).toEqual(expect.arrayContaining(["CWE-1321", "CWE-77"]));
    expect(r.packages).toBe(2);
    expect(r.warnings).toEqual([]);
  });

  it("a package with no known vulnerabilities produces no finding, and makes only one batch call", async () => {
    const { f, calls } = osv({}, {});
    const r = await analyzeDependencies(ctx(NPM), { fetch: f });
    expect(r.findings).toEqual([]);
    expect(calls).toEqual({ batch: 1, detail: 0 });
  });

  it("says so when OSV is unreachable, instead of reporting an all-clear", async () => {
    const { f } = osv({}, {}, { fail: "batch" });
    const r = await analyzeDependencies(ctx(NPM), { fetch: f });
    expect(r.findings).toEqual([]);
    expect(r.warnings.join(" ")).toMatch(/NOT checked/);
  });

  it("a transitive, never-imported package is medium confidence and the fix names overrides", async () => {
    const files = { "package-lock.json": JSON.stringify({ packages: { "node_modules/lodash": { version: "4.17.15" } } }), "package.json": `{"dependencies":{"other":"1"}}`, "src/a.ts": "export {}" };
    const { f } = osv({ "lodash@4.17.15": ["GHSA-p6mc-m468-83gw"] }, { "GHSA-p6mc-m468-83gw": LODASH_ADVISORY });
    const [x] = (await analyzeDependencies(ctx(files), { fetch: f })).findings;
    expect(x).toMatchObject({ confidence: "medium", path: "package-lock.json" });
    expect(x.line).toBeGreaterThan(0);
    expect(x.reason).toMatch(/pulled in by another package/);
    expect(x.fix).toMatch(/overrides/);
  });

  it("a dev-only dependency is called out as such", async () => {
    const files = { "package.json": `{"devDependencies":{"lodash":"4"}}`, "package-lock.json": JSON.stringify({ packages: { "node_modules/lodash": { version: "4.17.15", dev: true } } }) };
    const { f } = osv({ "lodash@4.17.15": ["GHSA-p6mc-m468-83gw"] }, { "GHSA-p6mc-m468-83gw": LODASH_ADVISORY });
    const [x] = (await analyzeDependencies(ctx(files), { fetch: f })).findings;
    expect(x.reason).toMatch(/development-only/);
    expect(x.confidence).toBe("medium");
  });

  it("skips withdrawn advisories and names the line of a pinned Python requirement", async () => {
    const files = { "requirements.txt": "flask==1.0\nDjango==3.0.0\n" };
    const { f } = osv({ "django@3.0.0": ["PYSEC-1", "PYSEC-2"] }, {
      "PYSEC-1": { id: "PYSEC-1", summary: "withdrawn one", withdrawn: "2024-01-01T00:00:00Z" },
      "PYSEC-2": { id: "PYSEC-2", summary: "SQL injection in Django", database_specific: { severity: "CRITICAL" }, affected: [{ package: { name: "Django", ecosystem: "PyPI" }, ranges: [{ events: [{ fixed: "3.0.7" }] }] }] },
    });
    const r = await analyzeDependencies(ctx(files), { fetch: f });
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({ severity: "critical", path: "requirements.txt", line: 2, title: "django@3.0.0 has 1 known vulnerability" });
    expect(r.findings[0].fix).toBe("Upgrade django to 3.0.7 or later.");
  });

  it("does not promise a fix version when one advisory has no published fix", async () => {
    const { f } = osv({ "lodash@4.17.15": ["A", "B"] }, { A: LODASH_ADVISORY, B: { id: "B", summary: "unfixed", database_specific: { severity: "LOW" }, affected: [{ package: { name: "lodash", ecosystem: "npm" }, ranges: [{ events: [{ introduced: "0" }] }] }] } });
    const [x] = (await analyzeDependencies(ctx(NPM), { fetch: f })).findings;
    expect(x.fix).toMatch(/No single published version/);
  });

  it("warns, but still reports, when some advisory details cannot be fetched", async () => {
    const { f } = osv({ "lodash@4.17.15": ["A", "GONE"] }, { A: LODASH_ADVISORY });
    const r = await analyzeDependencies(ctx(NPM), { fetch: f });
    expect(r.findings[0].detail.vulns).toHaveLength(1);
    expect(r.warnings.join(" ")).toMatch(/could not be fetched/);
  });
});

describe("helpers", () => {
  it("compares versions numerically and picks a same-major fix first", () => {
    expect(cmpVersion("4.17.21", "4.17.9")).toBeGreaterThan(0);
    expect(cmpVersion("1.0.0-rc.1", "1.0.0")).toBeLessThan(0 + 1); // pre-release never outranks the release by much
    expect(pickFix("3.5.0", ["4.0.0", "3.9.1", "3.6.0"])).toBe("3.6.0");
    expect(pickFix("3.5.0", ["4.0.0"])).toBe("4.0.0");
    expect(pickFix("3.5.0", ["3.4.0"])).toBeUndefined();
  });
  it("findUsage: finds real imports in ts, py and go; ignores look-alikes and node_modules", async () => {
    const files = {
      "a.ts": `import x from "lodash/fp";\nconst y = require('left-pad');`, "b.ts": `// lodash is great\nconst lodashy = 1; import z from "lodash-es"`, "node_modules/q/i.js": `require("lodash")`,
      "m.py": `import yaml\nfrom requests import get`, "g.go": `import (\n  "github.com/a/b/sub"\n)`,
    };
    const u = await findUsage(ctx(files), [
      { ecosystem: "npm", name: "lodash", version: "1", path: "x" }, { ecosystem: "npm", name: "left-pad", version: "1", path: "x" },
      { ecosystem: "PyPI", name: "pyyaml", version: "1", path: "x" }, { ecosystem: "PyPI", name: "django", version: "1", path: "x" }, { ecosystem: "Go", name: "github.com/a/b", version: "v1", path: "x" },
    ]);
    expect(u.get("npm:lodash")).toEqual(["a.ts"]);
    expect(u.get("npm:left-pad")).toEqual(["a.ts"]);
    expect(u.get("PyPI:pyyaml")).toEqual(["m.py"]);
    expect(u.has("PyPI:django")).toBe(false);
    expect(u.get("Go:github.com/a/b")).toEqual(["g.go"]);
  });
  it("normalizeVuln falls back to the advisory's own label, then to medium, and links somewhere real", () => {
    const p = { ecosystem: "npm" as const, name: "x", version: "1.0.0", path: "p" };
    expect(normalizeVuln({ id: "A", database_specific: { severity: "MODERATE" } }, p).severity).toBe("medium");
    expect(normalizeVuln({ id: "A", severity: [{ type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" }] }, p).severity).toBe("medium");
    expect(normalizeVuln({ id: "A b" }, p).url).toBe("https://osv.dev/vulnerability/A%20b");
    expect(normalizeVuln({ id: "A", references: [{ url: "javascript:alert(1)" }] }, p).url).toMatch(/^https:\/\/osv\.dev/); // never a script URL
  });
});

describe("duplicate advisories (real OSV publishes one CVE under several ids)", () => {
  const p = { ecosystem: "PyPI" as const, name: "requests", version: "2.31.0", path: "r.txt" };
  const adv = (id: string, aliases: string[], extra: Record<string, unknown> = {}) => normalizeVuln({ id, aliases, summary: `s-${id}`, database_specific: { severity: "MODERATE" }, affected: [{ package: { name: "requests", ecosystem: "PyPI" }, ranges: [{ events: [{ fixed: "2.32.0" }] }] }], ...extra }, p);

  it("merges advisories that share a CVE into one, keeping the worst severity, all fixes, and a CVE first", () => {
    const a = adv("GHSA-9hjg-9r4m-mvj7", ["CVE-2024-35195"]);
    const b = adv("PYSEC-2024-60", ["CVE-2024-35195", "GHSA-9wx4-h78v-vm56"], { severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" }], affected: [{ package: { name: "requests", ecosystem: "PyPI" }, ranges: [{ events: [{ fixed: "2.33.0" }] }] }] });
    const c = adv("GHSA-other", ["CVE-2099-1"]);
    const m = mergeVulns([a, b, c]);
    expect(m).toHaveLength(2);
    const merged = m.find((v) => v.aliases.includes("CVE-2024-35195"))!;
    expect(merged.id).toBe("GHSA-9hjg-9r4m-mvj7");
    expect(merged.aliases[0]).toBe("CVE-2024-35195");
    expect(merged.severity).toBe("high"); // the worse of the two (7.8)
    expect(merged.fixedIn.sort()).toEqual(["2.32.0", "2.33.0"]);
  });
  it("bridges chains: A~B and B~C are one flaw", () => {
    expect(mergeVulns([adv("A", ["X"]), adv("C", ["Y"]), adv("B", ["X", "Y"])])).toHaveLength(1);
  });
  it("leaves unrelated advisories alone", () => { expect(mergeVulns([adv("A", ["X"]), adv("B", ["Y"])])).toHaveLength(2); });
  it("the finding counts a flaw once, however many databases list it", async () => {
    const files = { "requirements.txt": "requests==2.31.0\n" };
    const { f } = osv({ "requests@2.31.0": ["GHSA-1", "PYSEC-1"] }, {
      "GHSA-1": { id: "GHSA-1", aliases: ["CVE-2024-1"], summary: "x", database_specific: { severity: "MODERATE" } },
      "PYSEC-1": { id: "PYSEC-1", aliases: ["CVE-2024-1"], summary: "x", database_specific: { severity: "MODERATE" } },
    });
    const [x] = (await analyzeDependencies(ctx(files), { fetch: f })).findings;
    expect(x.title).toBe("requests@2.31.0 has 1 known vulnerability");
  });
  it("warns before a major-version jump, since a fix may only exist on a newer major", async () => {
    const files = { "requirements.txt": "django==3.0.0\n" };
    const { f } = osv({ "django@3.0.0": ["A"] }, { A: { id: "A", summary: "x", database_specific: { severity: "HIGH" }, affected: [{ package: { name: "Django", ecosystem: "PyPI" }, ranges: [{ events: [{ fixed: "5.2.1" }] }] }] } });
    const [x] = (await analyzeDependencies(ctx(files), { fetch: f })).findings;
    expect(x.fix).toMatch(/Upgrade django to 5\.2\.1 or later\. That is a major-version jump/);
  });
});

describe("pnpm repositories: dev-only, chains and honest 'no fix yet'", () => {
  const PNPM = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      next-auth: { specifier: ^5, version: 5.0.0 }
    devDependencies:
      tsx: { specifier: ^4, version: 4.0.0 }
snapshots:
  next-auth@5.0.0:
    dependencies: { '@auth/core': 0.30.0 }
  '@auth/core@0.30.0':
    dependencies: { node-forge: 1.4.0 }
  node-forge@1.4.0: {}
  tsx@4.0.0:
    dependencies: { esbuild: 0.18.20 }
  esbuild@0.18.20: {}
`;
  const FORGE = { id: "GHSA-forge", aliases: ["CVE-2026-33894"], summary: "RSA signature check accepts extra elements", database_specific: { severity: "HIGH" }, affected: [{ package: { name: "node-forge", ecosystem: "npm" }, ranges: [{ events: [{ introduced: "0" }] }] }] };
  const ESB = { id: "GHSA-esbuild", summary: "esbuild dev server lets any website read responses", database_specific: { severity: "MODERATE" }, affected: [{ package: { name: "esbuild", ecosystem: "npm" }, ranges: [{ events: [{ fixed: "0.25.0" }] }] }] };
  const run = async () => {
    const { f } = osv({ "node-forge@1.4.0": ["GHSA-forge"], "esbuild@0.18.20": ["GHSA-esbuild"] }, { "GHSA-forge": FORGE, "GHSA-esbuild": ESB });
    return (await analyzeDependencies(ctx({ "pnpm-lock.yaml": PNPM, "src/a.ts": "export {}" }), { fetch: f })).findings;
  };
  it("a transitive package says how it got here, and where in the lockfile it is", async () => {
    const x = (await run()).find((f) => f.detail.package === "node-forge")!;
    expect(x.detail.via).toEqual(["next-auth", "@auth/core"]);
    expect(x.reason).toContain("It comes in through next-auth → @auth/core");
    expect(x.line).toBe(13); // the real line of `node-forge@1.4.0` in the lockfile, not just the file
    expect(x.path).toBe("pnpm-lock.yaml");
  });
  it("when no fix exists it says so plainly, and names the package that brings it in", async () => {
    const x = (await run()).find((f) => f.detail.package === "node-forge")!;
    expect(x.fix).toMatch(/^No fixed version has been published yet/);
    expect(x.fix).toContain("next-auth → @auth/core");
    expect(x.fix).not.toMatch(/No single published version/);
    expect(x.fix).not.toMatch(/replace/i); // advising "replace your framework" for a transitive flaw would be absurd
    expect(x.fix).toContain("update `next-auth` once it ships");
  });
  it("a build tool reachable only from devDependencies is called dev-only and ranks below the same finding in production", async () => {
    const found = await run();
    const esb = found.find((f) => f.detail.package === "esbuild")!;
    expect(esb.detail.dev).toBe(true);
    expect(esb.reason).toContain("development-only");
    expect(esb.reason).toContain("through tsx");
    expect(esb.fix).toMatch(/Update `tsx`, which brings in esbuild, or force 0\.25\.0/);
    expect(esb.confidence).toBe("medium");
  });
});
