import { describe, expect, it } from "vitest";
import { cvss3, severityOfLabel, severityOfScore } from "./cvss";
import { parseLockfiles, reach } from "./lockfiles";
import type { SecurityContext } from "../types";

const ctx = (files: Record<string, string>): SecurityContext => ({ repo: "a/b", files: Object.keys(files), read: async (p) => files[p] ?? null });

describe("cvss3", () => {
  it("matches published scores", () => {
    expect(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(9.8);
    expect(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")).toBe(6.1); // the classic reflected XSS
    expect(cvss3("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")).toBe(5.5);
    expect(cvss3("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")).toBe(0);
    expect(cvss3("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(8.1);
  });
  it("refuses what it cannot compute", () => {
    expect(cvss3("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")).toBeNull();
    expect(cvss3("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBeNull();
    expect(cvss3("nonsense")).toBeNull();
  });
  it("maps scores and advisory labels to severities", () => {
    expect([9.8, 7.5, 5.3, 2.1, 0].map(severityOfScore)).toEqual(["critical", "high", "medium", "low", "info"]);
    expect([severityOfLabel("MODERATE"), severityOfLabel("high"), severityOfLabel("???")]).toEqual(["medium", "high", null]);
  });
});

describe("parseLockfiles", () => {
  it("npm v3 lockfile: scoped and nested packages, direct vs transitive, dev flag", async () => {
    const lock = JSON.stringify({ lockfileVersion: 3, packages: {
      "": { name: "app" },
      "node_modules/lodash": { version: "4.17.15" },
      "node_modules/@scope/pkg": { version: "1.0.0" },
      "node_modules/a/node_modules/lodash": { version: "3.0.0" },
      "node_modules/jest": { version: "29.0.0", dev: true },
      "node_modules/linked": { link: true },
    } });
    const pkg = JSON.stringify({ dependencies: { lodash: "^4", "@scope/pkg": "1" }, devDependencies: { jest: "29" } });
    const r = await parseLockfiles(ctx({ "package-lock.json": lock, "package.json": pkg }));
    const by = Object.fromEntries(r.packages.map((p) => [`${p.name}@${p.version}`, p]));
    expect(Object.keys(by).sort()).toEqual(["@scope/pkg@1.0.0", "jest@29.0.0", "lodash@3.0.0", "lodash@4.17.15"]);
    expect(by["lodash@4.17.15"]).toMatchObject({ direct: true, ecosystem: "npm" });
    expect(by["jest@29.0.0"]).toMatchObject({ direct: true, dev: true });
    expect(r.lockfiles).toBe(1);
  });
  it("npm v1 lockfile with nested dependencies", async () => {
    const lock = JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: "1.0.0", dependencies: { b: { version: "2.0.0" } } } } });
    const r = await parseLockfiles(ctx({ "package-lock.json": lock }));
    expect(r.packages.map((p) => `${p.name}@${p.version}`).sort()).toEqual(["a@1.0.0", "b@2.0.0"]);
  });
  it("pnpm and yarn lockfiles", async () => {
    const pnpm = `lockfileVersion: '9.0'\npackages:\n  lodash@4.17.15:\n    resolution: {integrity: x}\n  '@scope/pkg@1.2.3(react@18.0.0)':\n    resolution: {integrity: y}\n`;
    const yarn = `# yarn lockfile v1\n\n"@scope/y@^1.0.0", "@scope/y@^1.1.0":\n  version "1.1.4"\n  resolved "https://x"\n\nleft-pad@^1.3.0:\n  version "1.3.0"\n`;
    const r = await parseLockfiles(ctx({ "pnpm-lock.yaml": pnpm, "sub/yarn.lock": yarn }));
    expect(r.packages.map((p) => `${p.name}@${p.version}`).sort()).toEqual(["@scope/pkg@1.2.3", "@scope/y@1.1.4", "left-pad@1.3.0", "lodash@4.17.15"]);
  });
  it("requirements.txt (pinned only, with line numbers), poetry.lock, Cargo.lock, go.mod", async () => {
    const req = `# deps\nDjango==3.0.0\nrequests>=2.0\nPyYAML[extra]==5.3.1  # pinned\n-r other.txt\n`;
    const poetry = `[[package]]\nname = "Flask"\nversion = "1.0.0"\n\n[[package]]\nname = "jinja2"\nversion = "2.10"\n`;
    const cargo = `[[package]]\nname = "regex"\nversion = "1.5.0"\nsource = "x"\n`;
    const gomod = `module x\nrequire (\n  github.com/a/b v1.2.3\n  github.com/c/d v0.1.0 // indirect\n)\nrequire github.com/e/f v2.0.0\n`;
    const r = await parseLockfiles(ctx({ "requirements.txt": req, "poetry.lock": poetry, "Cargo.lock": cargo, "go.mod": gomod }));
    const names = r.packages.map((p) => `${p.ecosystem}:${p.name}@${p.version}`).sort();
    expect(names).toEqual(["Go:github.com/a/b@v1.2.3", "Go:github.com/c/d@v0.1.0", "Go:github.com/e/f@v2.0.0", "PyPI:django@3.0.0", "PyPI:flask@1.0.0", "PyPI:jinja2@2.10", "PyPI:pyyaml@5.3.1", "crates.io:regex@1.5.0"]);
    expect(r.packages.find((p) => p.name === "django")).toMatchObject({ line: 2, direct: true });
    expect(r.packages.find((p) => p.name === "github.com/c/d")!.direct).toBe(false);
  });
  it("ignores node_modules, tolerates malformed files, and dedupes", async () => {
    const r = await parseLockfiles(ctx({ "node_modules/x/package-lock.json": "{}", "package-lock.json": "{not json", "a/package-lock.json": JSON.stringify({ packages: { "node_modules/x": { version: "1.0.0" }, "node_modules/y/node_modules/x": { version: "1.0.0" } } }) }));
    expect(r.packages).toHaveLength(1);
    expect(r.lockfiles).toBe(2);
  });
});

describe("dependency graph: dev-only and 'why is this here'", () => {
  const PNPM = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      next-auth:
        specifier: ^5.0.0
        version: 5.0.0(react@19.0.0)
    devDependencies:
      tsx:
        specifier: ^4.0.0
        version: 4.0.0
packages:
  next-auth@5.0.0: { resolution: { integrity: x } }
  '@auth/core@0.30.0': { resolution: { integrity: x } }
  node-forge@1.4.0: { resolution: { integrity: x } }
  tsx@4.0.0: { resolution: { integrity: x } }
  esbuild@0.18.20: { resolution: { integrity: x } }
  deepmerge@4.3.1: { resolution: { integrity: x } }
snapshots:
  next-auth@5.0.0(react@19.0.0):
    dependencies:
      '@auth/core': 0.30.0
  '@auth/core@0.30.0':
    dependencies:
      node-forge: 1.4.0
  node-forge@1.4.0: {}
  tsx@4.0.0:
    dependencies:
      esbuild: 0.18.20
  esbuild@0.18.20: {}
  deepmerge@4.3.1: {}
`;
  it("pnpm: a tool reachable only from devDependencies is dev-only; a shipped package is not", async () => {
    const r = await parseLockfiles(ctx({ "pnpm-lock.yaml": PNPM }));
    const by = Object.fromEntries(r.packages.map((p) => [p.name, p]));
    expect(by["esbuild"]).toMatchObject({ dev: true, direct: false, via: ["tsx"] });
    expect(by["tsx"]).toMatchObject({ dev: true, direct: true, via: [] });
    expect(by["node-forge"]).toMatchObject({ dev: false, direct: false });
    expect(by["next-auth"]).toMatchObject({ dev: false, direct: true });
  });
  it("pnpm: explains how a transitive package got here, direct dependency first", async () => {
    const r = await parseLockfiles(ctx({ "pnpm-lock.yaml": PNPM }));
    expect(r.packages.find((p) => p.name === "node-forge")!.via).toEqual(["next-auth", "@auth/core"]);
  });
  it("pnpm: a package nothing reaches keeps no verdict rather than a wrong one", async () => {
    const r = await parseLockfiles(ctx({ "pnpm-lock.yaml": PNPM }));
    const orphan = r.packages.find((p) => p.name === "deepmerge")!;
    expect(orphan.via).toBeUndefined();
    expect(orphan.dev).toBeUndefined();
  });
  it("pnpm: a package needed by BOTH prod and dev counts as prod", async () => {
    const y = `importers:
  .:
    dependencies:
      a: { specifier: 1, version: 1.0.0 }
    devDependencies:
      b: { specifier: 1, version: 1.0.0 }
snapshots:
  a@1.0.0:
    dependencies: { shared: 1.0.0 }
  b@1.0.0:
    dependencies: { shared: 1.0.0 }
  shared@1.0.0: {}
`;
    const r = await parseLockfiles(ctx({ "pnpm-lock.yaml": y }));
    expect(r.packages.find((p) => p.name === "shared")).toMatchObject({ dev: false, via: ["a"] });
  });
  it("pnpm: workspace links and aliases do not break parsing", async () => {
    const y = `importers:
  .:
    dependencies:
      local: { specifier: workspace:*, version: link:../local }
      alias: { specifier: npm:real@2, version: npm:real@2.0.0 }
snapshots:
  real@2.0.0: {}
`;
    const r = await parseLockfiles(ctx({ "pnpm-lock.yaml": y }));
    expect(r.packages.map((p) => p.name)).toEqual(["real"]);
    expect(r.packages[0]).toMatchObject({ dev: false, direct: true });
  });

  it("npm: follows nested node_modules resolution and separates dev from prod", async () => {
    const lock = JSON.stringify({ lockfileVersion: 3, packages: {
      "": { dependencies: { express: "4" }, devDependencies: { jest: "29" } },
      "node_modules/express": { version: "4.18.0", dependencies: { qs: "6" } },
      "node_modules/qs": { version: "6.0.0" },
      "node_modules/express/node_modules/qs": { version: "6.11.0" },
      "node_modules/jest": { version: "29.0.0", dev: true, dependencies: { glob: "7" } },
      "node_modules/glob": { version: "7.0.0", dev: true },
    } });
    const r = await parseLockfiles(ctx({ "package-lock.json": lock }));
    const by = (n: string, v: string) => r.packages.find((p) => p.name === n && p.version === v)!;
    expect(by("qs", "6.11.0")).toMatchObject({ via: ["express"], dev: false }); // express's own nested copy, not the top-level one
    expect(by("qs", "6.0.0").via).toBeUndefined(); // nobody depends on the top-level copy: no invented chain
    expect(by("glob", "7.0.0")).toMatchObject({ dev: true, via: ["jest"] });
    expect(by("express", "4.18.0")).toMatchObject({ direct: true, via: [] });
  });
  it("reach(): shortest chain wins, and cycles terminate", () => {
    const nodes = new Map(["a", "b", "c", "d"].map((n) => [n, { name: n, version: "1" }]));
    const edges = new Map([["a", new Set(["b", "c"])], ["b", new Set(["d"])], ["c", new Set(["d", "a"])], ["d", new Set(["a"])]]);
    const r = reach({ nodes, edges, prod: ["a"], dev: [] });
    expect(r.get("d")!.via).toEqual(["a", "b"]);
    expect(r.size).toBe(4);
  });
});
