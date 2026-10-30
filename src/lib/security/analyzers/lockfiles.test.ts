import { describe, expect, it } from "vitest";
import { cvss3, severityOfLabel, severityOfScore } from "./cvss";
import { parseLockfiles } from "./lockfiles";
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
