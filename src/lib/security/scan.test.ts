import { describe, expect, it } from "vitest";
import { analyzeContext } from "./scan";
import type { SecurityContext } from "./types";

const AWS = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE";
const ctx = (files: Record<string, string>): SecurityContext => ({ repo: "a/b", files: Object.keys(files), read: async (p) => files[p] ?? null });
const offline: typeof fetch = async () => new Response("down", { status: 503 });

const FILES = {
  "src/config.ts": `export const k = "${AWS}";`,
  "Dockerfile": "FROM node:24\nCMD x\n",
  ".github/workflows/ci.yml": "on: push\npermissions: read-all\njobs:\n  a:\n    steps:\n      - uses: foo/bar@v1\n",
  "package-lock.json": JSON.stringify({ packages: { "node_modules/x": { version: "1.0.0" } } }),
};

describe("analyzeContext", () => {
  it("combines every analyzer, ranks the worst first, and records what it scanned", async () => {
    const set = await analyzeContext(ctx(FILES), { sha: "a".repeat(40), now: 5 }, { fetch: async () => Response.json({ results: [{}] }) });
    expect(new Set(set.findings.map((f) => f.category))).toEqual(new Set(["secret", "container", "pipeline"]));
    expect(set.findings[0]).toMatchObject({ category: "secret", severity: "critical" });
    expect(set).toMatchObject({ repo: "a/b", sha: "a".repeat(40), scannedAt: 5, stats: { packages: 1, lockfiles: 1 } });
    expect(set.warnings).toEqual([]);
  });
  it("an unreachable vulnerability database becomes a visible warning, not a clean bill of health", async () => {
    const set = await analyzeContext(ctx(FILES), { sha: "s" }, { fetch: offline });
    expect(set.warnings.join(" ")).toMatch(/NOT checked/);
    expect(set.findings.length).toBeGreaterThan(0); // the other analyzers still report
  });
  it("one analyzer crashing does not take the others down, and says what is missing", async () => {
    const bad: SecurityContext = { repo: "a/b", files: ["Dockerfile", "src/a.ts"], read: async (p) => { if (p === "src/a.ts") throw new Error("disk gone"); return "FROM node:24\n"; } };
    const set = await analyzeContext(bad, { sha: "s" });
    expect(set.findings.some((f) => f.category === "container")).toBe(true);
    expect(set.warnings.join(" ")).toMatch(/Secrets check failed \(disk gone\)/);
  });
  it("an empty repository is a valid, empty result", async () => {
    const set = await analyzeContext(ctx({}), { sha: "s" });
    expect(set.findings).toEqual([]);
    expect(set.stats).toEqual({ files: 0, packages: 0, lockfiles: 0 });
  });
  it("the stored result holds no secret value", async () => {
    const set = await analyzeContext(ctx(FILES), { sha: "s" }, { fetch: async () => Response.json({ results: [{}] }) });
    expect(JSON.stringify(set)).not.toContain(AWS);
  });
});
