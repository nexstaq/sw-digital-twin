import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import type { RuntimeBucket } from "@/lib/health/signals";
import { fixtureGraph } from "@/lib/graph/fixture";
import { filePersist } from "./file";
import { memoryPersist, mergeBuckets } from "./memory";
import { neonSql, pgPersist, type Sql } from "./pg";
import type { Persist } from "./types";

const NOW = Date.now();
const b = (o: Partial<RuntimeBucket> = {}): RuntimeBucket => ({ source: "otlp", key: "api", ts: NOW - 600_000, errors: 1, requests: 10, p95Ms: 50, ...o });
const SHA = "a".repeat(40);

describe("mergeBuckets", () => {
  it("sums additive rates, takes max latency, keeps distinct buckets apart", () => {
    const m = mergeBuckets([b()], [b({ errors: 2, requests: 5, p95Ms: 80 }), b({ ts: NOW - 300_000 })], NOW);
    expect(m).toHaveLength(2);
    expect(m[0]).toMatchObject({ errors: 3, requests: 15, p95Ms: 80 });
  });
  it("drops buckets past retention and is ordered by time", () => {
    const m = mergeBuckets([b({ ts: NOW - 8 * 86_400_000 })], [b({ ts: NOW - 10 }), b({ ts: NOW - 1000 })], NOW);
    expect(m.map((x) => x.ts)).toEqual([NOW - 1000, NOW - 10]);
  });
  it("does not invent fields that were never reported", () => {
    expect(mergeBuckets([], [{ source: "s", key: "k", ts: NOW, errors: 3 }], NOW)[0].requests).toBeUndefined();
  });
});

const contract = (name: string, make: () => Persist) => describe(`${name} adapter`, () => {
  it("stores the latest security scan per repo (case-insensitive), replacing the previous one", async () => {
    const p = make();
    expect(await p.getFindings("acme/shop")).toBeNull();
    const set = { repo: "acme/shop", sha: "a".repeat(40), scannedAt: 1, findings: [], stats: { files: 3, packages: 2, lockfiles: 1 }, warnings: ["w"] };
    await p.putFindings("Acme/Shop", set);
    expect(await p.getFindings("acme/shop")).toEqual(set);
    await p.putFindings("acme/shop", { ...set, scannedAt: 2, warnings: [] });
    expect((await p.getFindings("acme/shop"))!.scannedAt).toBe(2);
    expect(await p.getFindings("other/repo")).toBeNull();
  });
  it("stores overrides per repo (case-insensitive) and replaces them wholesale", async () => {
    const p = make();
    expect(await p.getOverrides("acme/shop")).toEqual({});
    await p.putOverrides("Acme/Shop", { n1: { label: "Checkout", hidden: true } });
    expect(await p.getOverrides("acme/shop")).toEqual({ n1: { label: "Checkout", hidden: true } });
    await p.putOverrides("acme/shop", {});
    expect(await p.getOverrides("acme/shop")).toEqual({});
  });
  it("stores shares, revokes each once, and keeps repos apart", async () => {
    const p = make();
    const s = { id: "abc", hash: "f".repeat(64), createdBy: "nexstaq", createdAt: 1 };
    await p.addShare("acme/shop", s);
    await p.addShare("acme/shop", { ...s, id: "def", label: "for the board" });
    expect((await p.listShares("acme/shop")).map((x) => x.id)).toEqual(["abc", "def"]);
    expect((await p.listShares("acme/shop"))[1].label).toBe("for the board");
    expect(await p.listShares("other/repo")).toEqual([]);
    expect(await p.revokeShare("Acme/Shop", "abc", 99)).toBe(true);
    expect(await p.revokeShare("acme/shop", "abc", 100)).toBe(false); // already revoked
    expect(await p.revokeShare("acme/shop", "nope", 100)).toBe(false);
    expect(await p.revokeShare("other/repo", "def", 100)).toBe(false);
    const after = await p.listShares("acme/shop");
    expect(after[0].revokedAt).toBe(99);
    expect(after[1].revokedAt).toBeUndefined();
  });
  it("stores and filters buckets per repo (case-insensitive)", async () => {
    const p = make();
    await p.putBuckets("Acme/Shop", [b(), b({ ts: NOW - 5000 })]);
    expect(await p.getBuckets("acme/shop", NOW - 60_000)).toHaveLength(1);
    expect(await p.getBuckets("acme/shop", 0)).toHaveLength(2);
    expect(await p.getBuckets("other/repo", 0)).toEqual([]);
  });
  it("stores confirmed mappings per repo", async () => {
    const p = make();
    expect(await p.getMappings("acme/shop")).toEqual({});
    await p.putMappings("Acme/Shop", { "otlp:api": "api" });
    expect(await p.getMappings("acme/shop")).toEqual({ "otlp:api": "api" });
    await p.putMappings("acme/shop", {});
    expect(await p.getMappings("acme/shop")).toEqual({});
  });
  it("stores one snapshot per commit and lists them oldest first", async () => {
    const p = make();
    await p.putSnapshot("acme/shop", { sha: "b".repeat(40), createdAt: 2, graph: fixtureGraph });
    await p.putSnapshot("acme/shop", { sha: SHA, createdAt: 1, committedAt: "2026-01-01T00:00:00Z", graph: fixtureGraph });
    expect((await p.listSnapshots("acme/shop")).map((s) => s.sha)).toEqual([SHA, "b".repeat(40)]);
    expect((await p.getSnapshot("acme/shop", SHA))!.graph.nodes.length).toBe(fixtureGraph.nodes.length);
    expect(await p.getSnapshot("acme/shop", "c".repeat(40))).toBeNull();
  });
});

let dir = "";
contract("memory", memoryPersist);
contract("file", () => filePersist(path.join(dir || (dir = path.join(tmpdir(), `twin-${process.pid}-${Math.random().toString(36).slice(2)}`)), "x")));
afterAll(async () => { if (dir) await rm(dir, { recursive: true, force: true }); });

describe("file adapter safety", () => {
  it("rejects path-traversal repos and non-sha snapshot names", async () => {
    const d = await mkdtemp(path.join(tmpdir(), "twin-"));
    const p = filePersist(d);
    await expect(p.putBuckets("../../etc/passwd", [b()])).rejects.toThrow();
    await expect(p.putSnapshot("a/b", { sha: "../../x", createdAt: 1, graph: fixtureGraph })).rejects.toThrow();
    expect(await p.getSnapshot("a/b", "../../etc/passwd")).toBeNull();
    await rm(d, { recursive: true, force: true });
  });
});

/**
 * The same contract against real Postgres. Needs TEST_DATABASE_URL (a Neon connection string); skipped otherwise.
 * Every adapter instance gets its own throwaway schema, dropped at the end, so the real tables are never touched.
 */
const PG = process.env.TEST_DATABASE_URL;
const schemas: string[] = [];
const sql: Sql | undefined = PG ? neonSql(PG) : undefined;
const fresh = () => { const s = `t_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`; schemas.push(s); return pgPersist(sql!, s); };

describe.skipIf(!PG)("postgres adapter", { timeout: 30_000 }, () => {
  contract("postgres", fresh);

  it("upserts additively, like the memory adapter: sums counts, max latency, newest top issues, no invented fields", async () => {
    const p = fresh();
    await p.putBuckets("a/b", [b({ requests: undefined }), b({ requests: undefined, errors: 2, p95Ms: 90, top: [{ title: "boom", count: 2, url: "https://x" }] })]); // duplicate inside one batch
    await p.putBuckets("a/b", [b({ requests: undefined, errors: 4, p95Ms: 70 })]); // a later batch for the same bucket
    const [got] = await p.getBuckets("a/b", 0);
    expect(got).toMatchObject({ source: "otlp", key: "api", errors: 7, p95Ms: 90, top: [{ title: "boom" }] });
    expect(got.requests).toBeUndefined();
  });
  it("drops buckets past retention on write", async () => {
    const p = fresh();
    await p.putBuckets("a/b", [b({ ts: NOW - 6 * 86_400_000 })]);
    expect(await p.getBuckets("a/b", 0)).toHaveLength(1);
    await p.putBuckets("a/b", [b({ ts: NOW - 8 * 86_400_000 })]); // expired on arrival
    expect(await p.getBuckets("a/b", 0)).toHaveLength(1);
  });
  it("is safe against hostile input: repo names are parameters, shas are validated", async () => {
    const p = fresh();
    await p.putMappings("x/y'; DROP TABLE mappings;--", { a: "b" });
    expect(await p.getMappings("x/y'; DROP TABLE mappings;--")).toEqual({ a: "b" });
    await expect(p.putSnapshot("a/b", { sha: "x; drop", createdAt: 1, graph: fixtureGraph })).rejects.toThrow();
    expect(() => pgPersist(sql!, "bad; drop schema public")).not.toThrow(); // constructing is lazy...
    await expect(pgPersist(sql!, "bad; drop schema public").getMappings("a/b")).rejects.toThrow(/invalid schema/); // ...but it never reaches the database
  });
  afterAll(async () => { for (const s of schemas) await sql!(`DROP SCHEMA IF EXISTS ${s} CASCADE`); });
});
