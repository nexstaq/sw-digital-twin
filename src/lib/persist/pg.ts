import { neon } from "@neondatabase/serverless";
import type { Overrides } from "@/lib/graph/overrides";
import type { RuntimeBucket } from "@/lib/health/signals";
import type { FindingSet } from "@/lib/security/types";
import type { Share } from "@/lib/share/token";
import { mergeBuckets } from "./memory";
import { RETENTION_MS, type Persist, type Snapshot, type SnapshotMeta } from "./types";

const SAFE_SHA = /^[0-9a-f]{40}$/;
const SAFE_NAME = /^[a-z_][a-z0-9_]{0,40}$/;

export type Sql = (text: string, params?: unknown[]) => Promise<Record<string, unknown>[]>;

/** One statement per call over Neon's HTTP driver: no connection to hold open, which suits serverless. */
export function neonSql(url: string): Sql {
  const sql = neon(url);
  return (text, params = []) => sql.query(text, params) as Promise<Record<string, unknown>[]>;
}

/** Idempotent. `schema` isolates tests (and could isolate tenants); the name is validated because it is spliced into SQL. */
export function ddl(schema: string): string[] {
  if (!SAFE_NAME.test(schema)) throw new Error("invalid schema name");
  const s = schema;
  return [
    `CREATE SCHEMA IF NOT EXISTS ${s}`,
    `CREATE TABLE IF NOT EXISTS ${s}.buckets (
       repo text NOT NULL, source text NOT NULL, key text NOT NULL, ts bigint NOT NULL,
       errors double precision, requests double precision, p95_ms double precision, top jsonb,
       PRIMARY KEY (repo, source, key, ts))`,
    `CREATE TABLE IF NOT EXISTS ${s}.snapshots (
       repo text NOT NULL, sha text NOT NULL, committed_at text, created_at bigint NOT NULL, graph jsonb NOT NULL,
       PRIMARY KEY (repo, sha))`,
    `CREATE TABLE IF NOT EXISTS ${s}.mappings (repo text PRIMARY KEY, mappings jsonb NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS ${s}.findings (repo text PRIMARY KEY, data jsonb NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS ${s}.overrides (repo text PRIMARY KEY, overrides jsonb NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS ${s}.shares (
       repo text NOT NULL, id text NOT NULL, hash text NOT NULL, label text, created_by text NOT NULL, created_at bigint NOT NULL, revoked_at bigint,
       PRIMARY KEY (repo, id))`,
  ];
}

const num = (v: unknown) => (v === null || v === undefined ? undefined : Number(v));

/**
 * Postgres (Neon) implementation of `Persist`. Same semantics as the memory adapter: repo names are case-insensitive,
 * bucket writes are additive upserts (errors/requests summed, p95 = max, newest `top` wins) and buckets older than
 * RETENTION_MS are dropped on write.
 */
export function pgPersist(sql: Sql, schema = "twin"): Persist {
  const t = (name: string) => `${schema}.${name}`;
  let ready: Promise<void> | undefined;
  // the HTTP driver takes one statement per request: the schema first, then the tables side by side
  const init = () => (ready ??= (async () => {
    const [mk, ...tables] = ddl(schema);
    await sql(mk);
    await Promise.all(tables.map((stmt) => sql(stmt)));
  })().catch((e) => { ready = undefined; throw e; }));
  const k = (repo: string) => repo.toLowerCase();

  return {
    async getFindings(repo) {
      await init();
      const r = await sql(`SELECT data FROM ${t("findings")} WHERE repo = $1`, [k(repo)]);
      return (r[0]?.data as FindingSet | undefined) ?? null;
    },
    async putFindings(repo, set) {
      await init();
      await sql(`INSERT INTO ${t("findings")} (repo, data) VALUES ($1, $2::jsonb) ON CONFLICT (repo) DO UPDATE SET data = EXCLUDED.data`, [k(repo), JSON.stringify(set)]);
    },
    async getOverrides(repo) {
      await init();
      const r = await sql(`SELECT overrides FROM ${t("overrides")} WHERE repo = $1`, [k(repo)]);
      return (r[0]?.overrides as Overrides | undefined) ?? {};
    },
    async putOverrides(repo, o) {
      await init();
      await sql(`INSERT INTO ${t("overrides")} (repo, overrides) VALUES ($1, $2::jsonb) ON CONFLICT (repo) DO UPDATE SET overrides = EXCLUDED.overrides`, [k(repo), JSON.stringify(o)]);
    },
    async listShares(repo) {
      await init();
      const r = await sql(`SELECT id, hash, label, created_by, created_at, revoked_at FROM ${t("shares")} WHERE repo = $1 ORDER BY created_at`, [k(repo)]);
      return r.map((x): Share => ({
        id: String(x.id), hash: String(x.hash), createdBy: String(x.created_by), createdAt: Number(x.created_at),
        ...(x.label ? { label: String(x.label) } : {}), ...(x.revoked_at ? { revokedAt: Number(x.revoked_at) } : {}),
      }));
    },
    async addShare(repo, s) {
      await init();
      await sql(`INSERT INTO ${t("shares")} (repo, id, hash, label, created_by, created_at) VALUES ($1, $2, $3, $4, $5, $6)`, [k(repo), s.id, s.hash, s.label ?? null, s.createdBy, s.createdAt]);
    },
    async revokeShare(repo, id, at) {
      await init();
      const r = await sql(`UPDATE ${t("shares")} SET revoked_at = $3 WHERE repo = $1 AND id = $2 AND revoked_at IS NULL RETURNING id`, [k(repo), id, at]);
      return r.length > 0;
    },
    async getMappings(repo) {
      await init();
      const r = await sql(`SELECT mappings FROM ${t("mappings")} WHERE repo = $1`, [k(repo)]);
      return (r[0]?.mappings as Record<string, string> | undefined) ?? {};
    },
    async putMappings(repo, m) {
      await init();
      await sql(`INSERT INTO ${t("mappings")} (repo, mappings) VALUES ($1, $2::jsonb)
                 ON CONFLICT (repo) DO UPDATE SET mappings = EXCLUDED.mappings`, [k(repo), JSON.stringify(m)]);
    },
    async putBuckets(repo, incoming) {
      await init();
      const now = Date.now();
      // collapse duplicates inside the batch first: one INSERT cannot upsert the same row twice
      const rows = mergeBuckets([], incoming, now).map((b) => ({ source: b.source, key: b.key, ts: b.ts, errors: b.errors ?? null, requests: b.requests ?? null, p95_ms: b.p95Ms ?? null, top: b.top ?? null }));
      if (rows.length) {
        await sql(
          `INSERT INTO ${t("buckets")} (repo, source, key, ts, errors, requests, p95_ms, top)
           SELECT $1, r.source, r.key, r.ts, r.errors, r.requests, r.p95_ms, r.top
           FROM jsonb_to_recordset($2::jsonb) AS r(source text, key text, ts bigint, errors double precision, requests double precision, p95_ms double precision, top jsonb)
           ON CONFLICT (repo, source, key, ts) DO UPDATE SET
             errors   = CASE WHEN ${t("buckets")}.errors IS NULL AND EXCLUDED.errors IS NULL THEN NULL ELSE COALESCE(${t("buckets")}.errors, 0) + COALESCE(EXCLUDED.errors, 0) END,
             requests = CASE WHEN ${t("buckets")}.requests IS NULL AND EXCLUDED.requests IS NULL THEN NULL ELSE COALESCE(${t("buckets")}.requests, 0) + COALESCE(EXCLUDED.requests, 0) END,
             p95_ms   = GREATEST(${t("buckets")}.p95_ms, EXCLUDED.p95_ms),
             top      = COALESCE(EXCLUDED.top, ${t("buckets")}.top)`,
          [k(repo), JSON.stringify(rows)],
        );
      }
      await sql(`DELETE FROM ${t("buckets")} WHERE repo = $1 AND ts < $2`, [k(repo), now - RETENTION_MS]);
    },
    async getBuckets(repo, since) {
      await init();
      const r = await sql(`SELECT source, key, ts, errors, requests, p95_ms, top FROM ${t("buckets")} WHERE repo = $1 AND ts >= $2 ORDER BY ts`, [k(repo), since]);
      return r.map((x): RuntimeBucket => {
        const b: RuntimeBucket = { source: String(x.source), key: String(x.key), ts: Number(x.ts) };
        const errors = num(x.errors), requests = num(x.requests), p95Ms = num(x.p95_ms);
        if (errors !== undefined) b.errors = errors;
        if (requests !== undefined) b.requests = requests;
        if (p95Ms !== undefined) b.p95Ms = p95Ms;
        if (x.top) b.top = x.top as RuntimeBucket["top"];
        return b;
      });
    },
    async putSnapshot(repo, s) {
      if (!SAFE_SHA.test(s.sha)) throw new Error("invalid sha");
      await init();
      await sql(`INSERT INTO ${t("snapshots")} (repo, sha, committed_at, created_at, graph) VALUES ($1, $2, $3, $4, $5::jsonb)
                 ON CONFLICT (repo, sha) DO UPDATE SET committed_at = EXCLUDED.committed_at, created_at = EXCLUDED.created_at, graph = EXCLUDED.graph`,
        [k(repo), s.sha, s.committedAt ?? null, s.createdAt, JSON.stringify(s.graph)]);
    },
    async listSnapshots(repo): Promise<SnapshotMeta[]> {
      await init();
      const r = await sql(`SELECT sha, committed_at, created_at FROM ${t("snapshots")} WHERE repo = $1 ORDER BY created_at`, [k(repo)]);
      return r.map((x) => ({ sha: String(x.sha), ...(x.committed_at ? { committedAt: String(x.committed_at) } : {}), createdAt: Number(x.created_at) }));
    },
    async getSnapshot(repo, sha): Promise<Snapshot | null> {
      if (!SAFE_SHA.test(sha)) return null;
      await init();
      const r = await sql(`SELECT sha, committed_at, created_at, graph FROM ${t("snapshots")} WHERE repo = $1 AND sha = $2`, [k(repo), sha]);
      const x = r[0];
      return x ? { sha: String(x.sha), ...(x.committed_at ? { committedAt: String(x.committed_at) } : {}), createdAt: Number(x.created_at), graph: x.graph as Snapshot["graph"] } : null;
    },
  };
}
