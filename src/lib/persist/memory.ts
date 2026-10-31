import type { Overrides } from "@/lib/graph/overrides";
import type { RuntimeBucket } from "@/lib/health/signals";
import type { DomainEntry, FindingSet } from "@/lib/security/types";
import type { Share } from "@/lib/share/token";
import { RETENTION_MS, type Persist, type Snapshot } from "./types";

/** Merge `incoming` into `existing` (same source+key+ts => summed rates, max latency, newest issue list). Also drops expired buckets. */
export function mergeBuckets(existing: RuntimeBucket[], incoming: RuntimeBucket[], now = Date.now()): RuntimeBucket[] {
  const map = new Map<string, RuntimeBucket>();
  const add = (b: RuntimeBucket, sum: boolean) => {
    if (b.ts < now - RETENTION_MS) return;
    const k = `${b.source}\u0000${b.key}\u0000${b.ts}`;
    const cur = map.get(k);
    if (!cur) return void map.set(k, { ...b });
    if (!sum) return void map.set(k, { ...b });
    map.set(k, {
      ...cur,
      errors: cur.errors === undefined && b.errors === undefined ? undefined : (cur.errors ?? 0) + (b.errors ?? 0),
      requests: cur.requests === undefined && b.requests === undefined ? undefined : (cur.requests ?? 0) + (b.requests ?? 0),
      p95Ms: cur.p95Ms === undefined ? b.p95Ms : b.p95Ms === undefined ? cur.p95Ms : Math.max(cur.p95Ms, b.p95Ms),
      top: b.top ?? cur.top,
    });
  };
  for (const b of existing) add(b, false);
  for (const b of incoming) add(b, true);
  return [...map.values()].sort((a, b) => a.ts - b.ts);
}

export function memoryPersist(): Persist {
  const buckets = new Map<string, RuntimeBucket[]>();
  const snaps = new Map<string, Map<string, Snapshot>>();
  const maps = new Map<string, Record<string, string>>();
  const ovr = new Map<string, Overrides>();
  const shares = new Map<string, Share[]>();
  const found = new Map<string, FindingSet>();
  const doms = new Map<string, DomainEntry[]>();
  const k = (r: string) => r.toLowerCase();
  return {
    async getDomains(repo) { return structuredClone(doms.get(k(repo)) ?? []); },
    async putDomains(repo, d) { doms.set(k(repo), structuredClone(d)); },
    async getFindings(repo) { return structuredClone(found.get(k(repo)) ?? null); },
    async putFindings(repo, set) { found.set(k(repo), structuredClone(set)); },
    async getOverrides(repo) { return structuredClone(ovr.get(k(repo)) ?? {}); },
    async putOverrides(repo, o) { ovr.set(k(repo), structuredClone(o)); },
    async listShares(repo) { return structuredClone(shares.get(k(repo)) ?? []); },
    async addShare(repo, s) { shares.set(k(repo), [...(shares.get(k(repo)) ?? []), structuredClone(s)]); },
    async revokeShare(repo, id, at) {
      const s = shares.get(k(repo))?.find((x) => x.id === id && !x.revokedAt);
      if (!s) return false;
      s.revokedAt = at;
      return true;
    },
    async getMappings(repo) { return { ...(maps.get(k(repo)) ?? {}) }; },
    async putMappings(repo, m) { maps.set(k(repo), { ...m }); },
    async putBuckets(repo, b) { buckets.set(k(repo), mergeBuckets(buckets.get(k(repo)) ?? [], b)); },
    async getBuckets(repo, since) { return (buckets.get(k(repo)) ?? []).filter((b) => b.ts >= since); },
    async putSnapshot(repo, s) { (snaps.get(k(repo)) ?? snaps.set(k(repo), new Map()).get(k(repo))!).set(s.sha, s); },
    async listSnapshots(repo) { return [...(snaps.get(k(repo))?.values() ?? [])].map((s) => ({ sha: s.sha, committedAt: s.committedAt, createdAt: s.createdAt })).sort((a, b) => a.createdAt - b.createdAt); },
    async getSnapshot(repo, sha) { return snaps.get(k(repo))?.get(sha) ?? null; },
  };
}
