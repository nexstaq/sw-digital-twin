import type { TwinGraph } from "@/lib/graph/types";
import type { Overrides } from "@/lib/graph/overrides";
import type { RuntimeBucket } from "@/lib/health/signals";
import type { DomainEntry, FindingSet } from "@/lib/security/types";
import type { Share } from "@/lib/share/token";

export interface SnapshotMeta { sha: string; committedAt?: string; createdAt: number }
export interface Snapshot extends SnapshotMeta { graph: TwinGraph }

/**
 * Everything we keep. Deliberately small: compact rollups and graph structure, never raw telemetry or source.
 * Dev/self-host use the file or memory adapter; production swaps in Blob/Postgres behind this same interface.
 */
export interface Persist {
  /** merge by (source, key, ts); additive fields are summed so several OTLP batches can land in one bucket */
  putBuckets(repo: string, buckets: RuntimeBucket[]): Promise<void>;
  getBuckets(repo: string, sinceTs: number): Promise<RuntimeBucket[]>;
  putSnapshot(repo: string, snap: Snapshot): Promise<void>;
  listSnapshots(repo: string): Promise<SnapshotMeta[]>;
  getSnapshot(repo: string, sha: string): Promise<Snapshot | null>;
  /** confirmed signal -> node mappings, shared by everyone who can see the repo */
  getMappings(repo: string): Promise<Record<string, string>>;
  putMappings(repo: string, mappings: Record<string, string>): Promise<void>;
  /** human corrections to the map (rename, re-describe, hide); survive re-scans */
  getOverrides(repo: string): Promise<Overrides>;
  putOverrides(repo: string, overrides: Overrides): Promise<void>;
  /** the latest security scan: findings only (path, line, rule, reason), never source code or a secret's value */
  getFindings(repo: string): Promise<FindingSet | null>;
  putFindings(repo: string, set: FindingSet): Promise<void>;
  /** domains maintainers asked us to test, with their ownership proof (the token is public by design) */
  getDomains(repo: string): Promise<DomainEntry[]>;
  putDomains(repo: string, domains: DomainEntry[]): Promise<void>;
  /** read-only share links; only hashes are stored */
  listShares(repo: string): Promise<Share[]>;
  addShare(repo: string, share: Share): Promise<void>;
  /** false when there is no such live link */
  revokeShare(repo: string, id: string, at: number): Promise<boolean>;
}

export const RETENTION_MS = 7 * 24 * 3_600_000;
export const BUCKET_MS = 5 * 60_000;
