import { mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import type { Overrides } from "@/lib/graph/overrides";
import type { RuntimeBucket } from "@/lib/health/signals";
import type { FindingSet } from "@/lib/security/types";
import type { Share } from "@/lib/share/token";
import { mergeBuckets } from "./memory";
import type { Persist, Snapshot, SnapshotMeta } from "./types";

const SAFE_SHA = /^[0-9a-f]{40}$/;

/** JSON files under `.data/<owner>__<repo>/`. For dev and self-hosting; not safe for several writers. */
export function filePersist(root = path.join(/*turbopackIgnore: true*/ process.cwd(), ".data")): Persist {
  const dir = (repo: string) => {
    if (!/^[\w.-]+\/[\w.-]+$/.test(repo) || repo.includes("..")) throw new Error("invalid repo");
    return path.join(/*turbopackIgnore: true*/ root, repo.toLowerCase().replace("/", "__"));
  };
  const readJson = async <T>(file: string, fallback: T): Promise<T> => { try { return JSON.parse(await readFile(file, "utf8")) as T; } catch { return fallback; } };
  const writeJson = async (file: string, value: unknown) => {
    await mkdir(path.dirname(/*turbopackIgnore: true*/ file), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    await writeFile(tmp, JSON.stringify(value));
    await rename(tmp, file); // readers never see a half-written file
  };
  const sharesFile = (repo: string) => path.join(/*turbopackIgnore: true*/ dir(repo), "shares.json");
  return {
    async getFindings(repo) { return readJson<FindingSet | null>(path.join(/*turbopackIgnore: true*/ dir(repo), "findings.json"), null); },
    async putFindings(repo, set) { await writeJson(path.join(/*turbopackIgnore: true*/ dir(repo), "findings.json"), set); },
    async getOverrides(repo) { return readJson<Overrides>(path.join(/*turbopackIgnore: true*/ dir(repo), "overrides.json"), {}); },
    async putOverrides(repo, o) { await writeJson(path.join(/*turbopackIgnore: true*/ dir(repo), "overrides.json"), o); },
    async listShares(repo) { return readJson<Share[]>(sharesFile(repo), []); },
    async addShare(repo, s) { await writeJson(sharesFile(repo), [...(await readJson<Share[]>(sharesFile(repo), [])), s]); },
    async revokeShare(repo, id, at) {
      const all = await readJson<Share[]>(sharesFile(repo), []);
      const s = all.find((x) => x.id === id && !x.revokedAt);
      if (!s) return false;
      s.revokedAt = at;
      await writeJson(sharesFile(repo), all);
      return true;
    },
    async getMappings(repo) { return readJson<Record<string, string>>(path.join(/*turbopackIgnore: true*/ dir(repo), "mappings.json"), {}); },
    async putMappings(repo, m) { await writeJson(path.join(/*turbopackIgnore: true*/ dir(repo), "mappings.json"), m); },
    async putBuckets(repo, b) {
      const f = path.join(/*turbopackIgnore: true*/ dir(repo), "buckets.json");
      await writeJson(f, mergeBuckets(await readJson<RuntimeBucket[]>(f, []), b));
    },
    async getBuckets(repo, since) { return (await readJson<RuntimeBucket[]>(path.join(/*turbopackIgnore: true*/ dir(repo), "buckets.json"), [])).filter((b) => b.ts >= since); },
    async putSnapshot(repo, s) {
      if (!SAFE_SHA.test(s.sha)) throw new Error("invalid sha");
      await writeJson(path.join(/*turbopackIgnore: true*/ dir(repo), "snapshots", `${s.sha}.json`), s);
    },
    async listSnapshots(repo) {
      const d = path.join(/*turbopackIgnore: true*/ dir(repo), "snapshots");
      let names: string[] = [];
      try { names = await readdir(d); } catch { return []; }
      const metas: SnapshotMeta[] = [];
      for (const n of names.filter((x) => x.endsWith(".json"))) {
        const s = await readJson<Snapshot | null>(path.join(/*turbopackIgnore: true*/ d, n), null);
        if (s) metas.push({ sha: s.sha, committedAt: s.committedAt, createdAt: s.createdAt });
      }
      return metas.sort((a, b) => a.createdAt - b.createdAt);
    },
    async getSnapshot(repo, sha) { return SAFE_SHA.test(sha) ? readJson<Snapshot | null>(path.join(/*turbopackIgnore: true*/ dir(repo), "snapshots", `${sha}.json`), null) : null; },
  };
}
