import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import type { LlmNarrative } from "./schema";

export interface NarrativeCache {
  get(key: string): Promise<LlmNarrative | null>;
  set(key: string, value: LlmNarrative): Promise<void>;
}

export const cacheKey = (parts: unknown) => createHash("sha256").update(JSON.stringify(parts)).digest("hex");

/** Dev/self-host cache on disk. Production swaps this for Blob or the database (same interface). */
export function fileCache(dir = path.join(process.cwd(), ".cache", "narrative")): NarrativeCache {
  return {
    async get(key) {
      try { return JSON.parse(await readFile(path.join(dir, `${key}.json`), "utf8")) as LlmNarrative; } catch { return null; }
    },
    async set(key, value) {
      try { await mkdir(dir, { recursive: true }); await writeFile(path.join(dir, `${key}.json`), JSON.stringify(value)); } catch { /* cache is best-effort */ }
    },
  };
}
