import { filePersist } from "./file";
import { memoryPersist } from "./memory";
import { neonSql, pgPersist } from "./pg";
import type { Persist } from "./types";

const g = globalThis as unknown as { __twinPersist?: Persist };

/**
 * One persistence instance per server. Choice, in order:
 *  - TWIN_PERSIST=memory|file forces that adapter;
 *  - DATABASE_URL (Neon, provisioned through the Vercel Marketplace) => Postgres;
 *  - on Vercel without a database => memory (the filesystem is not durable there);
 *  - otherwise files in `.data/`.
 */
export function persist(): Persist {
  return (g.__twinPersist ??= choose());
}

function choose(): Persist {
  const forced = process.env.TWIN_PERSIST;
  if (forced === "memory") return memoryPersist();
  if (forced === "file") return filePersist();
  if (process.env.DATABASE_URL) return pgPersist(neonSql(process.env.DATABASE_URL));
  return process.env.VERCEL ? memoryPersist() : filePersist();
}
