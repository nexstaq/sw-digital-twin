import { timingSafeEqual } from "node:crypto";

export const otlpConfigured = (env: NodeJS.ProcessEnv = process.env) => !!env.OTLP_INGEST_KEY;

/** Constant-time check of `Authorization: Bearer <OTLP_INGEST_KEY>`. */
export function otlpAuthorized(header: string | null, env: NodeJS.ProcessEnv = process.env): boolean {
  const key = env.OTLP_INGEST_KEY;
  if (!key || !header?.startsWith("Bearer ")) return false;
  const a = Buffer.from(header.slice(7)), b = Buffer.from(key);
  return a.length === b.length && timingSafeEqual(a, b);
}
