import { createHmac, timingSafeEqual } from "node:crypto";

/** Constant-time check of GitHub's `X-Hub-Signature-256` header against the raw request body. */
export function verifySignature(secret: string, rawBody: string, header: string | null): boolean {
  if (!secret || !header?.startsWith("sha256=")) return false;
  const want = Buffer.from(createHmac("sha256", secret).update(rawBody).digest("hex"), "hex");
  const got = Buffer.from(header.slice(7), "hex");
  return got.length === want.length && timingSafeEqual(got, want);
}

const HANDLED = new Set(["workflow_run", "workflow_job", "deployment", "deployment_status", "check_run", "check_suite", "push"]);

/** Which repo's health a delivery might have changed. Null for events we ignore. */
export function repoOfEvent(event: string | null, payload: unknown): string | null {
  if (!event || !HANDLED.has(event)) return null;
  const full = (payload as { repository?: { full_name?: unknown } } | null)?.repository?.full_name;
  return typeof full === "string" && /^[\w.-]+\/[\w.-]+$/.test(full) ? full.toLowerCase() : null;
}
