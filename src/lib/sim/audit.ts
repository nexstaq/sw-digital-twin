import { createHash } from "node:crypto";
import { z } from "zod";
import { redactLine } from "@/lib/security/analyzers/secrets";
import { AGENTS } from "./roe";

/**
 * The audit log: an append-only, hash-chained record of everything a run decided and did. Each entry commits to the one before it,
 * so editing, deleting, inserting or reordering is detectable. A chain alone cannot show that the LAST entries were cut off, so the
 * head hash must be stored somewhere else (the run record) and passed as `expectedHead` when verifying.
 *
 * What is written is already safe to keep: summaries are redacted, whitespace-collapsed and cut to 300 characters, and a target
 * has its credentials, query string and fragment removed. Never put a response body or a secret value here.
 */

export const GENESIS = "0".repeat(64);
const MAX_SUMMARY = 300;
const MAX_FIELD = 200;

export const AUDIT_KINDS = ["roe", "decision", "tool-result", "finding", "approval", "kill", "note", "end"] as const;

const hex = z.string().regex(/^[0-9a-f]{64}$/);
const optText = z.string().max(MAX_FIELD).optional();
export const AuditEntrySchema = z.strictObject({
  seq: z.number().int().nonnegative(),
  ts: z.number().int().nonnegative(),
  runId: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
  agent: z.enum(["system", ...AGENTS]),
  kind: z.enum(AUDIT_KINDS),
  decision: z.enum(["allow", "deny"]).optional(),
  reason: optText,
  tool: optText,
  class: optText,
  technique: optText,
  target: optText,
  summary: z.string().max(MAX_SUMMARY),
  prevHash: hex,
  hash: hex,
});
export type AuditEntry = z.infer<typeof AuditEntrySchema>;
export type AuditInput = Omit<AuditEntry, "seq" | "prevHash" | "hash">;

const hashOf = (e: Omit<AuditEntry, "hash">) =>
  createHash("sha256")
    .update(JSON.stringify([e.seq, e.ts, e.runId, e.agent, e.kind, e.decision ?? null, e.reason ?? null, e.tool ?? null, e.class ?? null, e.technique ?? null, e.target ?? null, e.summary, e.prevHash]))
    .digest("hex");

const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n) : s);

/** Redact first, then cut, so a cut can never leave the front half of a key behind. */
export const cleanSummary = (s: string) => clip(redactLine(s.replace(/\s+/g, " ").trim()), MAX_SUMMARY);

function cleanTarget(t: string | undefined): string | undefined {
  if (t === undefined) return undefined;
  try {
    const u = new URL(t);
    u.username = ""; u.password = ""; u.search = ""; u.hash = "";
    return clip(redactLine(u.toString()), MAX_FIELD);
  } catch {
    return clip(redactLine(t), MAX_FIELD);
  }
}

export function appendEntry(prev: AuditEntry | undefined, input: AuditInput): AuditEntry {
  if (prev && prev.runId !== input.runId) throw new Error("audit: an entry must belong to the same run as the one before it");
  if (prev && input.ts < prev.ts) throw new Error("audit: time cannot go backwards");
  const body: Omit<AuditEntry, "hash"> = {
    ...input,
    target: cleanTarget(input.target),
    summary: cleanSummary(input.summary),
    seq: prev ? prev.seq + 1 : 0,
    prevHash: prev ? prev.hash : GENESIS,
  };
  const clean = Object.fromEntries(Object.entries(body).filter(([, v]) => v !== undefined)) as Omit<AuditEntry, "hash">;
  return { ...clean, hash: hashOf(clean) };
}

export type ChainResult = { ok: true; head: string } | { ok: false; index: number; why: string };

export function verifyChain(entries: readonly AuditEntry[], opts: { expectedHead?: string } = {}): ChainResult {
  if (!Array.isArray(entries)) return { ok: false, index: 0, why: "not a list" };
  let prevHash = GENESIS;
  for (let i = 0; i < entries.length; i++) {
    const parsed = AuditEntrySchema.safeParse(entries[i]);
    if (!parsed.success) return { ok: false, index: i, why: "entry is malformed" };
    const e = parsed.data;
    if (e.seq !== i) return { ok: false, index: i, why: "sequence number is out of order or an entry is missing" };
    if (e.prevHash !== prevHash) return { ok: false, index: i, why: i === 0 ? "the chain does not start at the beginning" : "does not link to the entry before it" };
    if (i > 0 && e.runId !== (entries[0] as AuditEntry).runId) return { ok: false, index: i, why: "entries from different runs are mixed" };
    if (i > 0 && e.ts < (entries[i - 1] as AuditEntry).ts) return { ok: false, index: i, why: "time goes backwards" };
    const { hash, ...rest } = e;
    if (hashOf(rest) !== hash) return { ok: false, index: i, why: "the entry was changed after it was written" };
    prevHash = hash;
  }
  if (opts.expectedHead !== undefined && opts.expectedHead !== prevHash) return { ok: false, index: entries.length, why: "the end of the log does not match the head that was recorded; entries may have been removed" };
  return { ok: true, head: prevHash };
}
