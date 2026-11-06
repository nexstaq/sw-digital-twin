import { persist } from "@/lib/persist";
import { byPriority } from "../map";
import { refreshTrend } from "../trend";
import { runPassiveChecks, verifyOwnership } from "./run";
import type { Transport } from "./transport";

export type DomainCheck =
  | { ok: true; findings: number; requests: number; notes: string[] }
  | { ok: false; status: 400 | 403 | 404 | 409; error: string; reasons?: string[] };

/**
 * Re-proves ownership of a registered domain, and only THEN runs the passive checks and stores what they found. Shared by the
 * "Check" button and the scheduled run, so the ownership rule cannot be skipped by either. If the proof fails the domain is
 * marked unverified and nothing is sent to it.
 */
export async function checkDomainAndStore(repo: string, domain: string, transport: Transport): Promise<DomainCheck> {
  const store = persist();
  const list = await store.getDomains(repo);
  const entry = list.find((d) => d.domain === domain);
  if (!entry) return { ok: false, status: 404, error: "Add that domain first." };

  const proof = await verifyOwnership(domain, entry.token, transport); // every run, not just the first
  if (!proof.ok) {
    await store.putDomains(repo, list.map((d) => (d.domain === domain ? { ...d, verifiedAt: undefined, verifiedVia: undefined } : d)));
    return { ok: false, status: 403, error: "Ownership of this domain could not be proven just now, so nothing was sent to it. Check the DNS record or file is still in place.", reasons: proof.reasons };
  }
  const set = await store.getFindings(repo);
  if (!set) return { ok: false, status: 409, error: "Run a security scan first, then run these checks." };

  const run = await runPassiveChecks(domain, transport);
  if (run.blocked) return { ok: false, status: 400, error: run.notes[0] ?? "That domain cannot be checked." };

  const key = `passive:${domain}`;
  const now = Date.now();
  const next = refreshTrend({
    ...set,
    findings: [...set.findings.filter((f) => f.detail.source !== key), ...run.findings].sort(byPriority),
    sources: { ...set.sources, [key]: { status: "ok", label: domain, count: run.findings.length, importedAt: now, via: "check", ...(run.notes.length ? { message: run.notes.join(" ") } : {}) } },
  });
  await store.putFindings(repo, next);
  // re-read: the list may have changed while the checks ran
  const fresh = await store.getDomains(repo);
  await store.putDomains(repo, fresh.map((d) => (d.domain === domain ? { ...d, verifiedAt: now, verifiedVia: proof.via, lastCheckAt: now, lastCheckCount: run.findings.length } : d)));
  return { ok: true, findings: run.findings.length, requests: run.requests, notes: run.notes };
}
