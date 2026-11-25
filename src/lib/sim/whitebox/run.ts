import { persist } from "@/lib/persist";
import type { Persist } from "@/lib/persist/types";
import { fetchExcerpt } from "@/lib/security/excerpt";
import type { Finding, FindingSet } from "@/lib/security/types";
import { applySimulations, verifyFindings } from "./agent";
import { proposePatch, validateDiff, type Excerpt } from "./source";

/**
 * "Verify by simulation" for one repository: loads the saved map and the latest scan, runs the white-box agent, stores the verdicts
 * on the findings, and returns the result. The caller has already checked that the person may do this (push access).
 * Shared by the route and tests, like `scanAndStore`.
 */

export type SimulateOutcome = { ok: true; set: FindingSet } | { ok: false; status: 409 | 500; error: string };

export interface SimDeps { store?: Pick<Persist, "getFindings" | "putFindings" | "listSnapshots" | "getSnapshot">; excerpt?: typeof fetchExcerpt; now?: () => number }

export async function simulateAndStore(repo: string, token: string | undefined, o: { source: boolean; signal?: AbortSignal; deps?: SimDeps }): Promise<SimulateOutcome> {
  const store = o.deps?.store ?? persist();
  const read = o.deps?.excerpt ?? fetchExcerpt;
  const now = o.deps?.now ?? Date.now;
  const set = await store.getFindings(repo);
  if (!set) return { ok: false, status: 409, error: "Run a security scan first, then verify it by simulation." };
  const latest = (await store.listSnapshots(repo)).at(-1);
  const snap = latest ? await store.getSnapshot(repo, latest.sha) : null;
  if (!snap) return { ok: false, status: 409, error: "Map the repository first: the simulation is built from its map." };

  const excerpt = o.source ? (f: Finding) => read(repo, set.sha, f.path, f.line, token, { signal: o.signal }) : undefined;
  const r = await verifyFindings({ repo, sha: set.sha, graph: snap.graph, set, excerpt, now });
  const notes = snap.sha !== set.sha ? ["The map and the security scan are from different commits, so some paths may not line up.", ...r.notes] : r.notes;
  const merged = applySimulations(set, { ...r, notes }, { sourceRead: o.source, at: now() });
  await store.putFindings(repo, merged);
  return { ok: true, set: merged };
}

export type PatchOutcome = { ok: true; diff: string; kind: string; retest: string } | { ok: false; status: 404 | 409; error: string };

/**
 * The proposed diff for one finding, made again now from the file as it is at the scanned commit. A diff contains source, so it is never
 * stored: it exists for this response only. Only available if the last simulation was allowed to read source.
 */
export async function patchFor(repo: string, findingId: string, token: string | undefined, o: { signal?: AbortSignal; deps?: SimDeps } = {}): Promise<PatchOutcome> {
  const store = o.deps?.store ?? persist();
  const read = o.deps?.excerpt ?? fetchExcerpt;
  const set = await store.getFindings(repo);
  const f = set?.findings.find((x) => x.id === findingId);
  if (!set || !f) return { ok: false, status: 404, error: "No such finding." };
  if (!set.simulated?.sourceRead) return { ok: false, status: 409, error: "Patches need the simulation to have been allowed to read source. Run it again with that switched on." };
  if (!f.simulation?.patch) return { ok: false, status: 404, error: "No patch was proposed for this finding." };
  const x: Excerpt | null = await read(repo, set.sha, f.path, f.line, token, { signal: o.signal });
  if (!x || !f.line) return { ok: false, status: 404, error: "Could not read that file at the scanned commit." };
  const p = proposePatch(f.ruleId, f.line, x);
  if (!p || !validateDiff(p.diff, f.path)) return { ok: false, status: 404, error: "The patch could not be made again from the current file." };
  return { ok: true, diff: p.diff, kind: p.kind, retest: f.simulation.patch.retest };
}
