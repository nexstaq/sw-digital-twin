import { applyOverrides } from "@/lib/graph/overrides";
import { explainVerdict, type Verdict } from "@/lib/graph/verdict";
import { applyHealth } from "@/lib/health/engine";
import type { TwinGraph } from "@/lib/graph/types";
import { tokenFor } from "@/lib/github/app";
import { getSignals, isPublicRepo } from "@/lib/github/signals";
import type { SignalSet } from "@/lib/health/signals";
import { persist } from "@/lib/persist";
import { matchShare } from "./token";

export type SharedView =
  | { ok: true; repo: string; graph: TwinGraph; signals: SignalSet | null; warning?: string }
  | { ok: false; reason: "forbidden" | "unmapped" };

/** Last saved map (human corrections applied) plus live health, for a repo the caller is already allowed to see. */
export async function loadView(repo: string, o: { token?: string }): Promise<SharedView> {
  const store = persist();
  const latest = (await store.listSnapshots(repo)).at(-1);
  const snap = latest && (await store.getSnapshot(repo, latest.sha));
  if (!snap) return { ok: false, reason: "unmapped" };
  const graph = applyOverrides(snap.graph, await store.getOverrides(repo));
  try {
    return { ok: true, repo, graph, signals: await getSignals(repo, { token: o.token }) };
  } catch (e) {
    return { ok: true, repo, graph, signals: null, warning: e instanceof Error ? e.message : "Live health is unavailable right now." };
  }
}

/** The launch verdict (GO / HOLD / NO-GO / NO DATA) for a loaded view. */
export function viewVerdict(v: Extract<SharedView, { ok: true }>): Verdict {
  return explainVerdict(v.signals ? applyHealth(v.graph, v.signals, v.signals.fetchedAt) : v.graph);
}

/**
 * What an anonymous viewer may see of a repo. Public repo: anyone, unless `requireSecret`. Anything else: only with a live
 * share link's secret. A bad secret and a repo that does not exist look the same ("forbidden"), so a link cannot be used to
 * probe for repos.
 */
export async function openSharedView(repo: string, secret: string | undefined, o: { requireSecret?: boolean } = {}): Promise<SharedView> {
  let pub = false;
  try { pub = await isPublicRepo(repo); } catch { /* treat as not public */ }
  if (o.requireSecret || !pub) {
    if (!secret || !matchShare(await persist().listShares(repo), secret)) return { ok: false, reason: "forbidden" };
  }
  return loadView(repo, { token: await tokenFor(repo, { installationOnly: !pub }) });
}
