import type { Alerts } from "./github-alerts";
import { byPriority } from "./map";
import type { FindingSet } from "./types";

const isImport = (source: string | undefined) => !!source && source.startsWith("sarif:");

/**
 * A fresh scan only re-runs OUR analyzers, so it must not lose what other tools told us. This keeps the reports CI or a person
 * imported (until the same tool sends a newer one), adds GitHub's alerts as just fetched, and marks our own findings that GitHub
 * independently confirmed. Pure.
 */
export function combine(fresh: FindingSet, prev: FindingSet | null, alerts: Alerts | null): FindingSet {
  const carried = prev?.findings.filter((f) => isImport(f.detail.source)) ?? [];
  const confirmed = alerts?.confirmed ?? new Map<string, string[]>();
  const own = fresh.findings.map((f) => (confirmed.has(f.id) ? { ...f, detail: { ...f.detail, alsoReportedBy: [...new Set([...(f.detail.alsoReportedBy ?? []), ...confirmed.get(f.id)!])] } } : f));

  const sources: NonNullable<FindingSet["sources"]> = { ...alerts?.sources };
  for (const [k, v] of Object.entries(prev?.sources ?? {})) if (isImport(k)) sources[k] = v;

  const ids = new Set(own.map((f) => f.id));
  const extra = [...(alerts?.findings ?? []), ...carried].filter((f) => !ids.has(f.id) && !!ids.add(f.id));
  return { ...fresh, findings: [...own, ...extra].sort(byPriority), ...(Object.keys(sources).length ? { sources } : {}) };
}
