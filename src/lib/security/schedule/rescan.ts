import { persist } from "@/lib/persist";
import { tokenFor } from "@/lib/github/app";
import { checkDomainAndStore } from "../passive/check-domain";
import { getTransport } from "../passive/transport";
import { scanAndStore } from "../run-scan";
import type { Schedule } from "../types";

const HOUR = 3_600_000;
/** a little under the nominal period, so a cron that fires at the same time each day does not skip a day by a few seconds of drift */
const PERIOD_MS: Record<Schedule["cadence"], number> = { daily: 23 * HOUR, weekly: 6 * 24 * HOUR + 23 * HOUR };
/** one cron run never starts more than this many scans, and stops starting new ones when time is short */
export const MAX_PER_RUN = 5;
const MIN_REMAINING_MS = 100_000;

export const isDue = (s: Schedule, now: number): boolean => !s.lastRunAt || now - s.lastRunAt >= PERIOD_MS[s.cadence];

export interface RescanDeps {
  scan: (repo: string, token: string | undefined) => Promise<unknown>;
  token: (repo: string) => Promise<string | undefined>;
  checkDomain: (repo: string, domain: string) => ReturnType<typeof checkDomainAndStore>;
  now: () => number;
}
const realDeps: RescanDeps = {
  scan: (repo, token) => scanAndStore(repo, token),
  token: (repo) => tokenFor(repo),
  checkDomain: (repo, domain) => checkDomainAndStore(repo, domain, getTransport()),
  now: Date.now,
};

export interface RescanReport { due: number; ran: { repo: string; ok: boolean; message?: string; domains: number }[]; skipped: number }

const brief = (e: unknown) => (e instanceof Error ? e.message : "The scan failed.").replace(/\s+/g, " ").slice(0, 200);

/**
 * Re-scans every repo whose schedule is due, oldest first, then re-checks its verified domains. One repo failing never stops the
 * others, and the result is written back so the page can say when it last ran and whether it worked. `deadline` is an epoch ms
 * after which no new repo is started.
 */
export async function runDueRescans(deadline: number, deps: RescanDeps = realDeps): Promise<RescanReport> {
  const store = persist();
  const all = await store.listSchedules();
  const due = all.filter((x) => isDue(x.schedule, deps.now())).sort((a, b) => (a.schedule.lastRunAt ?? 0) - (b.schedule.lastRunAt ?? 0));
  const report: RescanReport = { due: due.length, ran: [], skipped: 0 };

  for (const { repo } of due) {
    if (report.ran.length >= MAX_PER_RUN || deps.now() > deadline - MIN_REMAINING_MS) { report.skipped++; continue; }
    let ok = true, message: string | undefined, domains = 0;
    try {
      await deps.scan(repo, await deps.token(repo));
      for (const d of (await store.getDomains(repo)).filter((x) => x.verifiedAt)) {
        const r = await deps.checkDomain(repo, d.domain);
        domains++;
        if (!r.ok) message = `${d.domain}: ${r.error}`.slice(0, 200);
      }
    } catch (e) { ok = false; message = brief(e); }
    // the schedule may have been changed or removed while we worked: write onto the latest copy, and never bring a deleted one back
    const latest = await store.getSchedule(repo);
    if (latest) await store.putSchedule(repo, { ...latest, lastRunAt: deps.now(), lastStatus: ok ? "ok" : "failed", lastMessage: message });
    report.ran.push({ repo, ok, ...(message ? { message } : {}), domains });
  }
  return report;
}
