import { beforeEach, describe, expect, it, vi } from "vitest";
import { memoryPersist } from "@/lib/persist/memory";
import type { Schedule } from "../types";
import { isDue, MAX_PER_RUN, runDueRescans, type RescanDeps } from "./rescan";

const HOUR = 3_600_000;
const NOW = 1_800_000_000_000;
const sched = (o: Partial<Schedule> = {}): Schedule => ({ cadence: "daily", enabledBy: "ada", enabledAt: NOW - 100 * HOUR, ...o });

describe("isDue", () => {
  it("runs a schedule that never ran", () => expect(isDue(sched(), NOW)).toBe(true));
  it("waits about a day for daily, a week for weekly", () => {
    expect(isDue(sched({ lastRunAt: NOW - 10 * HOUR }), NOW)).toBe(false);
    expect(isDue(sched({ lastRunAt: NOW - 23 * HOUR }), NOW)).toBe(true);
    expect(isDue(sched({ cadence: "weekly", lastRunAt: NOW - 3 * 24 * HOUR }), NOW)).toBe(false);
    expect(isDue(sched({ cadence: "weekly", lastRunAt: NOW - 7 * 24 * HOUR }), NOW)).toBe(true);
  });
});

describe("runDueRescans", () => {
  const g = globalThis as unknown as { __twinPersist?: unknown };
  let deps: RescanDeps;
  beforeEach(() => {
    g.__twinPersist = memoryPersist();
    deps = {
      scan: vi.fn(async () => ({})), token: vi.fn(async () => "tok"), now: () => NOW,
      checkDomain: vi.fn(async () => ({ ok: true as const, findings: 0, requests: 1, notes: [] })),
    };
  });
  const store = () => g.__twinPersist as ReturnType<typeof memoryPersist>;

  it("scans only due repos, oldest first, and records the outcome", async () => {
    await store().putSchedule("a/new", sched());
    await store().putSchedule("a/fresh", sched({ lastRunAt: NOW - HOUR }));
    await store().putSchedule("a/old", sched({ lastRunAt: NOW - 50 * HOUR }));
    const r = await runDueRescans(NOW + 290_000, deps);
    expect(r.ran.map((x) => x.repo)).toEqual(["a/new", "a/old"]);
    expect(deps.scan).toHaveBeenCalledWith("a/new", "tok");
    expect((await store().getSchedule("a/old"))).toMatchObject({ lastRunAt: NOW, lastStatus: "ok" });
    expect((await store().getSchedule("a/fresh"))!.lastRunAt).toBe(NOW - HOUR);
  });

  it("one failing repo does not stop the others, and the failure is recorded", async () => {
    await store().putSchedule("a/bad", sched());
    await store().putSchedule("b/good", sched({ lastRunAt: NOW - 30 * HOUR }));
    deps.scan = vi.fn(async (repo: string) => { if (repo === "a/bad") throw new Error("clone failed"); return {}; });
    const r = await runDueRescans(NOW + 290_000, deps);
    expect(r.ran.map((x) => [x.repo, x.ok])).toEqual([["a/bad", false], ["b/good", true]]);
    expect(await store().getSchedule("a/bad")).toMatchObject({ lastStatus: "failed", lastMessage: "clone failed" });
  });

  it("re-checks only verified domains", async () => {
    await store().putSchedule("a/site", sched());
    await store().putDomains("a/site", [{ domain: "ok.example.com", token: "t", createdAt: 1, verifiedAt: 2 }, { domain: "new.example.com", token: "t", createdAt: 1 }]);
    const r = await runDueRescans(NOW + 290_000, deps);
    expect(deps.checkDomain).toHaveBeenCalledTimes(1);
    expect(deps.checkDomain).toHaveBeenCalledWith("a/site", "ok.example.com");
    expect(r.ran[0].domains).toBe(1);
  });

  it("caps work per run and stops when time is short", async () => {
    for (let i = 0; i < MAX_PER_RUN + 3; i++) await store().putSchedule(`a/r${i}`, sched());
    const r = await runDueRescans(NOW + 290_000, deps);
    expect(r.ran).toHaveLength(MAX_PER_RUN);
    expect(r.skipped).toBe(3);
    const late = await runDueRescans(NOW + 10_000, deps); // no time to start another
    expect(late.ran).toHaveLength(0);
  });

  it("does not resurrect a schedule that was switched off during the run", async () => {
    await store().putSchedule("a/gone", sched());
    deps.scan = vi.fn(async () => { await store().putSchedule("a/gone", null); return {}; });
    await runDueRescans(NOW + 290_000, deps);
    expect(await store().getSchedule("a/gone")).toBeNull();
  });
});
