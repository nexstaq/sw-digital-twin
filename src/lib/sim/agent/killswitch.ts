/**
 * The kill switch. Every run registers here when it starts and leaves when it ends. One call stops every run for a repository, or
 * the single run a kill-switch id names: new tool calls are refused at once (the run's guard sees `killed`), the model call is
 * aborted, the audit log records it, and everything the run started (a range, a sandbox) is torn down.
 *
 * Stopping does not depend on the model cooperating, and does not depend on aborting: the SDK keeps executing a tool call that is
 * already in a model reply after an abort (see smoke.test.ts), so the guard is what actually refuses it.
 */

export interface RunHandle {
  runId: string;
  repo: string;
  killSwitchId: string;
  /** stops this run and tears down what it started. Safe to call more than once. */
  kill(reason: string): Promise<void>;
}

export class KillRegistry {
  private runs = new Map<string, RunHandle>();

  register(h: RunHandle): () => void {
    this.runs.set(h.runId, h);
    return () => { this.runs.delete(h.runId); };
  }

  active(): RunHandle[] { return [...this.runs.values()]; }

  private async stop(match: (h: RunHandle) => boolean, reason: string): Promise<number> {
    const targets = this.active().filter(match);
    await Promise.allSettled(targets.map((h) => h.kill(reason))); // one run failing to tear down must not stop the others
    return targets.length;
  }

  /** every run for this repository, whoever started it */
  killRepo(repo: string, reason = "kill switch: repository"): Promise<number> { return this.stop((h) => h.repo.toLowerCase() === repo.toLowerCase(), reason); }
  /** the run(s) named by the ROE's kill-switch id */
  killSwitch(id: string, reason = "kill switch: id"): Promise<number> { return this.stop((h) => h.killSwitchId === id, reason); }
  killRun(runId: string, reason = "kill switch: run"): Promise<number> { return this.stop((h) => h.runId === runId, reason); }
}

const g = globalThis as { __simKillRegistry?: KillRegistry };
/** the one registry for this server process; tests make their own */
export const killRegistry = (): KillRegistry => (g.__simKillRegistry ??= new KillRegistry());
