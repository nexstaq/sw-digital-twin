import { PAYLOAD_CLASSES } from "../range/types";
import { sha256Hex } from "../range/sha256";

/**
 * The rules of engagement for a reachability run against the range. Range-only, so no approval is needed. The agent starts with
 * only the public surface (it calls as `anonymous` only; see `ROLES_FOR.redteam`) and asks one question: from here, with no
 * credentials, can the crown jewels (the data stores a map's `crown` markers protect) be reached at all, and how likely is that?
 * It is a reachability check, not a staged attack: every step is a bounded, logged call through the normal guarded path, and a
 * "success" is a harmless marker, never a working exploit against real software.
 */

export const RT = {
  /** exploiting a public-facing route with a hostile payload or an open write */
  web: "T1190",
  /** a pipeline an outsider can trigger (a pull request), used to see what the software it deploys could in turn reach */
  supplyChain: "T1195",
} as const;

export interface RedteamRoe {
  version: 1; runId: string; repo: string;
  targets: { kind: "range"; rangeId: string }[];
  agents: ["redteam"];
  allowedClasses: ("observe" | "probe" | "exploit-range")[];
  allowedTechniques: string[]; forbiddenTechniques: string[];
  window: { notBefore: number; notAfter: number };
  budgets: { steps: number; tokens: number; wallMs: number; costUsd: number };
  killSwitchId: string;
}

export function redteamRoe(o: { repo: string; rangeId: string; now: number; routes: number; workflows: number }): RedteamRoe {
  const runId = `rt_${sha256Hex(`${o.repo}|${o.rangeId}|${o.now}`).slice(0, 12)}`;
  return {
    version: 1, runId, repo: o.repo,
    targets: [{ kind: "range", rangeId: o.rangeId }],
    agents: ["redteam"],
    allowedClasses: ["observe", "probe", "exploit-range"],
    allowedTechniques: Object.values(RT), forbiddenTechniques: [],
    window: { notBefore: o.now - 60_000, notAfter: o.now + 30 * 60_000 },
    // one baseline probe plus every payload class per route; one trigger attempt per candidate workflow, plus a handful of follow-up traces
    budgets: { steps: Math.min(500, 4 + o.routes * (PAYLOAD_CLASSES.length + 1) + o.workflows * 8), tokens: 1000, wallMs: 10 * 60_000, costUsd: 1 },
    killSwitchId: `kill_${runId}`,
  };
}
