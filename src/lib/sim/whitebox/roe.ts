import { sha256Hex } from "../range/sha256";

/**
 * The rules of engagement for a white-box run. It is range-only, so it needs no approval: nothing real is touched. The caller
 * (the route) has already checked that the person has push access. One technique (ATT&CK T1190, exploit a public-facing
 * application) covers every request the agent makes, no other class of action is allowed, and the budget is sized to the work.
 */

export const WHITEBOX_TECHNIQUE = "T1190";

export interface WhiteboxRoe {
  version: 1; runId: string; repo: string;
  targets: { kind: "range"; rangeId: string }[];
  agents: ["whitebox"];
  allowedClasses: ("observe" | "probe" | "exploit-range")[];
  allowedTechniques: string[]; forbiddenTechniques: string[];
  window: { notBefore: number; notAfter: number };
  budgets: { steps: number; tokens: number; wallMs: number; costUsd: number };
  killSwitchId: string;
}

export function whiteboxRoe(o: { repo: string; rangeId: string; now: number; findings: number }): WhiteboxRoe {
  const runId = `wb_${sha256Hex(`${o.repo}|${o.rangeId}|${o.now}`).slice(0, 12)}`;
  return {
    version: 1, runId, repo: o.repo,
    targets: [{ kind: "range", rangeId: o.rangeId }],
    agents: ["whitebox"],
    allowedClasses: ["observe", "probe", "exploit-range"],
    allowedTechniques: [WHITEBOX_TECHNIQUE], forbiddenTechniques: [],
    window: { notBefore: o.now - 60_000, notAfter: o.now + 30 * 60_000 },
    // inspect once; per finding: baseline, exploit, control, and (with a patch) a re-run of baseline and exploit
    budgets: { steps: Math.min(500, 2 + 6 * o.findings), tokens: 1000, wallMs: 10 * 60_000, costUsd: 1 },
    killSwitchId: `kill_${runId}`,
  };
}
