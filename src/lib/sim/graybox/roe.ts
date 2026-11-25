import { sha256Hex } from "../range/sha256";

/**
 * The rules of engagement for a gray-box run against the range. Range-only, so no approval is needed. It names four ATT&CK techniques, one
 * per family of test, so the audit log says which kind of thing each request was.
 */

export const T = {
  /** exploit a public-facing application: function-level and object-level authorisation, mass assignment, workflow abuse */
  access: "T1190",
  /** valid accounts: using the credentials the route is meant for, as the baseline */
  credentials: "T1078",
  /** brute force: repeated attempts against a sign-in route */
  bruteForce: "T1110",
  /** use alternate authentication material: an expired or planted session */
  session: "T1550",
} as const;

export interface GrayboxRoe {
  version: 1; runId: string; repo: string;
  targets: { kind: "range"; rangeId: string }[];
  agents: ["graybox"];
  allowedClasses: ("observe" | "probe" | "exploit-range")[];
  allowedTechniques: string[]; forbiddenTechniques: string[];
  window: { notBefore: number; notAfter: number };
  budgets: { steps: number; tokens: number; wallMs: number; costUsd: number };
  killSwitchId: string;
}

export function grayboxRoe(o: { repo: string; rangeId: string; now: number; routes: number }): GrayboxRoe {
  const runId = `gb_${sha256Hex(`${o.repo}|${o.rangeId}|${o.now}`).slice(0, 12)}`;
  return {
    version: 1, runId, repo: o.repo,
    targets: [{ kind: "range", rangeId: o.rangeId }],
    agents: ["graybox"],
    allowedClasses: ["observe", "probe", "exploit-range"],
    allowedTechniques: Object.values(T), forbiddenTechniques: [],
    window: { notBefore: o.now - 60_000, notAfter: o.now + 30 * 60_000 },
    // inspect once; per route at most ~9 requests (more on a sign-in route, which gets a burst of 12); plus the escalation check
    budgets: { steps: Math.min(500, 4 + 14 * o.routes), tokens: 1000, wallMs: 10 * 60_000, costUsd: 1 },
    killSwitchId: `kill_${runId}`,
  };
}
