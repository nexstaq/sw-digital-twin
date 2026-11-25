// Test fixtures shared by the sim tests. Not imported by production code.
import type { GuardState } from "./scope";

export const NOW = 1_800_000_000_000;
export const HOUR = 3_600_000;

export const rangeRoe = () => ({
  version: 1,
  runId: "run_0001",
  repo: "acme/shop",
  targets: [{ kind: "range", rangeId: "range_acme_shop_1" }],
  agents: ["whitebox", "graybox", "redteam", "blue", "narrator"],
  allowedClasses: ["observe", "probe", "exploit-range"],
  allowedTechniques: ["T1190", "T1078", "T1059.004"],
  forbiddenTechniques: ["T1486"],
  window: { notBefore: NOW - HOUR, notAfter: NOW + HOUR },
  budgets: { steps: 100, tokens: 500_000, wallMs: 30 * 60_000, costUsd: 5 },
  killSwitchId: "kill_0001",
});

export const domainRoe = () => ({
  ...rangeRoe(),
  targets: [{ kind: "verified-domain", domain: "shop.example.com" }],
  allowedClasses: ["observe", "probe"],
  agents: ["graybox"],
  approval: { approvedBy: "alice", approvedAt: NOW - 2 * HOUR },
});

export const ciRoe = () => ({
  ...domainRoe(),
  targets: [{ kind: "ci-runner", repo: "acme/shop", url: "https://staging.shop.example.com" }],
});

export const freshState = (over: Partial<GuardState> = {}): GuardState => ({
  startedAt: NOW - 60_000,
  stepsUsed: 0,
  tokensUsed: 0,
  costUsd: 0,
  killed: false,
  ownershipProvedAt: {},
  ...over,
});

export const rangeAction = (over: Record<string, unknown> = {}) => ({
  id: "act_1",
  agent: "redteam",
  tool: "http.request",
  class: "exploit-range",
  technique: "T1190",
  target: { kind: "range", rangeId: "range_acme_shop_1" },
  ...over,
});

export const domainAction = (url: string, over: Record<string, unknown> = {}) => ({
  id: "act_2",
  agent: "graybox",
  tool: "http.request",
  class: "probe",
  technique: "T1190",
  target: { kind: "verified-domain", url },
  ...over,
});
