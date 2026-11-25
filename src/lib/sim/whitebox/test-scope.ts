// Test helper: ask the real guard about one action under a ROE, with a fresh run state. Not imported by production code.
import { allow } from "../scope";

export const scope = (action: unknown, roe: unknown, now: number) =>
  allow(action, roe, now, { startedAt: now - 1000, stepsUsed: 0, tokensUsed: 0, costUsd: 0, killed: false, ownershipProvedAt: {} });
