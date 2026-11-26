import type { TwinGraph } from "@/lib/graph/types";
import type { FindingSet } from "@/lib/security/types";
import { accessFindings, accessGraph, reported, shopFindings, shopGraph } from "../range/fixtures";

/**
 * Golden scenarios for the eval suite (X10): known inputs with a known right answer, so a regression in any of the four
 * checks behind "Verify by simulation" shows up as a wrong score, not just a passing test suite that happens not to
 * notice. Reuses the exact fixtures X4-X7's own tests already rely on, so the ground truth here is the same ground
 * truth those tests were written against, not a second, drifting copy of it.
 */
export interface GoldenCase {
  name: string;
  graph: TwinGraph;
  set: FindingSet;
  /** finding ids a correct run must confirm, from any of the three agents */
  shouldConfirm: ReadonlySet<string>;
  /** finding ids no check here can reach (a dependency, a secret, a weak hash with no modelled exercise, a live-test finding):
   *  a "confirmed" verdict on one of these would be a false positive, since nothing should have been able to produce one */
  shouldNotConfirm: ReadonlySet<string>;
}

const ACCESS = [
  reported("f_idor", "CWE-639", "api/src/order.ts"),
  reported("f_authz", "CWE-862", "api/src/admin-stats.ts"),
  reported("f_rate", "CWE-307", "api/src/login.ts"),
  reported("f_sess", "CWE-384", "api/src/users.ts"),
  reported("f_mass", "CWE-915", "api/src/users.ts"),
  reported("f_skip", "CWE-841", "api/src/checkout.ts"),
  reported("f_replay", "CWE-294", "api/src/checkout.ts"),
];

export const GOLDEN_CASES: GoldenCase[] = [
  {
    name: "shop: seeded code, pipeline and no-auth weaknesses",
    graph: shopGraph(), set: shopFindings(),
    shouldConfirm: new Set(["f1", "f2", "f3", "f6"]), // sql-injection, no-auth-seen, ssrf, pwn-request
    shouldNotConfirm: new Set(["f4", "f5", "f7", "f8"]), // a dependency, a secret, an unexercised weak hash, an already-imported live-test finding
  },
  {
    name: "access: seeded access-control weaknesses (imported report, as X5 finds them)",
    graph: accessGraph(), set: accessFindings(...ACCESS),
    shouldConfirm: new Set(ACCESS.map((f) => f.id)),
    shouldNotConfirm: new Set(),
  },
  {
    name: "clean: a map with nothing seeded at all",
    graph: shopGraph(), set: { ...shopFindings(), findings: [] },
    shouldConfirm: new Set(),
    shouldNotConfirm: new Set(),
  },
];
