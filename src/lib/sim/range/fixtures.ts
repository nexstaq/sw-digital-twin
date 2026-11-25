// Test fixtures for the range. Not imported by production code.
import type { TwinGraph, TwinNode } from "@/lib/graph/types";
import { FindingSchema, type Finding, type FindingSet } from "@/lib/security/types";

export const SUMMARY_CANARY = "NODE-SUMMARY-CANARY-DO-NOT-COPY";
export const MASK_CANARY = "ghp_MASKEDHINT1234";

export const node = (id: string, level: 0 | 1 | 2, kind: TwinNode["kind"], label: string, parentId?: string, path?: string, lines = "1"): TwinNode => ({
  id, level, kind, label, summary: SUMMARY_CANARY, state: "unknown", score: 0.5, spark: [0.5, 0.5], reasons: [],
  evidence: [{ path: path ?? ".", ...(path ? { lines } : {}) }], criticality: 2, ...(parentId ? { parentId } : {}),
});
export const edge = (id: string, from: string, to: string, kind: TwinGraph["edges"][number]["kind"]) => ({ id, from, to, kind, throughput: 0.5, errorRate: 0 });

export const WF = "wf:.github/workflows/ci.yml";
export const JOB_TEST = "job:.github/workflows/ci.yml:test";
export const JOB_DEPLOY = "job:.github/workflows/ci.yml:deploy";

export const shopGraph = (): TwinGraph => ({
  repo: "acme/shop",
  deploys: [],
  nodes: [
    node("blk:backend", 0, "service", "Backend", undefined, "api/package.json"),
    node("svc:api", 1, "service", "API", "blk:backend", "api/package.json"),
    node("pkg:api", 1, "package", "api package", "blk:backend", "api/package.json"),
    node("grp:api", 2, "endpoint", "/api (4 routes)", "svc:api", "api/src/orders.ts"),
    node("route:api:GET:/api/orders", 2, "endpoint", "GET /api/orders", "grp:api", "api/src/orders.ts", "10"),
    node("route:api:POST:/api/orders", 2, "endpoint", "POST /api/orders", "grp:api", "api/src/orders.ts", "30"),
    node("route:api:GET:/api/orders/[id]", 2, "endpoint", "GET /api/orders/[id]", "grp:api", "api/src/order.ts"),
    node("route:api:POST:/api/admin/reset", 2, "endpoint", "POST /api/admin/reset", "grp:api", "api/src/admin.ts"),
    node("svc:payments", 1, "service", "Payments", "blk:backend", "payments/package.json"),
    node("db:main", 1, "datastore", "Main database", "blk:backend", "api/src/db.ts"),
    node("q:jobs", 1, "queue", "Job queue", "blk:backend", "api/src/queue.ts"),
    node("ext:stripe", 1, "external", "Stripe", "blk:backend", "payments/src/stripe.ts"),
    node(WF, 1, "job", "CI", undefined, ".github/workflows/ci.yml"),
    node(JOB_TEST, 2, "job", "test", WF, ".github/workflows/ci.yml", "8"),
    node(JOB_DEPLOY, 2, "job", "deploy", WF, ".github/workflows/ci.yml", "20"),
    node("env:production", 1, "env", "production environment", undefined, ".github/workflows/ci.yml", "20"),
  ],
  edges: [
    edge("e1", "svc:api", "svc:payments", "calls"),
    edge("e2", "svc:api", "db:main", "reads"),
    edge("e3", "svc:api", "q:jobs", "publishes"),
    edge("e4", "svc:payments", "ext:stripe", "calls"),
    edge("e5", JOB_TEST, JOB_DEPLOY, "triggers"),
    edge("e6", JOB_DEPLOY, "env:production", "deploys_to"),
    edge("e7", "pkg:api", "svc:api", "depends_on"),
  ],
});

export const finding = (id: string, ruleId: string, category: Finding["category"], path: string, over: Partial<Finding> = {}): Finding =>
  FindingSchema.parse({ id, ruleId, category, severity: "high", title: `t ${id}`, path, line: 5, reason: "REASON-TEXT-DO-NOT-COPY", fix: "fix", confidence: "high", ...over });

export const shopFindings = (): FindingSet => ({
  repo: "acme/shop", sha: "a".repeat(40), scannedAt: 1, stats: { files: 1, packages: 1, lockfiles: 1 }, warnings: [],
  findings: [
    finding("f1", "CODE/sql-injection", "code", "api/src/orders.ts"),
    finding("f2", "CODE/no-auth-seen", "code", "api/src/admin.ts", { severity: "low" }),
    finding("f3", "CODE/ssrf", "code", "api/src/order.ts"),
    finding("f4", "SCA/known-vulnerability", "dependency", "api/package.json"),
    finding("f5", "SECRET/key", "secret", "api/src/config.ts", { detail: { secretKind: "GitHub token", masked: MASK_CANARY } }),
    finding("f6", "GHA/pwn-request", "pipeline", ".github/workflows/ci.yml", { severity: "critical" }),
    finding("f7", "CODE/weak-hash", "code", "api/src/orders.ts", { severity: "low" }),
    finding("f8", "NUCLEI/exposed-panel", "runtime", "https://shop.example.com/admin"),
  ],
});

// ---- access-control fixtures ----

/** the shop, plus routes that exercise the access model: an admin read, a login, a user update and a checkout step */
export const accessGraph = (): TwinGraph => {
  const g = shopGraph();
  g.nodes.push(
    node("route:api:GET:/api/admin/stats", 2, "endpoint", "GET /api/admin/stats", "grp:api", "api/src/admin-stats.ts"),
    node("route:api:POST:/api/auth/login", 2, "endpoint", "POST /api/auth/login", "grp:api", "api/src/login.ts"),
    node("route:api:PATCH:/api/users/[id]", 2, "endpoint", "PATCH /api/users/[id]", "grp:api", "api/src/users.ts"),
    node("route:api:POST:/api/checkout/pay", 2, "endpoint", "POST /api/checkout/pay", "grp:api", "api/src/checkout.ts"),
  );
  return g;
};

/** an imported report's finding: no built-in rule id, but a CWE tag, which is how access-control weaknesses reach the range */
export const reported = (id: string, cwe: string, path: string, over: Partial<Finding> = {}): Finding =>
  finding(id, `sarif:semgrep:${id}`, "code", path, { cwe: [cwe], detail: { source: "sarif:semgrep" }, ...over });

export const accessFindings = (...fs: Finding[]): FindingSet => ({ ...shopFindings(), findings: fs });
