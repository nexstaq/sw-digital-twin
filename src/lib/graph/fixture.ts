import { rollup } from "./rollup";
import { ruleStory } from "@/lib/narrate/rules";
import type { Narrative, NodeKind, Status, TwinEdge, TwinGraph, TwinNode } from "./types";

function rng(seed: number) {
  let s = seed;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 4294967296);
}

type Shape = "flat" | "up" | "spike" | "none";
function spark(seed: number, shape: Shape): number[] {
  const r = rng(seed);
  return Array.from({ length: 24 }, (_, i) => {
    const t = i / 23;
    const noise = r() * 0.08;
    if (shape === "up") return Math.min(1, 0.1 + t * 0.75 + noise);
    if (shape === "spike") return Math.min(1, 0.12 + noise + (i > 16 ? 0.35 + r() * 0.25 : 0));
    if (shape === "none") return 0.5;
    return 0.06 + noise;
  });
}

const SCORE: Record<Status, number> = { nominal: 0.96, degraded: 0.68, failing: 0.18, unknown: 0.5 };
let seedCounter = 1;

function n(
  id: string, level: 0 | 1 | 2, parentId: string | undefined, kind: NodeKind,
  label: string, summary: string, state: Status, evidencePath: string,
  reasons: string[] = [], owners?: string[],
): TwinNode {
  const shape: Shape =
    state === "failing" ? "up" : state === "degraded" ? "spike" : state === "unknown" ? "none" : "flat";
  const seed = seedCounter++ * 7919;
  return {
    id, level, parentId, kind, label, summary, state,
    score: SCORE[state] + (rng(seed)() - 0.5) * 0.06,
    spark: spark(seed, shape), reasons,
    evidence: [{ path: evidencePath }], owners, criticality: 2,
  };
}

let edgeCounter = 0;
function e(
  from: string, to: string, kind: TwinEdge["kind"],
  throughput = 0.5, errorRate = 0,
): TwinEdge {
  return { id: `e${edgeCounter++}`, from, to, kind, throughput, errorRate };
}

const leaves: TwinNode[] = [
  // ---- L0: system ----
  n("ci", 0, undefined, "job", "CI Pipeline", "Lints, tests and builds every pull request.", "nominal", ".github/workflows/ci.yml", [], ["@platform"]),
  n("release", 0, undefined, "job", "Release & Deploy", "Promotes builds from staging to production behind an approval gate.", "nominal", ".github/workflows/release.yml", [], ["@platform"]),
  n("web", 0, undefined, "service", "Web Storefront", "Customer-facing Next.js site served via CDN.", "nominal", "apps/web", [], ["@growth"]),
  n("api", 0, undefined, "service", "API Gateway", "Single GraphQL entry point with auth and rate limiting.", "nominal", "apps/api", [], ["@core"]),
  n("pay", 0, undefined, "service", "Payments", "Charges cards, handles Stripe webhooks and fraud checks.", "nominal", "services/payments", [], ["@payments"]),
  n("orders", 0, undefined, "service", "Orders & Fulfilment", "Order lifecycle and warehouse hand-off.", "nominal", "services/orders", [], ["@commerce"]),
  n("data", 0, undefined, "datastore", "Data Stores", "Primary database, cache and object storage.", "nominal", "infra/terraform/data.tf", [], ["@platform"]),
  n("ext", 0, undefined, "external", "External Services", "Third-party SaaS the system depends on.", "unknown", "package.json"),

  // ---- L1: CI ----
  n("wf-lint", 1, "ci", "job", "Lint & Typecheck", "ESLint and tsc across all packages.", "nominal", ".github/workflows/ci.yml:12-30"),
  n("wf-unit", 1, "ci", "job", "Unit Tests", "Vitest, 2,340 tests.", "nominal", ".github/workflows/ci.yml:32-55"),
  n("wf-e2e", 1, "ci", "job", "E2E (Playwright)", "Browser tests against a preview deploy.", "degraded", ".github/workflows/ci.yml:57-90",
    ["14% of runs failed and passed on retry this week (flaky)", "Median duration up 38%"]),
  n("wf-build", 1, "ci", "job", "Build Image", "Docker build and push to registry.", "nominal", ".github/workflows/ci.yml:92-120"),

  // ---- L1: Release ----
  n("rel-stage", 1, "release", "env", "Staging", "Auto-deploys every merge to main.", "nominal", ".github/workflows/release.yml:8-24"),
  n("rel-gate", 1, "release", "job", "Approval Gate", "Manual approval by an on-call lead.", "nominal", ".github/workflows/release.yml:26-34"),
  n("rel-prod", 1, "release", "env", "Production", "Rolling deploy to prod.", "degraded", ".github/workflows/release.yml:36-70",
    ["1 rollback in the last 7 days", "Deploy #482 took 3x longer than median"]),
  n("rel-flags", 1, "release", "package", "Feature Flags", "Gradual rollout controls.", "nominal", "packages/flags"),

  // ---- L1: Web ----
  n("web-cdn", 1, "web", "external", "CDN Cache", "Edge caching for static and ISR pages.", "nominal", "vercel.json"),
  n("web-next", 1, "web", "service", "Next.js Storefront", "Server-rendered React app.", "nominal", "apps/web/next.config.ts"),
  n("web-search", 1, "web", "package", "Search UI", "Typeahead and results.", "nominal", "apps/web/src/search"),

  // ---- L1: API ----
  n("api-gw", 1, "api", "endpoint", "GraphQL Gateway", "Resolves queries across services.", "nominal", "apps/api/src/server.ts"),
  n("api-auth", 1, "api", "service", "Auth Service", "Sessions and JWT validation.", "nominal", "apps/api/src/auth"),
  n("api-rate", 1, "api", "service", "Rate Limiter", "Per-key throttling.", "nominal", "apps/api/src/rate-limit.ts"),

  // ---- L1: Payments ----
  n("pay-hook", 1, "pay", "endpoint", "Stripe Webhooks", "Receives payment events.", "failing", "services/payments/src/webhooks.ts",
    ["Signature verification failing since 09:12"]),
  n("pay-svc", 1, "pay", "service", "Payments Service", "Creates charges and refunds.", "failing", "services/payments/src/charge.ts",
    ["TimeoutError: 41 exceptions/min (was 0.3)", "Started after deploy #482"]),
  n("pay-fraud", 1, "pay", "service", "Fraud Scoring", "Risk model calls.", "degraded", "services/payments/src/fraud.ts",
    ["p95 latency 2.4s (SLO 800ms)"]),
  n("pay-retry", 1, "pay", "job", "Retry Worker", "Re-attempts failed charges.", "nominal", "services/payments/src/retry.ts"),

  // ---- L1: Orders ----
  n("ord-svc", 1, "orders", "service", "Orders Service", "Order state machine.", "nominal", "services/orders/src"),
  n("ord-q", 1, "orders", "queue", "Fulfilment Queue", "SQS queue feeding the warehouse.", "degraded", "services/orders/src/queue.ts",
    ["Backlog 4,180 messages and growing", "312 messages in dead-letter queue"]),
  n("ord-wh", 1, "orders", "service", "Warehouse Sync", "Pushes orders to the 3PL.", "nominal", "services/orders/src/warehouse.ts"),

  // ---- L1: Data ----
  n("db-pg", 1, "data", "datastore", "Postgres (primary)", "Orders, users, catalogue.", "nominal", "infra/terraform/rds.tf"),
  n("db-redis", 1, "data", "datastore", "Redis", "Sessions and rate-limit counters.", "nominal", "infra/terraform/redis.tf"),
  n("db-s3", 1, "data", "datastore", "Object Storage", "Product images and exports.", "nominal", "infra/terraform/s3.tf"),

  // ---- L1: External ----
  n("ext-stripe", 1, "ext", "external", "Stripe", "Card processing. No telemetry connected.", "unknown", "services/payments/package.json"),
  n("ext-mail", 1, "ext", "external", "SendGrid", "Transactional email. No telemetry connected.", "unknown", "services/orders/package.json"),
  n("ext-tax", 1, "ext", "external", "TaxJar", "Tax calculation. No telemetry connected.", "unknown", "services/orders/package.json"),

  // ---- L2: Payments Service ----
  n("f-charge", 2, "pay-svc", "file", "charge.ts", "createCharge() wraps Stripe with a 5s timeout.", "failing", "services/payments/src/charge.ts:44-88",
    ["TimeoutError at line 61, 41/min"], ["@maya"]),
  n("f-idem", 2, "pay-svc", "file", "idempotency.ts", "Idempotency-key store.", "nominal", "services/payments/src/idempotency.ts"),
  n("run-8812", 2, "pay-svc", "job", "Run #8812", "Integration test run for deploy #482.", "failing", ".github/workflows/ci.yml",
    ["3 of 12 integration tests failed: charge timeout"]),

  // ---- L2: Fulfilment Queue ----
  n("f-consumer", 2, "ord-q", "file", "consumer.ts", "Batch consumer, concurrency 4.", "degraded", "services/orders/src/consumer.ts:10-72",
    ["Processing rate 12/s vs. inflow 31/s"]),
  n("q-dlq", 2, "ord-q", "queue", "Dead-letter queue", "Messages that failed 5 times.", "degraded", "infra/terraform/sqs.tf",
    ["312 messages, oldest 6h"]),
];

// criticality: 3 = system would be down without it, 1 = nice to have
const CRITICALITY: Record<string, 1 | 3> = {
  "pay-svc": 3, "pay-hook": 3, "api-gw": 3, "db-pg": 3, "ord-svc": 3,
  "wf-lint": 1, "rel-flags": 1, "pay-retry": 1, "web-search": 1, "db-s3": 1,
};
const nodes = rollup(leaves.map((x) => (CRITICALITY[x.id] ? { ...x, criticality: CRITICALITY[x.id] } : x)));

const edges: TwinEdge[] = [
  // L0
  e("ci", "release", "triggers", 0.4), e("release", "web", "deploys_to", 0.3), e("release", "api", "deploys_to", 0.3),
  e("release", "pay", "deploys_to", 0.3), e("web", "api", "calls", 0.9), e("api", "pay", "calls", 0.6, 0.22),
  e("api", "orders", "calls", 0.7), e("pay", "data", "reads", 0.5), e("orders", "data", "reads", 0.6),
  e("pay", "ext", "calls", 0.5, 0.18), e("orders", "ext", "calls", 0.3),
  // CI
  e("wf-lint", "wf-build", "triggers", 0.4), e("wf-unit", "wf-build", "triggers", 0.4), e("wf-e2e", "wf-build", "triggers", 0.4, 0.1),
  // Release
  e("rel-stage", "rel-gate", "triggers", 0.3), e("rel-gate", "rel-prod", "triggers", 0.3), e("rel-flags", "rel-prod", "depends_on", 0.2),
  // Web
  e("web-cdn", "web-next", "calls", 0.8), e("web-next", "web-search", "calls", 0.5),
  // API
  e("api-gw", "api-auth", "calls", 0.8), e("api-gw", "api-rate", "calls", 0.8),
  // Payments
  e("pay-hook", "pay-svc", "calls", 0.5, 0.35), e("pay-svc", "pay-fraud", "calls", 0.5, 0.12), e("pay-svc", "pay-retry", "publishes", 0.4),
  // Orders
  e("ord-svc", "ord-q", "publishes", 0.9), e("ord-q", "ord-wh", "calls", 0.3),
  // L2
  e("f-charge", "f-idem", "calls", 0.5, 0.2), e("run-8812", "f-charge", "triggers", 0.2, 0.3),
  e("f-consumer", "q-dlq", "publishes", 0.3, 0.1),
];

// Hand-written sample of what the AI layer produces, so /demo shows personas and the tour without a model key.
const SAMPLE: Record<string, Omit<Narrative, "citations" | "confidence" | "order">> = {
  ci: { name: "Quality Checks", purpose: "Tests every change before it can ship.", exec: "Automatically checks every code change so mistakes are caught before customers see them.", engineer: "GitHub Actions: lint, unit tests, Playwright E2E, then a Docker image build.", security: "Runs untrusted PR code on hosted runners; no secrets are referenced in these jobs." },
  release: { name: "Release Pipeline", purpose: "Moves approved builds to production.", exec: "Gets approved changes live safely, with a person signing off before production.", engineer: "Staging auto-deploys from main; production waits on a manual approval gate and uses feature flags.", security: "Production deploys need a human approval, which limits the damage from a bad merge." },
  web: { name: "Customer Storefront", purpose: "The website shoppers use.", exec: "The online shop customers browse and buy from.", engineer: "Next.js app behind a CDN, with a search UI package.", security: "Public-facing; all data access goes through the API gateway." },
  api: { name: "Front Door", purpose: "Single entry point for all requests.", exec: "Every request from the website passes through here first, which keeps things consistent and protected.", engineer: "GraphQL gateway with a separate auth service and per-key rate limiting.", security: "The main public endpoint; authentication and throttling live here." },
  pay: { name: "Payments", purpose: "Takes and refunds payments.", exec: "Charges customers' cards. If this breaks, the business cannot take money.", engineer: "Charge service, Stripe webhook receiver, fraud scoring and a retry worker.", security: "Handles payment events from Stripe; webhook signature checks are critical." },
  orders: { name: "Order Fulfilment", purpose: "Turns purchases into shipments.", exec: "Takes paid orders and hands them to the warehouse to be packed and sent.", engineer: "Order state machine publishing to an SQS queue consumed by the warehouse sync.", security: "Dead-letter queue holds failed orders; they contain customer addresses." },
  data: { name: "Databases & Storage", purpose: "Where information is kept.", exec: "Where customer, order and product information lives.", engineer: "Postgres primary, Redis for sessions and counters, object storage for images.", security: "Holds all customer data; access is defined in Terraform." },
  ext: { name: "Outside Partners", purpose: "Third parties the shop relies on.", exec: "Outside companies for card processing, email and tax calculations.", engineer: "Stripe, SendGrid and TaxJar via their SDKs.", security: "Three third parties receive customer data; none have monitoring connected here." },
};
nodes.forEach((n) => {
  const x = SAMPLE[n.id];
  if (x) n.narrative = { ...x, confidence: "high", citations: n.evidence.map((e) => e.path), order: Object.keys(SAMPLE).indexOf(n.id) };
});

export const fixtureGraph: TwinGraph = {
  repo: "acme/shop",
  nodes,
  edges,
  deploys: [
    { hoursAgo: 46, label: "#471", ok: true },
    { hoursAgo: 30, label: "#476", ok: true },
    { hoursAgo: 19, label: "#479", ok: true },
    { hoursAgo: 8, label: "#481 (rolled back)", ok: false },
    { hoursAgo: 0.4, label: "#482", ok: true },
  ],
};
fixtureGraph.story = { ...ruleStory(fixtureGraph), headline: "An online shop: code is checked, released, then served to customers, taking payments and shipping orders.", source: "ai", model: "sample" };

for (const p of nodes) {
  if (p.level < 2 && (p.state === "failing" || p.state === "degraded") && nodes.some((k) => k.parentId === p.id)) {
    p.spark = spark(p.id.length * 31, p.state === "failing" ? "up" : "spike");
  }
}

export const childrenOf = (g: TwinGraph, parentId: string | null) =>
  g.nodes.filter((x) => (x.parentId ?? null) === parentId);

export const nodeById = (g: TwinGraph, id: string) => g.nodes.find((x) => x.id === id);
