# Build Prompts (run in order in Claude Code, one per session/phase)

Paste `docs/PLAN.md` context first or tell Claude to read it. Each prompt is self-contained and ends with acceptance criteria.

---

## P0: Scaffold and control-room design system

```
Read docs/PLAN.md. Scaffold a Next.js (App Router, TypeScript, Tailwind, shadcn/ui) app named "twin".
Build a design system for a dark "launch control room" aesthetic: CSS tokens for surface/ink/status
(nominal, degraded, failing, unknown), each status paired with a distinct icon/shape for colorblind safety.
Create these components: StatusRing, NodeTile (icon, label, sparkline, status ring, glow/pulse),
AnimatedEdge (particles whose speed maps to throughput; red flicker on error), GoNoGoBanner,
LensSwitcher (Overview/Flow/Ops/Risk/Tour), TimelineScrubber, SideDrawer.
Build /demo rendering a hardcoded fixture graph (~40 nodes, 3 levels) with @xyflow/react + elkjs.
Respect prefers-reduced-motion. No tables.
Acceptance: /demo looks like a control room, 60fps pan/zoom, Lighthouse a11y >= 95, Storybook-style
/design page showing all components in all four statuses.
```

## P1: Canonical graph schema and semantic zoom

```
Implement the graph schema from docs/PLAN.md §5.2 as Zod schemas in packages/graph (Node, Edge, Health,
Snapshot), with versioning and JSON fixtures. Implement semantic zoom in the canvas: L0 shows 6-10
cluster nodes; zooming into or clicking a cluster animates it expanding into its L1 children (not mere
scaling), with a breadcrumb "mission path" and a back gesture. Health rolls up child to parent with
worst-of weighted by criticality. Add hover blast-radius highlighting (downstream dependents).
Acceptance: unit tests for rollup and blast radius; smooth expand/collapse; URL encodes zoom path so
views are shareable.
```

## P2: Ingestion: repo to raw graph

```
Create an ingestion pipeline (Vercel Workflow, steps are idempotent and retryable). Input: a GitHub repo
URL + ref. Steps: (1) shallow clone inside Vercel Sandbox, (2) run detectors: GitHub Actions workflows
-> job DAG; Dockerfile/compose/k8s/vercel.json/serverless/terraform -> services & infra;
package manifests/workspaces -> packages and internal deps; tree-sitter (WASM) -> entrypoints, HTTP
routes, import graph, queue pub/sub, DB clients, external SDKs; CODEOWNERS and git churn -> owners and
hotspots. (3) Emit a raw graph with evidence (path:lines) on every node/edge. Stream progress events
to the client over SSE so the UI animates the map building live during the scan.
Each detector is a separate module implementing `detect(ctx): Partial<Graph>` with fixture-based tests.
Acceptance: run on 3 public repos (a Next.js app, a Python/FastAPI+Docker service, a monorepo) and get a
sensible L1 map; every node has >= 1 evidence ref.
```

## P3: LLM clustering and plain-English layer

```
Using AI SDK via AI Gateway ("provider/model" strings), add a step that takes the raw graph (structured
JSON plus short per-file summaries, never the whole repo) and returns, via generateObject with a Zod
schema: logical clusters (L0), human names, one-line purposes, layout hints (left->right flow order),
and a per-persona description (exec / engineer / security). Validate that every claim cites evidence
IDs that exist; drop or flag the rest with a confidence badge. Cache by content hash. Add a
"metadata-only" mode that never sends source text. Build the Tour lens: an auto-playing narrated
walkthrough that pans/zooms through L0 nodes with captions.
Acceptance: L0 view of each test repo has 6-10 clusters with sensible names; zero hallucinated
evidence refs in tests; Tour plays end to end.
```

## P4: GitHub App, auth, private repos, health from Actions/Deployments

```
Add auth (Marketplace provider such as Clerk + GitHub login) and a GitHub App (read-only: contents,
metadata, actions, deployments, checks, code scanning alerts). Implement install flow, repo picker with
a magical "paste URL and go" path for public repos, webhook receiver (workflow_run, deployment_status,
check_run, push) that verifies signatures and enqueues to Vercel Queues. Build the Health Engine:
compute per-node state/score/reasons from CI pass rate & flakiness, deploy success/rollback rate,
change-failure rate, open alerts, staleness; map workflow jobs and deployments onto graph nodes;
roll up. Push updates to the browser via SSE so nodes pulse and change color live.
Acceptance: push a failing commit to a test repo and watch the corresponding job node turn red within
seconds, with "why" listing the failing step and linking the run.
```

## P5: Lenses, control-room chrome, command palette

```
Implement the five lenses as filters/emphasis on the same graph (Overview, Flow, Ops, Risk, Tour) with
persona-appropriate defaults and label language. Build the top bar GO/NO-GO indicator (rule-based,
explainable), deploy countdown-style timeline (last deploy, in-flight, queued), and a ⌘K command
palette with natural-language queries ("what breaks if payments is down", "show failing things",
"what changed in the last deploy") that run through an LLM tool-calling agent over the graph and
respond by highlighting/zooming the canvas, not by printing text. Side drawer: why, evidence, owners,
recent runs, "ask AI about this node".
Acceptance: an exec can state system health in <5 seconds from first paint; usability pass with 3
personas documented in docs/usability.md.
```

## P6: Telemetry connectors, anomaly, replay

```
Define a Connector interface (auth, discover(), mapToNodes(), poll()/webhook()). Implement Sentry
(issues/error rate by project), OTLP HTTP ingest (map service.name -> node), and Vercel
(deployments/logs). Auto-match signals to nodes by name/tags and ask the user to confirm once. Add
simple anomaly detection (EWMA/z-score on error rate & latency). Persist snapshots per commit and
health frames over time; build a time-scrubber that replays the control room historically, including an
"incident replay" that auto-focuses the first node to degrade and the propagation path.
Acceptance: seeded incident scenario replays correctly end to end in a demo repo.
```

## P7: Browser extension, sharing, polish

```
Build a Manifest V3 extension (WXT or plain Vite) that on github.com/{owner}/{repo} injects a
"View Twin" button and a small health badge fetched from our public badge endpoint, deep-linking to the
app. Add read-only share links and embeddable iframe/SVG badges with revocable tokens, a user
"correct this node" override system that survives rescans, rate limiting and BotID, error/empty states
for every screen, and an e2e Playwright suite covering the paste-URL -> map -> drill-down -> failing-node
flow.
Acceptance: extension works on public and private repos (private requires signed-in app session);
e2e green in CI; Lighthouse perf >= 90 on the landing page.
```

---

### Meta-prompt for any session
```
Before coding: restate the acceptance criteria, list files you'll touch, and write failing tests first
for graph logic. After coding: run typecheck, lint, tests, and screenshot the UI at 1440px and 390px.
Never invent graph facts without an evidence ref. Prefer deterministic detection over LLM inference.
```
