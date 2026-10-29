# Software Deployment Digital Twin ("Mission Control for Code")

## 1. Product thesis

Point it at any GitHub repo. It reads the code, CI/CD, and infra definitions, and renders a **live, zoomable process-flow** of how the software is built, shipped, and run. Each node glows by health (nominal / degraded / failing / unknown), like a launch control room. Click a node to dive one level deeper, down to files, jobs, and individual errors.

Differentiator vs incumbents (Datadog, Backstage, Sourcegraph, CI dashboards): **zero-config, visual-first, no tables**. The system map is derived automatically, then enriched with live signals.

## 2. Plugin vs web app: recommendation

**Build the web app first, add a thin browser extension second.**

| | Browser plugin only | Web app (+ GitHub App) |
|---|---|---|
| Heavy analysis (clone, parse, LLM) | No. Must call a backend anyway | Yes |
| Live health (CI, deploys, Sentry, OTel) | Hard: CORS, secrets in browser | Yes, server-side connectors |
| Rich canvas, replay, multi-repo, sharing | Cramped inside GitHub's DOM and CSP | Full control |
| Discovery / "magic moment" on github.com | Excellent | Needs a link |
| Private repos | Reuses user session, but cannot read via API without token | GitHub App install, least-privilege |

**Extension role (Phase 5):** a "View Twin" button and a mini health badge injected on `github.com/{owner}/{repo}`, deep-linking to the web app. It is about 200 lines and gives the in-GitHub entry point without constraining the product.

## 3. Personas and lenses

One graph, five lenses (a toggle at the top, not separate apps):

| Persona | Lens | Sees first |
|---|---|---|
| Exec / PM | **Overview** | 6-10 big blocks, one Go/No-Go status, trend arrows, plain-English labels |
| Engineer | **Flow** | Build → test → deploy → services, with code paths and owners |
| SRE / on-call | **Ops** | Error rate, failing jobs, blast radius, recent deploys on a timeline |
| Security | **Risk** | Vulnerable deps, secrets scanning, exposed endpoints, permissions |
| New joiner | **Tour** | Auto-narrated guided walkthrough of the architecture |

## 4. Core concepts

**Two intertwined graphs, one canvas:**
1. **Delivery flow**: commit → PR checks → build → test → artifact → deploy → environment (the "launch sequence").
2. **Runtime topology**: web, API, workers, queues, DBs, third-party services (the "vehicle").

**Semantic zoom (3 levels, plus evidence):**
- **L0 System**: 6-10 logical components (LLM-clustered, human-named: "Checkout", "Auth", "Data Pipeline").
- **L1 Component**: services, packages, jobs, endpoints inside it.
- **L2 Unit**: files, functions, workflow steps, individual failing runs/exceptions.
- **Evidence**: every node and edge links to file:line or a workflow run. Nothing is invented without a citation.

**Health model** (per node, rolled up to parents with worst-of plus weighting):
`nominal | degraded | failing | unknown` plus a numeric score, a sparkline, and "why" (top 3 reasons).
Signals: CI pass rate and flakiness, deploy success and rollback frequency, exception rate (Sentry), latency/error rate (OTel/Datadog/Vercel), open critical alerts, change-failure rate, staleness.

## 5. Architecture

```
GitHub ──(App install, webhooks)──┐
                                  ▼
┌─────────────────────── Next.js app on Vercel ───────────────────────┐
│ UI: Control room canvas (React Flow + ELK + Framer Motion)          │
│ API routes / Server Actions   ·   SSE stream for live health        │
└───────────┬───────────────────────────────┬─────────────────────────┘
            │                               │
   Ingestion Workflow (durable)      Signal Connectors (pluggable)
   1 clone (Vercel Sandbox)          GitHub Actions/Deployments/Checks
   2 detect & parse (tree-sitter)    Vercel deployments/logs
   3 build raw graph                 Sentry · OTLP · Datadog · Prometheus
   4 LLM cluster + label (AI Gateway)        │
   5 persist snapshot + embeddings           ▼
            │                        Health Engine (rollups, anomaly)
            ▼                               │
   Postgres (Neon) ◄──────────────────────┘
   Blob (graph snapshots, replay frames) · Queues (webhook fan-out)
```

**Stack:** Next.js (App Router, TS), Tailwind + shadcn/ui, `@xyflow/react` + `elkjs` for layout, Framer Motion, Zustand, Drizzle + Neon Postgres, Vercel Workflow + Queues + Sandbox, AI SDK via AI Gateway, GitHub App (Octokit), tree-sitter (WASM) for parsing. Auth via a Marketplace provider (e.g. Clerk) plus GitHub OAuth.

### 5.1 Detectors (static analysis, deterministic first, LLM second)

| Source | Extracts |
|---|---|
| `.github/workflows/*` | Jobs DAG, triggers, environments, deploy targets |
| `Dockerfile`, `docker-compose`, `k8s/`, Helm, `vercel.json/ts`, `serverless.yml`, `fly.toml`, Terraform/Pulumi | Services, ports, env deps, infra resources |
| `package.json`/workspaces, `pyproject`, `go.mod`, `Cargo`, `pom` | Packages, internal deps, frameworks |
| Source (tree-sitter) | Entrypoints, HTTP routes, import graph, queue publish/consume, DB clients, external SDKs |
| `CODEOWNERS`, git log | Ownership, churn hotspots |

LLM step receives the *structured* raw graph plus file summaries (not the whole repo), and returns: clusters, names, one-line purpose, L0 layout hints. Output is validated against a Zod schema, and every claim must carry evidence refs.

### 5.2 Graph schema (canonical, versioned)

```ts
Node { id, level: 0|1|2, parentId?, kind: 'service'|'job'|'package'|'datastore'|'queue'|'external'|'endpoint'|'file'|'env',
       label, summary, evidence: {path, lines?, runId?}[], owners?: string[], tags: string[] }
Edge { id, from, to, kind: 'calls'|'triggers'|'deploys_to'|'depends_on'|'publishes'|'consumes'|'reads'|'writes', evidence[] }
Health { nodeId, ts, state, score, signals: {name, value, threshold}[], reasons: string[] }
Snapshot { repoId, commitSha, createdAt, graph, version }
```

Snapshots per commit enable **time-travel replay** ("what did prod look like at 14:02 during the incident?").

### 5.3 Live updates
GitHub webhooks (`workflow_run`, `deployment_status`, `check_run`, `push`) → Queue → Health Engine → SSE to the browser. Optional OTLP ingest endpoint for runtime telemetry mapped to nodes via service-name tags.

## 6. UX direction (the "control room")

- **Look:** dark, high-contrast, restrained palette. Status colors only for state (green/amber/red/grey), always paired with shape or icon (colorblind-safe). Soft glow and pulse for activity. No default table anywhere; tables exist only behind an "evidence" drawer.
- **Canvas:** nodes are rich tiles (icon, name, mini sparkline, status ring). Edges animate along direction of flow, with particle speed ∝ throughput, red flicker on error edges.
- **Top bar:** big **GO / NO-GO** indicator, deploy countdown-style timeline ("Last deploy 12m ago · 3 in flight"), lens switcher, time scrubber.
- **Interactions:** scroll to zoom semantically (nodes expand into their children, not just scale), breadcrumb "mission path", `⌘K` natural-language ("show what breaks if payments is down"), hover for blast radius highlight, click for side drawer (why, evidence, owners, recent runs, "ask AI").
- **Onboarding:** paste a repo URL → streaming "scan" animation that builds the map live (builds trust, and the wow moment) → Tour mode auto-plays.
- **Empty/unknown states:** greyed "no telemetry, connect Sentry" nodes with one-click connect, rather than blank.
- **A11y/perf:** keyboard nav, reduced-motion mode, virtualized rendering above ~500 nodes, collapse by default.

## 7. Phased roadmap

| Phase | Goal | Done when |
|---|---|---|
| 0 | Scaffold, design system, fixtures | App runs with a hardcoded sample graph rendered beautifully |
| 1 | Repo → static graph (workflows, Docker/infra, packages) | Any public repo yields an L0/L1 map with evidence |
| 2 | LLM clustering, labeling, L2 drill-down, lenses | Exec view reads in plain English; Tour works |
| 3 | GitHub App, private repos, webhooks, health from Actions/Deployments | Live status glows correctly on a real repo |
| 4 | Connectors (Sentry, OTLP, Vercel), anomaly, blast radius, replay | Incident replay demo end-to-end |
| 5 | Browser extension, sharing/embeds, teams, polish | "View Twin" on GitHub; shareable read-only links |

## 8. Risks and mitigations

- **Inferred architecture is wrong** → evidence on everything, confidence badges, "correct this" edits persisted as overrides that survive re-scans.
- **Huge monorepos** → shallow clone, language-scoped parsing, incremental re-analysis by changed paths, time-boxed stages with partial results streamed.
- **Security of private code** → GitHub App with read-only scopes, ephemeral Sandbox, no code persisted (store graph + summaries only), configurable "no LLM on source, metadata only" mode.
- **LLM cost / nondeterminism** → deterministic detectors first, cache by content hash, structured outputs, snapshot diffing.
- **Signal mapping** (which Sentry project is which node) → auto-match by service name and tags, confirm once in UI.

## 9. Decisions
1. Launch personas: engineering leaders + SRE/on-call (default lens: Ops, with Overview one click away). Broaden later.
2. GitHub only for v1.
3. SaaS first; self-hostable after features are proven. Keep it cheap later: no vendor-specific code outside adapters (LLM, queue, storage, auth).
4. We are not a telemetry backend. Connectors read from the customer's tools; we store only compact health rollups. Signal order: GitHub (free, zero-setup) → Sentry → Vercel → OTLP/Datadog.
5. LLM access goes through one provider-agnostic layer (AI Gateway, BYOK-capable). Free Gemini key is OK for dev on public repos only.
