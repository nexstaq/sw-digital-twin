# Mission Control for Code

Point it at a GitHub repository. It reads the code, CI/CD and infrastructure files and draws a **live, zoomable map** of how the software is built, shipped and run. Each part of the map glows by health (nominal, degraded, failing, unknown), like a launch control room. Click a part to go one level deeper, down to files, jobs and individual errors.

It also checks the repository for security problems: vulnerable dependencies, leaked secrets, risky code and pipeline settings, container issues, and (for sites you prove you own) the live site's TLS, headers and cookies.

Live at <https://sw-digital-twin.nexstaq.com>. There is a no-sign-in demo at `/demo`.

## What it does

| Area | What you get |
|---|---|
| **Map** | Delivery flow, services and infrastructure derived from workflows, Dockerfiles, package manifests and code. Five lenses: Overview, Flow, Ops, Risk, Tour. Every node shows its evidence and a confidence badge. |
| **Simulate** | A sixth lens: click any block and watch a request, a queue hand-off or a change going through the pipeline pass through it step by step, in plain English, engineer or security voice. Then break something and see which blocks the real health rules would turn red. A simulated copy: nothing is sent anywhere, and the real verdict is never replaced. |
| **Verify by simulation** | On the Security page: tries each code finding against a simulated copy of the system. Can an outside request reach it, and what does it reach then? With source (only if you allow it) it also looks for protection already in the code, downgrades likely false alarms, and proposes patches as diffs to read. Evidence, not proof: it reorders the fix-first list and never changes a severity or the score. |
| **Health** | GitHub Actions and Deployments, plus Sentry, Vercel and OpenTelemetry (OTLP) connectors, mapped onto the nodes. Go / No-Go verdict, blast radius, incident replay. |
| **Plain English** | Optional AI descriptions and "ask the map" questions. Private repos never go to the free dev key. |
| **Security** | Dependency advisories with reachability, secrets, code rules, pipeline and container checks, attack paths, OWASP and CWE views, SARIF import, GitHub alerts, trend over time, printable report. |
| **Live site checks** | Passive TLS, header, cookie, exposed-file and email-DNS checks, only after you prove domain ownership, and re-proved on every run. |
| **Scheduled scans** | Opt-in daily or weekly re-scans (and re-checks of verified domains) from a Vercel Cron job. |
| **Sharing** | Read-only share links, an embeddable README badge, and a browser extension that adds a "View Twin" button on github.com. |

Design notes and decisions live in [`docs/`](docs): [PLAN](docs/PLAN.md), [INGEST](docs/INGEST.md), [HEALTH](docs/HEALTH.md), [CONNECTORS](docs/CONNECTORS.md), [AUTH](docs/AUTH.md), [SECURITY](docs/SECURITY.md), [SECURITY-ANALYSIS](docs/SECURITY-ANALYSIS.md), [BACKLOG](docs/BACKLOG.md) (open work), [SIMULATION](docs/SIMULATION.md) (in design: simulation and adversary-emulation agents). Build prompts: [PROMPTS](docs/PROMPTS.md), [PROMPTS-SECURITY](docs/PROMPTS-SECURITY.md), [PROMPTS-SIM](docs/PROMPTS-SIM.md).

## Run it locally

Requires Node.js 22 or later.

```bash
npm install
cp .env.example .env.local   # every variable is optional; see below
npm run dev                  # http://localhost:3000
```

With no configuration it works on public repositories using rule-based descriptions and files under `.data/` for storage. Paste a public `owner/name` on the home page, or open `/demo`.

> After running `npm run build`, delete `.next` before starting `npm run dev` again; the two share that folder and a stale build makes the dev server reload endlessly.

### Configuration

All settings are environment variables; [`.env.example`](.env.example) documents each one. The common ones:

| You want | Set |
|---|---|
| Higher GitHub rate limits for public repos | `GITHUB_TOKEN` |
| Sign-in and private repos | a GitHub App: `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET`, `GITHUB_APP_SLUG`, `SESSION_SECRET`, `APP_URL` (see [docs/AUTH.md](docs/AUTH.md)) |
| Instant updates | `GITHUB_WEBHOOK_SECRET` |
| AI descriptions | `AI_GATEWAY_API_KEY` (production) or `GOOGLE_GENERATIVE_AI_API_KEY` (dev, public repos only) |
| Durable storage | `DATABASE_URL` (Neon Postgres). Without it: files locally, memory on Vercel |
| Scheduled scans | `CRON_SECRET` |
| Runtime signals | `SENTRY_*`, `VERCEL_*`, `OTLP_INGEST_KEY` (see [docs/CONNECTORS.md](docs/CONNECTORS.md)) |

## Scripts

| Command | Does |
|---|---|
| `npm run dev` | Development server |
| `npm run build` / `npm start` | Production build and server |
| `npm test` | Unit tests (Vitest) |
| `npm run e2e` | End-to-end tests (Playwright) against a production build and a mock GitHub. Hermetic: no network, no real credentials. Builds into `.next-e2e`, so it is safe while `npm run dev` is running |
| `npm run lint` | ESLint |
| `npm run ext:build` / `ext:zip` | Build or package the browser extension in [`extension/`](extension) |

## Deploy

Deployed on Vercel. Connect the repository, add the environment variables above, and (for persistence) add Neon through the Vercel Marketplace. [`vercel.json`](vercel.json) registers the daily cron job for scheduled scans; set `CRON_SECRET` so it can run.

## How it is built

Next.js (App Router, TypeScript), React Flow with ELK for the map, Zustand for client state, Neon Postgres or files for storage, and the AI SDK for the optional language layer. Analysis is deterministic first (parsers and detectors); a model only describes what was found. Only graph structure and findings are stored, never source code or the value of a secret.

Security and safety notes, including the rules for testing a live site, are in [docs/SECURITY.md](docs/SECURITY.md) and [docs/SECURITY-ANALYSIS.md](docs/SECURITY-ANALYSIS.md).

> This repository's `AGENTS.md` warns that this Next.js version differs from older releases. When changing framework code, read the matching guide under `node_modules/next/dist/docs/` first.
