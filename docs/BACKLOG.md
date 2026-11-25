# Backlog: the single list of open work

Written by prompt H0 (2026-11-25). Each item says why it is open. "Owner" is blank until someone takes it. When an item ships, delete it here and fix the doc it came from.
Other docs describe how things work today; they should not carry their own to-do lists.

## Build gaps

| ID | Item | Why open | Source |
|---|---|---|---|
| B1 | Run ingestion in Vercel Sandbox, driven by Vercel Workflow | P2 asked for it. Today the scan runs inside the request (git locally, GitHub tarball on Vercel). Works, but a timeout loses the scan and untrusted repo content is parsed in the app's own process. Needed before simulation ranges (X1) | docs/INGEST.md |
| B2 | Shared webhook bus (Vercel Queues or Redis behind `src/lib/github/bus.ts`) | In-process bus: other instances catch up within 20 s. Needs a provisioned queue, a cost and provider decision | docs/HEALTH.md |
| B3 | Choose the stored map that existed at the replayed time | Snapshots are stored per commit; replay always uses the latest map | docs/CONNECTORS.md |
| B4 | "What changed in the last deploy" mapped to nodes | Needs the GitHub compare API plus ownership/path mapping | docs/usability.md |
| B5 | Verify Sentry and Vercel connectors against live services | Mock-tested only. Steps are in docs/CONNECTORS.md | docs/CONNECTORS.md |
| B6 | Datadog and Prometheus connectors; OTLP metrics, logs, protobuf; Sentry webhooks | Not built | docs/CONNECTORS.md |
| B7 | Verify tree-sitter Wasm grammars on a production Vercel deployment | Listed in `outputFileTracingIncludes` for both scan routes; no recorded production check. BotID blocks scripted calls, so do it from a signed-in browser and record the result | docs/INGEST.md |
| B8 | Share views and the embed: runtime layer (Sentry/OTLP) and auto-refresh | Share and embed show GitHub-derived health only; the embed reloads only on frame reload | docs/SECURITY.md |
| B9 | Health signal from code-scanning alerts; join the Risk lens with Security findings | S3 reads alerts for the security view only; the lens still shows exposure surface only | docs/HEALTH.md, docs/usability.md |
| B10 | Live-App test of the installation-token path | Unit-tested with a generated key and mocked GitHub only | docs/HEALTH.md |

## Simulation (from X1)

| ID | Item | Why open |
|---|---|---|
| B11 | Real emulated servers in Vercel Sandbox | Only if a later prompt needs them. The virtual range does not, and has no network by construction |
| B12 | Run the range on a real scanned repository and record what it got wrong | X1 was tested on fixtures and the demo graph only |
| B13 | Persist ranges and run events; an API route to start one | Needs the rules-of-engagement flow (X3, X8) first |
| B14 | Weaknesses the scanner cannot find (IDOR, business logic) | The range is seeded only from findings; X5 needs another source, such as an imported report |
| B15 | Tie a finding to one handler, not every route in its file | The map does not carry line-to-handler mapping for routes |

| B16 | Optional model rewording of simulation captions | The X2 prompt allowed it; not built. Needs the same untrusted-text rules as explain.ts |
| B17 | Simulate state in the URL, so a run can be shared | Not built |
| B18 | Show a pipeline's jobs and its release in one view | The canvas shows one level; jobs inside a workflow appear only in the step list |

| B19 | Store each run's audit log and head hash; check the head when the log is read | X3 returns them; nothing keeps them, so a cut-off tail cannot yet be detected later |
| B20 | Per-repository and global limits on concurrent runs and total spend | X3 bounds one run; nothing bounds the number of runs |
| B21 | Evaluate real models against the range: finding quality, false positives, whether any scope violation ever gets as far as the guard | X3 used scripted models only (X10) |
| B22 | Widen the sanitiser's patterns, carefully | It misses three of the eight sample forms; the guard covers them, but cutting more reduces how often a model is tempted |
| B23 | The real network transport for the gray-box probe, reusing the S4 networking code | Not written (X9) |
| B24 | A screen to approve an intrusive step and to stop a run | The gate and the kill switch exist as code only (X8) |

| B25 | A model-assisted white-box mode (exploring beyond the two templates, writing patches) | X4 is deterministic. A model would need the X3 runtime, untrusted-source quoting, and a decision on sending excerpts to a model |
| B26 | Patch templates for more kinds and languages; multi-line edits | Two kinds, one line, JS/TS only |
| B27 | Keep verdicts across a rescan when a finding is unchanged | A rescan replaces the findings, so verdicts are lost |
| B28 | A stop switch that reaches runs on other server instances | The registry is in-process, like the webhook bus (B2) |
| B29 | Share the source-excerpt reader between the snippet route and the simulation | `src/lib/security/excerpt.ts` repeats part of the snippet route |
| B30 | Run the simulation as a durable job, not inside the request | It runs in the request (60 s). Same reason as B1 |
| B31 | Check a real repository on GitHub, not only the fixture | X4 was tested on the fixture and a fake store |

## Quality and verification

| ID | Item | Why open |
|---|---|---|
| Q1 | Usability test with real people (3 per persona) | The 5-second exec claim is untested with users. Protocol in docs/usability.md |
| Q2 | Screen-reader pass | Only roles and labels checked. Includes the Simulate lens |
| Q5 | Lens tabs have no visible label on a phone, so their accessible name is the tooltip text | Existing for every lens; found while testing Simulate |
| Q3 | Language-model output quality on a live model | Exercised with mocks and with no key only (ask, explain, persona text) |
| Q4 | Tile subtitle size (about 11 px, truncated) | Needs a real read-through |

## Security analysis (from S1 to S4)

| ID | Item |
|---|---|
| S-1 | Git history scanning (a secret removed from HEAD is not found) |
| S-2 | Taint tracking across functions and files (rules look at one call at a time) |
| S-3 | Code rules for Java, Go, Ruby, Rust; dependency reachability for Rust, Java, Ruby |
| S-4 | CycloneDX / SPDX SBOM import |
| S-5 | Webhooks so a GitHub alert shows without a scan |
| S-6 | Subdomain discovery; deeper TLS probing; checks behind authentication |
| S-7 | OSV rate-limit retry; a true server-side PDF |
| S-8 | Scheduled scans: notify on new findings; switch off after repeated failures |
| S-9 | A nonce-based CSP to remove `unsafe-inline` (costs prerendering; revisit if the landing page goes dynamic) |

Deliberately off, not backlog: sending source code to a model for security analysis (a separate decision for the repo owner).
