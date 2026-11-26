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
| B14 | Weaknesses the scanner cannot find (IDOR, business logic) | Partly done in X5: imported reports, mapped by CWE, seed them. The built-in scanner still finds none (B34) |
| B15 | Tie a finding to one handler, not every route in its file | The map does not carry line-to-handler mapping for routes |

| B16 | Optional model rewording of simulation captions | The X2 prompt allowed it; not built. Needs the same untrusted-text rules as explain.ts |
| B17 | Simulate state in the URL, so a run can be shared | Not built |
| B18 | Show a pipeline's jobs and its release in one view | The canvas shows one level; jobs inside a workflow appear only in the step list |

| B19 | Store each run's audit log and head hash; check the head when the log is read | X3 returns them; nothing keeps them, so a cut-off tail cannot yet be detected later |
| B20 | Per-repository and global limits on concurrent runs and total spend | X3 bounds one run; nothing bounds the number of runs |
| B21 | Evaluate REAL models against the range: finding quality, false positives, whether any scope violation ever gets as far as the guard | X10's eval suite (golden runs + a scope-violation gate, in CI) uses scripted models throughout, same reasoning as X3: real-model evaluation needs an API key, real cost and accepts nondeterminism, none of which this suite does |
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

| B32 | Run the real-site probe from the app | `probeDomain` is a library function. It needs the approval screen and a stored-domain flow (X8) |
| B33 | Real-site tests with credentials (object-level access, sessions, mass assignment) | Needs a design for handling real secrets that are never stored or logged. Today the agent takes none |
| B34 | Detect IDOR, missing authorisation and mass assignment in code, in the built-in scanner | Without an imported report the range has none of these and the gray-box agent finds none |
| B35 | Use the application's real access policy instead of path conventions (admin under `/admin`, writes need a sign-in, ids addressing objects) | The model is an assumption, labelled as one |
| B36 | A dedicated reachability/crown-jewel screen (the path graph drawn on the map, not just the notes list and per-finding badge) | X6 surfaces its summary sentence and per-finding verdicts only; no graphical view of the reachability paths yet |
| B37 | A detection-coverage screen (tried/detected/missed, time-to-detect, the combined replay drawn as an incident) | X7 surfaces detection-gap findings through the ordinary findings list and notes only |
| B38 | Offer the candidate request-volume anomaly rule as a real, installable addition to the health engine | X7 only demonstrates it inside the detection check; `health/runtime.ts` is untouched |
| B39 | Run a real Lighthouse accessibility audit of the Simulation page | X8 asked for ≥95; this environment has no Lighthouse CLI, so a landmarks/labels/keyboard pass was done by hand instead and the score is not claimed |
| B40 | Embed "Explain a block" (the Simulate lens) directly on the Simulation page, instead of linking out to the map | X8 judged duplicating the whole Canvas/Simulate-lens tree on a second page not worth the risk; the link-out is a deliberate, documented simplification |
| B41 | A real approval screen and ROE creation flow for a human-approved real target (the verified-domain path, not range-only, and not the CI-runner path X9 built) | X8's pre-flight screen is for the range-only run; X9 covers the CI-runner path (no human approval needed, OIDC + the repo's own confirmation); the verified-domain path is still just a design in the ROE type |
| B42 | A UI on the Simulation page (X8) to configure or trigger X9's authorised CI run, instead of copying the generated workflow by hand | X9 is reached only from "Sources and live testing" on the Security page |
| B43 | Run X9's generated workflow on a real GitHub Actions runner | Tested against the exported route handlers and the YAML's own shape only, not a real run (B31, shared with X4–X6) |
| B44 | Answer the exec's real question ("are we resilient?") directly on the Security page, not just a vulnerability-count grade | X10's usability pass: the grade loads fast but answers a different question; the reachability likelihood that actually answers this lives on a different page and tab |
| B45 | Lead the reachability replay with its own plain-language summary sentence, not whichever finding happens to sort first | X10's usability pass: the sentence already exists in `notes`; it is not the first thing shown |
| B46 | A "delete everything for this repository" endpoint | X10's privacy review: a maintainer can remove one imported report, domain or share link, but not purge a repository's whole record in one action |
| B47 | A single, enforced "metadata-only" mode, instead of several independently-defaulted switches that currently add up to the same thing | X10's privacy review: the simulation's source-read checkbox defaults off and AI explanations never take source regardless, but no one flag guarantees it |
| B48 | Generate an SBOM for this repository's own dependencies in CI | X10: needs a third-party tool (`@cyclonedx/cyclonedx-npm`) this session could not verify running safely first |
| B49 | Run this project's own security scanner against this repository, in CI | X10: the scan pipeline currently assumes the request/response cycle of the Security page, not a standalone CI invocation |

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
