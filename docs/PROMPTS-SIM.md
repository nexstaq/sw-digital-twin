# Simulation and adversary-emulation prompts (H0, X0 to X10)

Second prompt set, continuing after `docs/PROMPTS.md` (P0 to P7) and the security work (S1 to S4, scheduled scans).
Run in order, one per Claude Code session. Each prompt is self-contained and ends with acceptance criteria.
Read `docs/PLAN.md`, `docs/SECURITY.md` and `docs/SECURITY-ANALYSIS.md` first.

## The boundary (applies to every prompt)

We build **emulators and simulators, not an attack platform.** This is the same rule S1 to S4 already follow:

1. **Default target is a range**: an emulated copy of the software's own blocks, generated from the map, run in an
   isolated sandbox with no network egress. Nothing real is attacked.
2. **Real targets only with proof of authority.** Either the customer's own CI runs the test (the S3 pattern, GitHub OIDC), or a
   domain whose ownership was proven in this run (the S4 pattern). Never both unproven, never a third party.
3. **Safe by construction.** Agents get a fixed tool allowlist, a scope guard enforced in code (not in the prompt), a step and
   time budget, and a kill switch. Proofs of concept are harmless markers, never working weapons against real systems.
4. **Evidence or it did not happen.** Every finding cites a transcript step, a file:line or a request/response pair. Same rule as the map.
5. **Privacy.** No source text to a model unless the repo owner turned it on. No secret values stored. Transcripts redact.
6. **Humans approve** anything beyond read-only probing of the range.

## Agents (what each one knows, and what it may do)

| Agent | Knowledge | Does | Target |
|---|---|---|---|
| **White-box** | Source, graph, findings, configs | Reviews code paths, writes and runs exploit *tests* against the range, proposes fixes | Range |
| **Gray-box** | Graph, endpoints, one user's credentials, docs | Authenticated probing: broken access control, IDOR, privilege escalation, business logic | Range, then verified domain |
| **Red team** | Nothing but the public surface and what it discovers | Chains steps into a campaign (recon to impact), mapped to MITRE ATT&CK; tries to reach the crown-jewel assets | Range |
| **Blue observer** | Telemetry the range emits | Checks whether the health engine, anomaly detector and alerts noticed each step | Range |
| **Block narrator** | The block's emulator | Explains how a block works, step by step, in the user's persona language | Range |

---

## H0: Close what is pending before building on it

```
Read docs/PROMPTS.md, docs/INGEST.md, docs/HEALTH.md, docs/CONNECTORS.md, docs/SECURITY.md and
docs/SECURITY-ANALYSIS.md. Several "Not yet" and "Known limits" notes predate later work. For each one, check the
code and either (a) delete the stale note, (b) fix it if it is small, or (c) list it in docs/BACKLOG.md with an owner
and a one-line reason. Specifically verify and decide:
 - ingestion still clones with git on the app server: move to Vercel Sandbox and drive with Vercel Workflow, or record
   why not (P2 asked for both)
 - webhook bus is in-process: put Vercel Queues behind bus.ts, or record it
 - snapshot selection during replay; "what changed in the last deploy" mapping changed files to nodes
 - Sentry and Vercel connectors only mock-tested: write the live-check steps in docs/CONNECTORS.md
 - the S-series prompts are not recorded anywhere: reconstruct them into docs/PROMPTS-SECURITY.md from the commits
 - tree-sitter Wasm on a real Vercel deployment: verify on production and record the result
Acceptance: no doc contradicts the code; docs/BACKLOG.md is the single list of open work; typecheck, lint, unit and
e2e green.
```

## X0: Spec, threat model and rules of engagement (no feature code)

```
Create docs/SIMULATION.md and an ADR. Write: (1) a threat model of THIS feature (STRIDE plus abuse cases): an
attacker uses our agents to attack a third party; scope escape from the sandbox; prompt injection from repo content
into an agent; a malicious repo that targets our sandbox; leaking secrets via transcripts; cost exhaustion; a
user who is not an owner requesting a real-target run. (2) A Rules-of-Engagement schema in Zod: targets (range |
verified-domain | ci-runner), allowed techniques (ATT&CK ids), forbidden actions, time window, step/token/cost
budgets, who approved and when, kill-switch id. (3) The scope guard contract: a pure function
`allow(action, roe, now)` that every tool call passes through, default-deny. (4) The audit-log format: append-only,
hash-chained, redacted. (5) The list of acceptance tests that must exist before any agent ships.
Write failing tests first for allow() and the ROE schema.
Acceptance: threat model has mitigations mapped to tests; allow() has tests for every deny reason; nothing else built.
```

## X1: The range (emulated twin of the software)

```
From a stored Snapshot, generate a "range": one emulator per node kind. Services and endpoints become small
deterministic HTTP emulators that implement the routes the map found (method, path, auth-required flag). Datastores
become in-memory fakes with a seeded schema. Queues, external services and environments become fakes with
configurable latency and failure. CI jobs and deploys become step emulators that replay a workflow's DAG. Run the range
inside Vercel Sandbox with no network egress and a hard time limit. Seed weaknesses ONLY from findings the scanner
already produced (a SQL injection finding makes that route injectable in the emulator), so the range mirrors the real
risk and nothing is invented. Emit health and trace events into the existing health engine so the map lights up.
Never copy source or secrets into the range; emulators are generated from graph metadata.
Acceptance: range for the demo repo starts in under 20 s; the same snapshot always yields the same range
(deterministic, snapshot tested); egress attempts from inside are blocked and tested; destroyed on completion.
```

## X2: Block simulators ("show me how this block works")

```
Add a "Simulate" lens. Select any block; a simulator runs the block's emulator and animates a real flow through it
on the existing canvas: a request entering an endpoint, passing auth, hitting the datastore, publishing to a queue,
a consumer picking it up; or a commit through its CI jobs to a deploy. Controls: play, pause, step, speed, and
inject a fault (latency, error, outage, expired token, dependency down) to see the blast radius and the health
rollup respond. Narration per step in the persona language (exec / engineer / security), generated from emulator
events, each step citing the node or edge evidence. Deterministic by default; an optional model only rewords captions.
Respect prefers-reduced-motion with a step-through view. Keyboard accessible.
Acceptance: three block types demonstrable end to end (HTTP service, queue, CI pipeline); fault injection changes
health exactly as the engine's rules say (tested); captions never reference a node that does not exist.
```

## X3: Agent runtime and guardrails

```
Build the shared agent runtime in src/lib/sim/agent. Use the AI SDK through AI Gateway ("provider/model" strings);
read node_modules/ai/docs first, and propose before adopting any new agent framework. Tools are typed and
allowlisted per agent; every tool call goes through allow() from X0 and is written to the audit log. Enforce budgets
(steps, tokens, wall time, cost) in code. Repo content, advisories, HTTP responses from the range and tool output are
UNTRUSTED data: quote them inside JSON, never as instructions, and strip anything that tries to change scope.
Structured output validated with Zod; every finding must cite an audit-log step or evidence ref, else it is dropped.
Kill switch: one call stops all runs for a repo and tears down sandboxes. Human approval gate for any step flagged
"intrusive". Private repos never use a free-tier model.
Acceptance: an injection suite (repo README, a response body and a finding text each telling the agent to ignore
scope) cannot cause an out-of-scope call; budgets stop runaway loops in tests; kill switch verified; no secret
or source in logs.
```

## X4: White-box agent

```
Implement the white-box agent. Inputs: the snapshot, scanner findings, and (only if the repo owner enabled it)
source excerpts the maintainer's own token can read. It: (1) picks the highest-risk attack paths from paths.ts,
(2) for each, writes an exploit TEST (a failing test or a request sequence) that proves the weakness against the range,
(3) confirms or downgrades the scanner's finding with that proof, (4) proposes a minimal patch as a diff and re-runs the
test to show it now fails safely. Output joins the existing Security map as "confirmed by simulation" with a confidence
badge; unconfirmed findings stay as they were. Never opens a PR on its own.
Acceptance: on the fixture repo it confirms the seeded SQL injection and path traversal, and downgrades one seeded false
positive; patch suggestions are shown as diffs only; every claim cites an audit step.
```

## X5: Gray-box agent

```
Implement the gray-box agent: it knows the map, the endpoint list and one set of range credentials per role (user,
admin). It tests: broken access control and IDOR (user A reads user B), missing function-level authorization,
privilege escalation, mass assignment, rate-limit and lockout gaps, session handling, and business-logic abuse the
graph suggests (skip a step, replay a request). Then, only when the ROE names a verified domain and a human approved,
it may repeat the NON-intrusive subset against that domain through the S4 passive-check client (same ownership proof,
same public-address rule, same caps). Findings use the existing Finding type plus a "technique" and "proof" field.
Acceptance: finds the seeded IDOR and the unauthenticated admin route in the range; against a verified test domain
it sends nothing unless ownership is re-proved (counted requests, like the S4 e2e); credentials never persisted.
```

## X6: Red-team campaign agent (adversary emulation)

```
Implement the red-team agent. It starts with only the public surface of the range. It plans a campaign as a graph of
steps mapped to MITRE ATT&CK techniques (recon, initial access, execution, credential access, lateral movement,
exfiltration, impact) and tries to reach the "crown jewels" (datastores and secrets-holding environments the map
marks). Include CI/CD-specific chains from the pipeline analyzer (pwn request, poisoned dependency, leaked token to
deploy). Each step is a bounded range action with a harmless proof marker; no real malware, no real exploit code
against real software. The campaign output is a replayable timeline plus the attack path drawn on the map.
Include a "purple" mode that, after each step, asks the Blue observer (X7) whether it was detected.
Acceptance: reaches the seeded crown jewel via at least two distinct paths; the plan only uses technique ids allowed
by the ROE; replay works from the audit log alone; a run with a forbidden technique id is refused in a test.
```

## X7: Blue observer: did we notice?

```
Implement detection validation. For every simulated step, record the telemetry the range emitted and check whether
the health engine, anomaly detector and any alert rule noticed, and how long it took. Produce a coverage view: ATT&CK
techniques tried vs detected vs missed, time to detect, and for each miss a concrete suggestion (which signal to add
or threshold to change). Feed missed-detection gaps into the Security map as findings with category "detection gap".
Reuse the incident replay: a campaign replays like an incident, with patient zero and propagation.
Acceptance: a seeded stealthy step (slow data exfil with no errors) is reported as missed by default and detected after
the suggested rule is applied (test); coverage numbers match the audit log.
```

## X8: UI: campaigns, replays and reports

```
Build the experience: a Simulation page per repo with three entry points (Explain a block, Run a test, Run a campaign),
a pre-flight screen that shows the ROE in plain language and requires explicit approval, live progress on the canvas
(attack path glows, detected steps get a different mark from missed ones, both with shapes not only colour), a
timeline scrubber for replay, and a printable report (reuse report.ts conventions: escaped text, https links only,
locked CSP, no secrets). Export to SARIF with technique ids. Share links never include simulation transcripts (tested).
Empty, running, failed, killed and budget-exhausted states for every screen. Mobile at 390px.
Acceptance: Lighthouse a11y >= 95; keyboard-only run-through works; Playwright covers explain, test and campaign
flows against the range.
```

## X9: Authorised external runs (customer CI and verified domains)

```
Extend the S3 pattern. Generate a GitHub Actions workflow that runs the chosen simulation profile in the CUSTOMER'S
runner against a staging URL they name, authenticated to us with GitHub OIDC (audience, repository claim, short
expiry, same verifier), uploading SARIF plus a redacted transcript. Safe by default: manual or weekly only, never on
pull requests, refuses to run until the target is https and an owner-confirmation variable is set, no intrusive
techniques, rate limited, pinned images by digest. Our servers never send simulation traffic to third parties.
Run our own pipeline analyzer over the generated YAML in a test. Verified-domain runs reuse S4 ownership proof re-checked
at the start of every run, with the ROE time window enforced.
Acceptance: generated workflow passes our own analyzer; a token for another repository is refused; a run outside the
ROE window or on an unproven domain sends zero requests (e2e, counted at the target).
```

## X10: Assurance for the agents themselves

```
Treat the agents as high-risk software. Add: (1) an eval suite in CI with golden range runs, scored on true findings,
false positives, scope violations (must be zero) and cost; fail the build on any scope violation. (2) A "red team the
red team" test set: prompt injection, tool-argument smuggling, DNS rebinding and redirect tricks against the scope guard,
sandbox egress attempts, oversized outputs, and a malicious repo fixture. (3) Privacy review: what leaves the
server (to which model/provider), retention periods, deletion on request, redaction tests on transcripts, a
metadata-only mode that sends no source. (4) Supply chain: pin and review every new dependency, generate an SBOM in CI, run our
own scanner on this repo. (5) Operational: per-repo and global rate limits, cost caps with alerts, audit-log export, an
incident runbook for "an agent did something out of scope". (6) Update docs/SECURITY.md, the README feature table and
docs/usability.md with three persona tasks (exec: "are we resilient?", security lead: "what could an attacker reach?",
engineer: "how does this block work?").
Acceptance: all evals and injection tests run in CI; zero scope violations across the suite; SBOM artifact produced;
every doc matches the code.
```

---

### Meta-prompt for every session (AI-first SDLC)

```
Before coding: read AGENTS.md and the relevant guide in node_modules/next/dist/docs/ (this Next.js differs from older
versions). Restate the acceptance criteria and the boundary rules above, list the files you will touch, name the risks
(abuse, privacy, cost) and write the failing tests first, security tests included. While coding: deterministic
before model-based; default-deny; no secret values or source in logs, storage or prompts; every claim carries evidence.
After coding: typecheck, lint, unit, e2e, screenshot at 1440px and 390px, run our own security scan on the diff
(/security-review), update the matching doc and docs/BACKLOG.md, and state plainly what was NOT verified.
Do not commit or deploy unless asked. After npm run build, rm -rf .next before npm run dev.
```
