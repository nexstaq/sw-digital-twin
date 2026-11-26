# Security notes

## Browser hardening (`src/lib/security/headers.ts`, wired in `next.config.ts`)
Every response carries CSP, HSTS (production only), `nosniff`, `X-Frame-Options: DENY`, a strict `Referrer-Policy`, a
`Permissions-Policy` that turns off camera/mic/location/payment, and COOP/CORP `same-origin`. `X-Powered-By` is removed.

**Known trade-off:** the CSP is static, so `script-src` includes `'unsafe-inline'` (Next's bootstrap scripts are inline). A
nonce-based CSP would remove it but forces every page to render per request, undoing prerendering (Next CSP guide). What
the policy still blocks: `eval` in production, plugins, foreign script/connect/frame origins, `<base>` and form hijacking,
and being framed. Revisit if the landing page becomes dynamic anyway.

**Embeds (P7):** badge and embed routes override `frame-ancestors` and `Cross-Origin-Resource-Policy` for themselves
only. Everything else stays locked.

Verified on a production build in Chromium: `/`, `/repos`, `/demo`, `/demo/incident`, `/design`, `/scan` render with zero
CSP violations.

## Rate limits (`src/lib/security/ratelimit.ts`)
Per client address, per route, fixed window: login 20/min, scan 6/min, ask 20/min, health stream 20/min, OTLP 120/min.
In-memory, so each serverless instance counts separately: a brake on one noisy client, not a global quota. Add a Vercel
Firewall rate-limit rule (dashboard) for a global one, and BotID on scan/ask.

## Sign-in
See `docs/AUTH.md`: sealed single-use `state`, httpOnly SameSite=Lax Secure cookies, same-site-only `returnTo`, the token
never reaches page JavaScript.

## "Dangerous site" warnings
Chrome Safe Browsing can flag a brand-new domain that redirects to a login. Code cannot fix that. Check
`transparencyreport.google.com/safe-browsing/search`, verify the domain in Google Search Console (Security issues →
Request review), and report a false positive at `safebrowsing.google.com/safebrowsing/report_error`.

## Share links, badges and overrides (P7)
- **Who can do what.** Read the map: anyone for public repos; signed-in readers for private ones (`authorizeRepo`). Create/revoke share
  links and edit node overrides: push access only, checked with the user's own GitHub token.
- **Share links** are bearer secrets: 192 random bits, shown once, stored only as a SHA-256 hash, compared in constant time over
  all of a repo's links, revocable (takes effect on the next request, including for pages already open). Max 20 live per repo.
  A link opens the *last saved map* plus live health, read-only, with no sign-in. Pages carry `noindex` and `no-referrer`.
- **No probing.** A wrong, revoked or malformed secret, a missing repo and a private repo without a token all answer the same,
  for both `/api/shared/...` and `/api/badge/...`.
- **Badge** `/api/badge/<owner>/<repo>[?t=<secret>]` is the one cross-origin-loadable route (`Cross-Origin-Resource-Policy:
  cross-origin`); token-bearing badges are `private` cached so a CDN cannot hand them to someone without the token.
- **Overrides** (rename, re-describe, hide) are keyed by node id, applied after every scan, and stored per repo. Hidden nodes stay
  listed in a "hidden" menu so they can be restored.
- **Status card embed** `/embed/<owner>/<repo>[?t=<secret>]` is an HTML card for an `<iframe>` (the share panel copies the snippet): the
  GO / HOLD / NO-GO word, the one-line reason, and the top-level parts with a glyph each. It is the **only** page other sites may frame
  (`frame-ancestors *`, no `X-Frame-Options`); it is served with `default-src 'none'`, so no script, font, image or request can run in it,
  and every label is escaped. Same no-probing rule as the badge: private, unmapped and wrong-token all say "Unavailable". A card with a
  secret is `private`-cached. Every other page still answers `frame-ancestors 'none'`.
- **Not yet.** Share views show GitHub-derived health only (no Sentry/OTLP runtime layer), and the embed does not refresh by itself (reload the frame).

## BotID (P7)
`/api/scan` (clones a repo) and `/api/ask` (spends model tokens) call `denyBots()` (`src/lib/security/bot.ts`), which uses Vercel
BotID. The browser side is `src/instrumentation-client.ts` (`initBotId`) plus `withBotId` in `next.config.ts`. BotID attaches its
token to `fetch`/XHR only, so the scan page streams with `fetch` (`src/lib/sse.ts`), not `EventSource`.
- Only active on Vercel (`process.env.VERCEL`); elsewhere it is off, so dev, self-hosting and CI are unaffected.
- Fails open if BotID itself errors (logged), because the per-client rate limits still apply.
- Deliberately NOT protected: the badge (GitHub's image proxy must reach it), pages, and sign-in.
- Basic mode is free. "Deep Analysis" is an optional dashboard toggle (Project → Firewall → Configure).
- `RATE_LIMIT_SCALE` multiplies every rate limit (default 1; the e2e suite uses 5).

## Outbound requests: passive checks (S4)
The one place the server fetches a user-supplied hostname is `src/lib/security/passive/`. Ownership (DNS TXT or well-known file) is
re-proved on every run; only public addresses are contacted (all DNS answers validated, the validated address is the one connected to);
standard ports, no redirects off the host, size and time caps, a cooldown and a per-repo cap. Response bodies are not stored. Full model:
`docs/SECURITY-ANALYSIS.md`.

## AI explanations (S4)
Findings text is untrusted input to the model; no source code and no secret value is ever sent; private repositories never use a
free-tier model; answers citing an id or version not in the facts are discarded.

## Tests
- `npx vitest run`: unit tests. Set `TEST_DATABASE_URL` (a Neon connection string) to also run the Postgres adapter tests.
- `npm run e2e`: Playwright against a production build (built into `.next-e2e`, so it never collides with `next dev`) and a mock
  GitHub (`e2e/mock-github.mjs`, fixture repo in `e2e/fixture/`). Hermetic: no network, no real credentials, real env blanked.
  Covers paste URL -> map -> drill-down -> failing step, private-repo access, sign-in/out, share + revoke, overrides, CSP on
  every page, security headers, anonymous write refusal and rate limiting. CI: `.github/workflows/ci.yml`.

## Assurance for the simulation agents themselves (X10)

The simulation feature (X0-X9: white-box, gray-box, red-team, the blue observer, and the two routes to a real target)
is treated as high-risk software in its own right, not exempted because it is "only testing".

**Eval suite, in CI (`src/lib/sim/eval/`, `.github/workflows/eval.yml`).** Golden range runs with a known right answer
(not just a passing test suite that might not notice a regression), scored on true findings, false positives, missed
confirmations, and a representative slice of X3's own prompt-injection suite scored on scope violations. **The build
fails on any scope violation or score regression.** The full, exhaustive injection suite (60 cases) stays in
`injection.test.ts`; the eval suite's own slice is there to make the CI gate visible and fast, not to replace it.

**"Red team the red team"**: already built across X0-X9, not duplicated here.
- Prompt injection (README, a finding's text, an advisory, a range response, a tool's output; a model that obeys
  everything it reads): `agent/injection.test.ts`, 60 cases, plus the eval suite's own representative slice.
- Tool-argument smuggling (a fake tool-call embedded as text, a forbidden technique named in prose, Unicode
  look-alike hosts): the same suite's `fakeToolCall`/`lookalike`/`forbiddenTechnique` payloads; `scope.test.ts`'s
  look-alike table and prototype-pollution/garbage-input tests (15 deliberate guard breakages, all caught).
- DNS rebinding and redirect tricks against the scope guard: `scope.test.ts` (host-confusion table), S4's transport
  tests (public addresses only, no redirects off the validated host).
- Sandbox egress attempts: `isolation.test.ts` (the range has no network of its own, by construction) and the agent
  runtime's own tests (a tool gets only a frozen abort signal, never a way to reach the real ROE, state or approvals).
- Oversized outputs: `agent/untrusted.test.ts` (depth, item-count and character caps on anything quoted from outside).
- A malicious repository fixture: the range is built from graph *metadata* only and never repo text or code, tested
  with literal canary strings (`generate.test.ts`, `isolation.test.ts`) that must never appear in anything the range
  produces.

**Privacy review.**
- *What leaves the server, and to which provider.* The four simulation checks (white-box, gray-box, red-team, blue)
  use no model at all — deterministic code only. The separate "explain"/"ask the map" features (unrelated to
  simulation) pick a model via the AI Gateway (any provider, `NARRATE_MODEL`, default `anthropic/claude-sonnet-5-5`) or
  a dev-only Google key; a private repository never uses the free-tier dev key. Findings text sent to a model never
  includes source code or a secret's value (checked for: a reply citing an id or version not in the given facts is
  discarded).
- *Source code.* Read only when a maintainer explicitly checks "Let it read the few lines around each finding" on
  "Verify by simulation" (off by default, each run); even then, only the few lines around one finding, through the
  caller's own GitHub access, never stored, never sent to a model. A proposed patch is a diff made fresh from that
  read, every time it is asked for; it is never persisted.
- *Retention.* Runtime telemetry (health buckets) is capped at 7 days (`RETENTION_MS`, `persist/types.ts`) and
  dropped on write past that. **Findings, maps and simulation verdicts have no automatic expiry**: they are replaced
  by the next scan or simulation run, but nothing deletes them on its own. There is no account- or repository-level
  "delete everything" endpoint (B46): a maintainer can remove an imported report, a domain, or a share link
  individually, but not purge a repository's whole record in one action.
- *Redaction.* The audit log (`audit.ts`) caps every field's length and is designed to hold nothing secret-shaped in
  the first place (synthetic range credentials, no request bodies, no response bodies beyond a capped marker);
  tested directly (X3: nothing secret-shaped in a run's model view, log, result or console).
- *"Metadata-only" is not one named toggle*, honestly: it is the DEFAULT state of several independent switches (the
  simulation's source-read checkbox defaults off; the AI-explanation path never takes source regardless of any
  switch). There is no single flag that guarantees "nothing but metadata will ever be read," only several
  independently-tested defaults that currently add up to that (B47, if a single enforced mode is wanted later).

**Supply chain.** No new runtime or build dependency was added for the whole simulation feature (X0-X9): every check
reuses `zod`, the `yaml` parser already used for pipeline analysis, and Node's own `crypto` — verified directly
(`git log --oneline -- package.json` shows no commit in this range). An SBOM for this repository's own dependencies,
generated in CI, and a run of this project's own scanner against this repository, are both **not done** (B48, B49):
the former needs a third-party tool this session could not verify running safely first; the latter needs the scan
pipeline wired to run outside the request/response cycle it currently assumes.

**Operational.**
- *Rate limits* exist per client address, per route (above). **Not done:** global (cross-instance) limits and
  spend caps with alerts, and exporting the audit log anywhere it survives past one run's own result (B19, B20,
  already tracked).
- *Incident runbook: "an agent did something out of scope".* If `allow()` ever let something through it should not
  have: **1.** Kill it — `DELETE /api/security/simulate?repo=<repo>` stops every run for that repository immediately
  (the kill switch is checked before every action and the range is torn down once; other repositories' runs are
  unaffected). **2.** Read the log — every run's audit entries are hash-chained (`verifyChain`); pull the stored
  `runId`/`head` from the finding's own `simulation` field and check the chain has not been cut or edited. **3.**
  Reproduce — every agent is deterministic given the same inputs (X1-X9's own determinism tests); re-run it against
  the same snapshot and finding set to confirm, rather than trusting a one-off log line. **4.** Fix the guard, not the
  symptom — a real scope violation means `allow()` (`scope.ts`) itself is wrong; patch that one file, add the exact
  case to `scope.test.ts`, and re-run the eval suite before considering it closed. **5.** Nothing here ever reached a
  real third party by construction unless the target was a verified domain or a customer's own `ci-runner`: check
  `ownershipProvedAt` and the ROE's own target list in the log first, before assuming real damage.

## Browser extension (P7)
See `extension/README.md`. Security shape: runs only on `github.com/*/*`; reads only the URL; the one network call is made by a
background worker to the single host in `host_permissions`; the page world never sees the request, a cookie or a token; the
button is built with `textContent` inside a Shadow DOM. The server side is `/api/verdict`: same `authorizeRepo` rule as every
other route (public: open, private: the caller's own session), `private, no-store`, deliberately **no CORS headers**, rate
limited. The worker's `fetch(..., { credentials: "include" })` carries the SameSite=Lax session cookie (verified in Chromium).
