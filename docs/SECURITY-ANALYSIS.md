# Security analysis (S1 to S4)

A security view of the same map. Open **Security** from the health map (maintainers only), run a scan, and see which parts of the
system carry which risks, down to the file and line.

## What S1 checks
| Analyzer | Finds | Pinned to |
|---|---|---|
| Dependencies (`analyzers/dependencies.ts`) | Known CVEs in npm (package-lock, pnpm, yarn), PyPI (requirements.txt, poetry.lock), Go (go.mod), crates (Cargo.lock) via **OSV.dev** (free, no key) | where the dependency is declared (manifest line), else the lockfile |
| Secrets (`secrets.ts`) | Private keys, AWS/GitHub/Stripe/Slack/npm/Google keys, DB URLs with passwords, entropy-checked hard-coded credentials | file:line. Value is never stored |
| Pipelines (`pipeline.ts`) | `pull_request_target` + PR checkout (pwn request), script injection, unpinned actions, broad token permissions, `curl \| sh` | workflow line |
| Containers (`container.ts`) | Root user, unpinned base image, secrets in `ENV`/`ARG`, `curl \| sh`, `ADD url`, `chmod 777`, SSH; compose `privileged`, host network/pid, docker socket | Dockerfile / compose line |

**Reachability.** A vulnerable package is marked *direct / transitive / dev-only*, and for npm, PyPI and Go we look for real imports
in your source ("imported by src/a.ts"). That feeds the ranking (`priority()` in `map.ts`): a high CVE in a library your code
imports outranks the same CVE in a dev tool nothing imports.

**Honesty rules.** An analyzer that fails, or an OSV outage, becomes a visible warning, never a silent all-clear. A clean result
reads "these checks passed, not that the software is proven secure". Test fixtures and templates are demoted, not ignored.

## How it shows up
- `securityGraph()` recolours the existing map by worst finding (critical/high = high risk, medium = medium, none = low). The canvas
  is unchanged; it gets a "security" vocabulary (High risk / Low risk) and drops health-only chrome (lenses, deploy timeline).
- Findings attach to the **package or service that owns the file** (a datastore that merely cites `package.json` does not own it).
  Counts roll up to every ancestor, so a block glows for what is inside it and leads with its worst finding.
- Posture card: grade (a critical caps it at D), severity bar, a category filter that recolours the map, "fix first" list.
- Deep dive: block → part → finding → the exact lines (highlighted), why it matters, how to fix, CVEs with fixed versions, CWE/OWASP.

## Privacy and access
- **Findings store path, line, rule, reason. Never source code or a secret's value** (`Finding` in `types.ts`). The code excerpt is
  fetched from GitHub when a finding is opened, with the caller's own access, secrets redacted, a private key shown as its header
  line only. `/api/security/snippet` serves only files a stored finding points at.
- **Push access required** for scan, findings and snippet. Vulnerability lists are more sensitive than architecture. Share links and
  the badge never include findings (tested).
- Scan is rate-limited (3/min per client), BotID-protected on Vercel, and capped to 2 concurrent per instance.

## Pen testing: the boundary
We do **not** run attack traffic from our servers: that would let anyone aim our infrastructure at third parties. Planned instead
(S3/S4): active tests run in the customer's own CI (a GitHub Action running ZAP/Nuclei against their staging, uploading SARIF to us);
passive checks (TLS, headers, cookie flags, exposed files) only against a domain whose ownership has been proven; a generated test
plan from the graph for a human tester.

## S2: code analysis, attack paths, reports, trend

### Code analysis (`analyzers/code.ts`)
JavaScript, TypeScript, TSX and Python are parsed with tree-sitter (the same grammars the map uses), so rules match code structure, not text.
| Rule | Flags | Does NOT flag |
|---|---|---|
| `CODE/sql-injection` | SQL built with a template string, `+`, f-string, `%` or `.format`, worst when request data reaches it | parameterised queries; tagged templates (`sql\`...\``, Prisma `$queryRaw\`\``), which bind values |
| `CODE/command-injection` | `exec`/`execSync` with built text, `spawn` with `shell: true`, `os.system`, `subprocess(shell=True)` | `execFile` with an argument array; fixed strings; files that never import `child_process` |
| `CODE/eval` | `eval`, `new Function`, Python `eval`/`exec` on non-literal text | literals and module-level constant strings |
| `CODE/xss-react`, `CODE/xss-dom` | `dangerouslySetInnerHTML`, `innerHTML =`, `document.write` with variables; JSON in a `<script>` without escaping `<` | sanitised values; constants; JSON-LD with `<` escaped |
| `CODE/ssrf` | server-side fetch of a URL taken from the request | client components (`"use client"`); relative or fixed-origin URLs |
| `CODE/path-traversal`, `CODE/open-redirect` | request data reaching a file path or a redirect | normalised/`basename`d paths; fixed targets |
| crypto and config | MD5/SHA-1, `Math.random` for tokens, disabled TLS verification, insecure cookies, JWT `none` algorithm or a literal secret, CORS `*` with credentials, `pickle`/unsafe `yaml.load`, Flask debug mode | |
| `CODE/no-auth-seen` | a request handler that accepts writes with no authentication check and no project-wide auth middleware | read-only routes; anything covered by auth middleware. LOW and low-confidence, and says it can be a false alarm |

Severity is decided by whether request data reaches the sink (high) or only "some variable" does (medium, low confidence). It is a
heuristic that ranks, not proof. Tests, generated, minified and declaration files are skipped. Found by running it on a real Next.js
app: three false positives (a client-side relative fetch, JSON-LD with `<` escaped, a constant passed to a sink), now covered by tests.

### Attack paths (`paths.ts`)
From each **foothold** (the nearest service above a group of public endpoints, or a pipeline an outsider can trigger via
`pull_request_target`/script injection) the map's real edges are walked, depth-limited, to the **assets** (datastores, external
services, queues, environments). Web paths walk `calls`/`reads`/`publishes`; pipeline paths walk `triggers`/`deploys_to`. `deploys_to`
is deliberately NOT a route from an endpoint (it says where something is hosted), and `depends_on` adds exposure (a vulnerable shared
package) but is never walked. A path is reported only if something risky is on it, or endpoints accept unauthenticated writes. A
missing edge in the map means a missing path, not a safe one. The canvas shows a path with its "impact" highlight.

### Reports (`report.ts`, `/api/security/report`)
`format=html` (print-ready; use the browser's Save as PDF), `format=sarif` (SARIF 2.1.0 with CWE tags and GitHub's `security-severity`,
for code scanning and other tools), `format=json`. Push access only. All text is HTML-escaped (package names, paths and advisories
are untrusted), only `https` links are emitted, no secret value appears, and the HTML is served with a locked CSP (no scripts at all).

### Trend (`trend.ts`)
Each scan is compared with the previous one by stable finding id: **new**, **fixed**, and the safety score over the last 30 scans.
Re-scanning the same commit replaces its point. History lives inside the stored scan; no extra tables.

## S3: other sources, and live testing from your own CI

### GitHub's own alerts (`github-alerts.ts`)
Each scan also asks GitHub for open **Dependabot**, **code scanning** and **secret scanning** alerts. Every source reports its own
status, so you see "Dependabot 4 · code scanning not switched on · secret scanning needs a permission", never a silent empty list.
An alert about a package our own scan also found is merged into that finding ("also confirmed by Dependabot"), not duplicated.
GitHub's secret-scanning API returns **the secret itself**: it is never read into a finding, and tests assert it appears nowhere we
store, show or export.

**One-time setup (only the App's owner can do this).** The App was created read-only for contents, actions, deployments, checks and
metadata. To read alerts, open the App's settings > Permissions & events > Repository permissions and set **Dependabot alerts**,
**Code scanning alerts** and **Secret scanning alerts** to *Read-only*, then accept the updated permissions on each installation
(GitHub shows a banner and emails the installation owner). Availability is GitHub's: Dependabot alerts must be enabled on the
repository; code and secret scanning are free on public repositories and need GitHub Advanced Security on private ones. Until
then, the panel says exactly which it is.

### SARIF import (`sarif-import.ts`, `POST /api/security/import`)
Any tool that writes SARIF (Semgrep, CodeQL, Trivy, ZAP, Nuclei, gitleaks, Checkov…) can feed the same map. Reports are untrusted:
5 MB cap, 2000 results, parsed defensively (never throws, counts what it skipped), absolute or `..` paths refused, URL query
strings and fragments removed (they can carry tokens), secret-shaped text redacted, code snippets ignored. A new report from a tool
replaces that tool's previous one; imports survive re-scans; an imported report can be removed (`DELETE`, maintainers only).
A finding about a URL (live testing) is its own category, is not placed on the map, and has no GitHub file link or code excerpt.

### Authentication for CI: GitHub Actions OIDC (`oidc.ts`)
A workflow cannot use a browser session, and a long-lived token would be a secret to leak. Instead the run asks GitHub for a
short-lived signed token naming its repository, and presents it as `Authorization: Bearer`. We verify: RS256 signature against
GitHub's published keys (cached, one rate-limited refetch on an unknown key id), issuer, **audience = this service**, expiry, and
that `repository` matches the repository being imported into, so a workflow can only ever import into its own repository.
`alg: none`, HS256 "algorithm confusion", tampered payloads, wrong audience/issuer, expired and unknown-key tokens are all refused
(unit and e2e tested, with a mock issuer that signs with a real key). CI can add reports; it cannot delete them.

### Live testing: the boundary, as built (`ci.ts`)
We do **not** run attack traffic from our servers. The app generates a GitHub Actions workflow (Settings of the security page >
"Add live testing to your CI") that runs **Nuclei in your repository, on GitHub's runners, against a staging site you name**, then
uploads the SARIF with the OIDC token. It is safe by default: manual or weekly only (never on pull requests, so no stranger can
trigger it or obtain an identity token), refuses to run until `SECURITY_TEST_TARGET` is set to an https URL and
`SECURITY_TEST_CONFIRM_OWNER` is `yes`, skips intrusive / fuzzing / brute-force / denial-of-service templates, is rate limited,
disables out-of-band callbacks to third-party servers, and pins the scanner image by digest. Our own pipeline analyzer is run over
the generated YAML in a test, so the workflow we hand out never trips our own rules. Nuclei downloads its community templates at
run time (unpinned); pin them with `-t` if you need a fully reproducible run.

## S4: standards, AI explanations, passive checks on a verified domain

### Standards views (`owasp.ts`)
Findings are grouped by **OWASP Top 10 (2021)** and by **CWE**, in the panel and in the report. Built-in analyzers tag their own OWASP
category; imported findings (SARIF, GitHub alerts) are mapped from their CWE using OWASP's published lists. All ten categories are always
shown. **A04 Insecure Design and A09 Logging and Monitoring are marked "not assessed"**: a scan of a repository cannot judge them, and
showing them green would be a lie. "None found" and "not assessed" are different statements and look different.

### AI explanations (`explain.ts`, `POST /api/security/explain`)
"Explain this in plain English" writes a summary, how it could be abused here, ordered fix steps and a rough effort, from the finding's
own facts: never source code, never a secret's value. Safeguards: repository-derived and advisory text is **untrusted data** (quoted
inside JSON under a system prompt that says so); a private repository **never** uses a free-tier model (gateway only); the answer is
schema-validated; links and markup are stripped; and **any CVE/GHSA/CWE id or version number in the answer must appear in the facts we
gave it, or the whole answer is discarded**, which stops invented advisories and invented "upgrade to 9.9.9" advice. Results are cached
per finding and model. With no key it says so and the written reason and fix remain. Maintainers only, rate limited, bot-checked.

### Passive checks on a verified domain (`passive/`)
About 25 ordinary requests to a domain a maintainer registers: the home page (redirects on that exact host only), the TLS certificate
(trust, expiry, key, protocol), plain HTTP, security headers (HSTS, CSP, nosniff, framing, version disclosure), cookies (Secure,
HttpOnly, SameSite), CORS reflection, OPTIONS/TRACE, a dozen well-known file paths, and SPF/DMARC when the domain receives mail.
**No attacks, no logins, no guessing, no fuzzing.**

The safety model, because a server that fetches user-typed hostnames is an SSRF risk and an abuse risk:
- **Ownership first, every time.** A random token must be in a DNS TXT record (`_mission-control-verify.<domain>`) or at
  `/.well-known/mission-control-verify.txt` on that exact host. It is re-proved at the start of **every** run, so a domain that changed
  hands cannot be tested by its previous claimant. Nothing is sent to an unproven domain (e2e-tested by counting requests the target receives).
- **Public addresses only.** We resolve the name ourselves; if **any** returned address is private, loopback, link-local, cloud-metadata,
  carrier-grade, multicast or reserved (including IPv4-in-IPv6 and transition forms), the host is refused. The connection uses the address
  we validated, so DNS cannot change its answer afterwards (rebinding).
- **Bounded.** Standard ports, no IP literals or credentials in URLs, no redirects off the host, no compression, 8 s timeouts, 8 KB caps,
  a pause between requests, at most 5 domains per repository, one run per domain per 5 minutes, a fixed User-Agent that says who we are.
- **Nothing sensitive kept.** Exposed files are detected by a content *signature* (so a single-page app that answers 200 to every path is
  not reported) and the content is discarded. Only "this file is readable" is recorded, never what is in it. Cookie values are never kept.
Validated against the real network on a real site (`sw-digital-twin.nexstaq.com`): 23 requests in 4.5 s, one accurate finding.

### Not yet (S4)
Scheduled passive checks; subdomain discovery; deeper TLS probing (legacy protocol and cipher enumeration); checking a site behind
authentication; AI that sees code (deliberately off: sending source to a model is a separate decision).

### Not yet (S3)
Passive checks (TLS, headers, cookie flags, exposed files) against a domain whose ownership we have verified; importing other
formats (CycloneDX/SPDX SBOMs); webhooks so a GitHub alert shows up without a scan.

## Roadmap
S1 to S4 are done (above).

## Not yet (overall)
Git history scanning (a secret removed from HEAD is not found), real taint tracking across functions and files (rules look at one
call at a time), Java/Go/Ruby/Rust code rules, Rust/Java/Ruby dependency reachability, OSV rate-limit retry, scheduled re-scans, and a
true server-side PDF (use the browser's Save as PDF).

## Testing
Unit: each analyzer, mapping, scoring (`src/lib/security/**`). Real OSV was used once by hand to validate parsing and scores
(it exposed duplicate advisories, now merged). E2E: `e2e/vulnerabilities.spec.ts` against a mock OSV and a fixture repo whose secrets
are assembled at run time, so no key-shaped string is ever committed.
