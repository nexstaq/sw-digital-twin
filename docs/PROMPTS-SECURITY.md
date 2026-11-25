# Security prompts (S1 to S4, scheduled scans): reconstructed

**These are not the original prompts.** The originals were not saved. This file was rebuilt on 2026-11-25 from the commit messages
(`51c6650`, `517c9c2`, `9624ff0`, `4a0c4f4`, `4b07a27`) and docs/SECURITY-ANALYSIS.md, so it describes what was built and its
acceptance tests, written as prompts. Re-running them would produce something similar, not identical. All five are complete.

## S1: Dependencies, secrets, pipelines, containers
```
Add a security view of the map. Analyzers: known CVEs for npm, PyPI, Go and crates via OSV.dev with reachability (direct,
transitive, dev-only; real imports in source); secrets (key formats plus entropy; never store the value); GitHub Actions
misconfiguration (pull_request_target + PR checkout, script injection, unpinned actions, broad token permissions,
curl|sh); Dockerfile and compose risks. Pin each finding to file:line and attach it to the package or service that owns the
file; roll counts up to blocks and recolour the existing canvas by worst finding. Deep dive to the exact lines fetched on
demand with the caller's access, secrets redacted. Push access required; findings never appear in share links or badges.
An analyzer failure is a visible warning, never a silent all-clear.
Acceptance: unit tests per analyzer; e2e against a mock OSV and a fixture repo whose secrets are assembled at run time.
```
## S2: Code analysis, attack paths, reports, trend
```
Add tree-sitter rules for JS/TS/TSX/Python (SQL and command injection, eval, XSS, SSRF, path traversal, open redirect,
weak crypto, disabled TLS, insecure cookies, JWT misuse, unsafe deserialization, writes with no auth check). Severity depends
on whether request data reaches the sink. Walk the map's real edges from public endpoints and outsider-triggerable
pipelines to datastores and external services as attack paths. Export print-ready HTML (escaped, locked CSP), SARIF 2.1.0
and JSON. Show new/fixed since the last scan and a score trend. Tune on a real app; every false positive found becomes a test.
Acceptance: safe idioms are not flagged (tagged SQL templates, JSON-LD, client-side relative fetch); report contains no secret.
```
## S3: GitHub alerts, SARIF import, live testing from your own CI
```
Pull Dependabot, code-scanning and secret-scanning alerts, each with its own status (permission missing, feature off, GitHub
down are stated, never "no alerts"); merge duplicates; never keep the secret value GitHub returns. Import SARIF from any tool
as untrusted input (size caps, defensive parsing, URL queries stripped, secret-shaped text redacted). Authenticate CI with
GitHub Actions OIDC (RS256 pinned; audience, issuer, expiry, repository claim must match). Generate a workflow that runs
Nuclei in the customer's runner against a staging site they name: never on pull requests, refuses without target and owner
confirmation, no intrusive templates, rate limited, image pinned by digest. We never send attack traffic from our servers.
Acceptance: none/HS256/tampered/expired/wrong-audience tokens refused; the generated YAML passes our own pipeline analyzer.
```
## S4: Standards, AI explanations, passive checks
```
Group findings by OWASP Top 10 (2021) and CWE; mark A04 and A09 "not assessed" rather than green. Add "explain in plain
English" from the finding's own facts (never code or secret values; repository text is untrusted data; private repos never use a
free-tier model; discard any answer citing an id or version not in the facts). Add passive checks on a domain the maintainer
proves they own (DNS TXT or well-known file), re-proved on every run: TLS, headers, cookies, CORS, well-known paths,
SPF/DMARC. SSRF-safe networking: resolve ourselves, refuse any non-public address, connect to the validated address, standard
ports, no redirects off the host, size and time caps, cooldown, per-repo cap. Store no response bodies.
Acceptance: an unproven domain receives zero requests (counted in e2e); private, loopback, metadata and IPv4-in-IPv6 addresses refused.
```
## Scheduled scans
```
Let a maintainer switch on daily or weekly re-scans, off by default. One Vercel Cron job calls a route that does nothing
unless CRON_SECRET is set and matched. Run due repos oldest first (max 5, respect the time budget) with the same code as
the Scan button, using the App installation token; re-check verified domains after re-proving ownership; one failure never
stops the others; record the outcome.
Acceptance: the route answers 503 with no secret and refuses a wrong one; e2e covers enable, run and disable.
```
