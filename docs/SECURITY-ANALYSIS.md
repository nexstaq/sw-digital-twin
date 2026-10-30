# Security analysis (S1)

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

## Roadmap
S2: code analysis (tree-sitter rules), attack paths (internet-facing → datastore), HTML/PDF reports, finding trend per commit.
S3: GitHub Dependabot / code-scanning / secret-scanning alerts, SARIF import, the CI Action. S4: passive external checks, AI
explanations, OWASP/CWE compliance views.

## Not in S1
Git history scanning (a secret removed from HEAD is not found), transitive reachability beyond "imported or not", Rust/Java/Ruby
reachability, `OSV` rate-limit retry, scheduled re-scans, and diffing between scans.

## Testing
Unit: each analyzer, mapping, scoring (`src/lib/security/**`). Real OSV was used once by hand to validate parsing and scores
(it exposed duplicate advisories, now merged). E2E: `e2e/vulnerabilities.spec.ts` against a mock OSV and a fixture repo whose secrets
are assembled at run time, so no key-shaped string is ever committed.
