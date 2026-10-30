# Security analysis (S1 and S2)

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

## Roadmap
S2: done (above). S3: GitHub Dependabot / code-scanning / secret-scanning alerts, SARIF import, the CI Action. S4: passive external checks, AI
explanations, OWASP/CWE compliance views.

## Not yet
Git history scanning (a secret removed from HEAD is not found), real taint tracking across functions and files (rules look at one
call at a time), Java/Go/Ruby/Rust code rules, Rust/Java/Ruby dependency reachability, OSV rate-limit retry, scheduled re-scans, and a
true server-side PDF (use the browser's Save as PDF).

## Testing
Unit: each analyzer, mapping, scoring (`src/lib/security/**`). Real OSV was used once by hand to validate parsing and scores
(it exposed duplicate advisories, now merged). E2E: `e2e/vulnerabilities.spec.ts` against a mock OSV and a fixture repo whose secrets
are assembled at run time, so no key-shaped string is ever committed.
