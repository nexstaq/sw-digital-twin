# Ingestion (P2)

`repo URL -> clone -> detectors -> raw graph -> canonical L0/L1/L2 graph`, streamed to the UI over SSE (`GET /api/scan?repo=owner/name`). Page: `/scan`.

## Pipeline (`src/lib/ingest`)
| File | Role |
|---|---|
| `repo.ts` | URL validation (`parseRepo`), shallow clone (depth 100), file walk (skips symlinks, vendor dirs), size-capped reader, git churn |
| `detectors/actions.ts` | Workflows -> jobs DAG (`needs`), environments, deploy targets, path filters -> packages |
| `detectors/packages.ts` | package.json / pyproject / requirements / go.mod / Cargo -> services, libs, workspace deps, datastores, third parties |
| `detectors/infra.ts` | Dockerfile, compose, Kubernetes, Terraform, vercel/fly/netlify/serverless |
| `detectors/code.ts` | tree-sitter (TS/JS/Python): imports, Express-style routes, FastAPI/Django routes, Next.js file routes, NestJS decorators (regex), entrypoints |
| `builder.ts` | merge by id, CODEOWNERS + churn, cluster, lift edges to siblings, roll up |
| `pipeline.ts` | orchestration; each detector isolated with a 30s timeout; partial graph streamed after each |

## Guarantees
- Every node has >= 1 evidence ref (`path`, optional `lines`); enforced by `validateGraph` and tests.
- Nothing from the repo is executed. Symlinks are never followed; reads cannot escape the checkout.
- A detector crash/timeout becomes a warning and the scan keeps its partial map.
- A node with no live signal stays `unknown`, never green. The banner says NO DATA, not GO.

## Known limits (open items are tracked in docs/BACKLOG.md)
- Where the code comes from: `cloneRepo` uses `git` when the binary exists (local, self-host). Vercel's runtime has no git, so there it downloads GitHub's tarball of one ref and unpacks it with `tarball.ts` (size, file-count and path-escape limits; no history, so no churn hotspots). Private repos use the GitHub App installation token (never in argv, the URL or `.git/config`).
- The scan runs inside the request, not in Vercel Sandbox, and is not a durable Workflow: a function timeout loses the scan (partial maps are streamed as they form). Tracked as B1.
- Tree-sitter covers TS/JS/Python. Go/Java/Ruby/Rust get manifest-level detection only.
- Grouping is deterministic; the optional language layer (P3, `src/lib/narrate`) only names and describes, and must cite existing evidence.
- Access: the scan route checks `authorizeRepo`, is rate limited, BotID-protected on Vercel, and capped at 2 concurrent per instance.
- Wasm grammars are listed in `outputFileTracingIncludes` for `/api/scan` and `/api/security/scan`. Not recorded as verified on a production deployment (B7).
