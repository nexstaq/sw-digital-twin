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
- All nodes start `unknown`: there is no live signal until P4+. The banner says NO DATA, not GO.

## Known limits (deliberate for now)
- Public repos only; private repos arrive with the GitHub App (P4).
- Clone runs on the app server via `git`. Production should run it inside Vercel Sandbox (the `analyzeDirectory` seam is already separate for this) and drive it with Vercel Workflow for durability.
- Tree-sitter covers TS/JS/Python. Go/Java/Ruby/Rust get manifest-level detection only.
- No LLM yet: grouping is deterministic. P3 adds naming/clustering on top and must cite existing evidence.
- Unauthenticated endpoint with an in-memory concurrency cap of 2. Needs auth and rate limiting before public launch.
- Wasm grammars are listed in `outputFileTracingIncludes` for deploy; not yet verified on a real Vercel deployment.
