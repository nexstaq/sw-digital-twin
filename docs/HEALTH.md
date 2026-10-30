# Live health (P4)

Nodes stop being grey when a live source is connected. Today that source is GitHub (Actions + Deployments), with zero setup for public repos.

## How it flows

```
GitHub ── webhook ──► /api/webhooks/github ── verify HMAC ── poke(repo) ─┐
                                                                          ▼
Browser ◄── SSE ◄── /api/health/stream?repo= ◄── wakes on poke, or every 20s ── fetchSignals() ── GitHub REST
   │
   └─ applyHealth(graph, signals)   (pure, in the browser; same function will drive replay in P6)
```

- `src/lib/github/api.ts`: reads runs (default branch), jobs for each workflow's latest finished run, deployments + their latest status. About 3 + workflows + deployments requests per refresh.
- `src/lib/health/engine.ts`: pure `applyHealth(graph, signals, now)`. Same inputs, same output; it never mutates its input.
- The server stores no signals. Streams share one fetch per repo per 15s per instance (`signals.ts`).

## What turns a node red / amber

| Node | Failing | Degraded | Nominal | Unknown |
|---|---|---|---|---|
| Workflow | latest finished run on the default branch failed / timed out | pass rate < 80% of last 20, or one commit both passed and failed (flaky) | otherwise | no finished runs |
| Job | its step failed in the latest finished run (names the step, links the job) | | passed | not present in that run |
| Environment | latest deployment failed / errored | < 70% of recent deploys succeeded | otherwise | no deployments |

Blocks roll up from their children (`rollup.ts`). Cancelled / skipped runs and PR branches are ignored. Staleness (> 30 days quiet) is shown as a reason, not as a colour. A node with no matching signal stays **unknown**, never green.

## Security rules (important)

- **Anonymous viewers get public repositories only.** The stream first checks the repo without any credentials. A shared `GITHUB_TOKEN` or the App's installation token is only used afterwards, for rate limit. So tokens can never reveal a private repo to a visitor.
- Private repos need sign-in, which is not built yet (see "Not done yet"). Until then they are refused with a clear message.
- Webhooks are rejected unless `X-Hub-Signature-256` matches (constant-time compare). With no `GITHUB_WEBHOOK_SECRET` the endpoint answers 503.
- Stream concurrency is capped per instance (60). The scan endpoint is capped separately (2).

## Setup

### Public repos (nothing to do)
Paste a repo at `/scan`. 60 GitHub requests/hour per server IP unauthenticated; set `GITHUB_TOKEN` to get 5,000.

### Webhooks for instant updates
1. Create a random secret: `openssl rand -hex 32`. Set it as `GITHUB_WEBHOOK_SECRET`.
2. In the repo (Settings, Webhooks) or the App: payload URL `https://<your-host>/api/webhooks/github`, content type `application/json`, the same secret.
3. Events: Workflow runs, Workflow jobs, Deployment statuses, Check runs, Pushes.

Local testing: expose the dev server with a tunnel, or sign a request yourself (HMAC-SHA256 of the raw body with the secret, sent as `X-Hub-Signature-256: sha256=<hex>`).

### GitHub App (for private repos later)
Register at https://github.com/settings/apps/new (or paste the manifest below at `https://github.com/settings/apps/new?` via the manifest flow). Read-only permissions only.

```json
{
  "name": "Mission Control for Code",
  "url": "https://YOUR-HOST",
  "hook_attributes": { "url": "https://YOUR-HOST/api/webhooks/github" },
  "redirect_url": "https://YOUR-HOST/repos",
  "callback_urls": ["https://YOUR-HOST/api/auth/callback"],
  "request_oauth_on_install": true,
  "public": false,
  "default_permissions": {
    "metadata": "read", "contents": "read", "actions": "read",
    "deployments": "read", "checks": "read", "security_events": "read"
  },
  "default_events": ["workflow_run", "workflow_job", "deployment_status", "check_run", "push"]
}
```

Then set `GITHUB_APP_ID` and `GITHUB_APP_PRIVATE_KEY`. `tokenFor()` mints installation tokens (RS256 JWT, cached until 5 minutes before expiry) and falls back to `GITHUB_TOKEN`.

## Not done yet

(Sign-in, the install flow, repo picker and private-repo scanning landed in P4b: see docs/AUTH.md.)

Still open from P4:

- **Sign-in** (Clerk via the Vercel Marketplace) and the **App install flow / repo picker**. These need a provisioned Clerk instance and a registered App.
- **Private-repo scanning**: `cloneRepo` still clones anonymously. It should use an installation token (via a git credential helper, never in the URL or logs).
- **Shared queue**: the bus is in-process. On several instances a webhook only wakes streams on the instance that received it; others catch up within 20s. Swap in Vercel Queues / Redis behind `bus.ts`.
- **Persistence**: no health history is stored yet (P6 adds frames for replay).
- **Code scanning alerts** as a signal.
- Live-GitHub behaviour of the App token path is unit-tested only (generated RSA key, mocked GitHub), not against a real App.
