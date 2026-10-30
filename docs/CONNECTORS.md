# Connectors, anomaly detection, replay (P6)

We are **not a telemetry backend**. Connectors read from your tools and reduce what they read to compact rollups (`RuntimeBucket`: errors/min, requests/min, p95, top issues, 5-minute grain). Raw spans, logs and source are never stored.

```
Sentry (pull)  ─┐
Vercel (pull)  ─┼─► collect() ─► SignalSet{runs, deploys, runtime[]} ─► applyHealth(graph, signals, t) ─► map
OTLP (push) ───┘        ▲                      │                           ▲
   /api/otlp/v1/traces ─┴─ persist (rollups)    └─ signalsAt(signals, t) ───┘   time travel / replay
```

Everything downstream is one pure function: **`applyHealth(graph, signalsAt(signals, t), t)`**. Live is `t = now`; scrubbing the timeline and replaying an incident only move `t`.

## Setting up each source

| Source | How | What it gives |
|---|---|---|
| **OpenTelemetry** | Set `OTLP_INGEST_KEY`. Exporter env: `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://HOST/api/otlp/v1/traces`, `OTEL_EXPORTER_OTLP_PROTOCOL=http/json`, `OTEL_EXPORTER_OTLP_HEADERS=authorization=Bearer <key>,x-twin-repo=owner/name` | errors/min, requests/min, p95 per `service.name`. Counts entry spans only (server spans, or root spans). **JSON only**, no protobuf. |
| **Sentry** | `SENTRY_AUTH_TOKEN` (read scopes: `org:read`, `project:read`, `event:read`) + `SENTRY_ORG` | errors/min per project (hourly, Sentry's finest stats grain) and the top 3 unresolved issues, linked, on the unhealthy node |
| **Vercel** | `VERCEL_TOKEN` + `VERCEL_PROJECT_ID` (`VERCEL_TEAM_ID` if a team) | deployments → health of the matching environment node (`production`, `preview`) and the timeline. Runtime logs are not read. |

Then **enable the repo**: `CONNECTOR_REPOS=owner/name`. Open **Sources** in the top bar: each tool's services are auto-matched to nodes by name and shown for a one-time **Confirm**. Nothing is used until confirmed. Confirmations are kept in this browser (`localStorage`) until accounts exist.

## How health is decided (runtime)

- **Error rate** (when request volume is known): failing at >= 5% for two consecutive buckets, degraded at >= 2% or when anomalous.
- **Latency / error counts**: EWMA + z-score anomaly (`src/lib/health/anomaly.ts`). Anomalous means >= 3 sigma on the last two buckets; failing needs a large ratio too (p95 >= 5x normal, or errors >= 8x normal at z >= 4). The reason always says what normal is: *"p95 latency 900ms (normally 42ms)"*.
- The baseline **never learns from anomalous points**. A plain EWMA absorbs a long spike within a few samples and the problem "heals" while still happening; this one doesn't. (Found by the incident tests.)
- No recent data (older than ~45 min, or 2.5 sampling steps for hourly sources) → **unknown**, never green.
- Several sources for one node: the worse state wins and every source explains itself.

## Replay

- **Scrub**: the timeline slider re-renders the whole map as it was up to 48h ago. GitHub runs/deploys are time-sliced by their created/updated timestamps; runtime rollups by bucket time.
- **Incident replay**: `sampleFrames` evaluates the map every 10 minutes, `findIncident` finds the most serious stretch where a top-level block was unhealthy, the part that went bad **first** (patient zero), the order the rest followed, and the subset that depends on patient zero (its path). "Replay incident" plays it back and lights that path. Chronic problems (bad for >= 90% of the window) are ignored.
- **Demo**: `/demo/incident`. A seeded, synthetic scenario that runs through the real engine: a deploy, then the database gets slow (latency only, no errors, so only the anomaly detector sees it first), then Payments API, API Gateway and Web Storefront fail in that order, a rollback, recovery.

## Persistence

`src/lib/persist`: `putBuckets / getBuckets / putSnapshot / listSnapshots / getSnapshot`. Default: JSON files in `.data/` (dev, self-host; single writer). `TWIN_PERSIST=memory` (and automatically on Vercel) keeps it in memory. **Production needs a Blob/Postgres adapter behind the same interface**: not built yet, so pushed OTLP data does not survive a serverless cold start.
Each public scan also stores its map keyed by commit sha (`/api/snapshots?repo=`). Replay currently uses the latest map; choosing the map that existed at the replayed time is not wired into the UI yet.

## Security

- Connector tokens are the operator's. They are served **only for repos in `CONNECTOR_REPOS`**; for any other repo every connector reports "not enabled" and nothing is fetched or shown.
- `/api/otlp/v1/traces` requires the exact `OTLP_INGEST_KEY` (constant-time compare), a valid `x-twin-repo`, JSON content, and <= 4 MB.
- Errors from providers never include the token.

## Verified vs not

Verified: engine, anomaly, incident finder, persistence adapters, OTLP parsing/auth, matching, caching (unit tests, 213 total); the seeded incident replay in a browser; OTLP ingest → match → confirm → red node in a browser against a mock GitHub.
**Not verified against live services**: Sentry and Vercel (built from their documented response shapes and tested with mocks), any real OpenTelemetry SDK exporter, and Sentry's stats grain being hourly means Sentry-only alerts lag by up to ~2 hours (use OTLP for fast signals).
Not built: Datadog/Prometheus connectors, OTLP metrics/logs and protobuf, Sentry webhooks, shared (cross-device) mappings, snapshot selection during replay, changed-files mapping for "what changed in the last deploy".
